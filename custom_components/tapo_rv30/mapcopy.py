"""Restoring a backup as a new map, and copying a map, without hurting the map that carries it.

What the robot does (verified on an RV30 Max Plus, firmware 1.3.3):

* mapRecovery only takes a restore onto a map it already has (the carrier). The backup comes
  back under the map id stored inside it, as a new unsaved map if no map has that id.
* The backup's JSON tail (room names and colours, per-room flags, furniture) is written onto
  the carrier, not onto the restored map. A carrier that is a real map loses its room names,
  colours and furniture to the backup's. No-go zones and the grid are not touched.
* saveMap with only new_map_name saves the current unsaved map under that name and keeps its id.
* setAreaInfo and setFurnitureInfo write to the map_id they are given, current or not.

So a restore onto a carrier snapshots the carrier's rooms and furniture first, writes the tail
onto the restored map and puts the carrier back. A copy is a backup whose id is changed
(mapbackup.reid_bkmap) and restored as a new map.
"""
from __future__ import annotations

MAX_MAPS = 3            # the firmware's MAX_SAVE_MAP_NUM
_ROOM_FIELDS = ("type", "id", "name", "color", "define_type", "floor_material", "floor_texture",
                "carpet_strategy", "label")
_TAIL_ROOM_KEYS = ("name", "color", "carpet_strategy")
_FURNITURE_FIELDS = ("type", "id", "angle", "vertexs")


def new_map_id(existing, now: float) -> int:
    """A fresh map id: the robot's own ids are unix timestamps, so use the time, stepping past
    any id already on the robot. Always 10 digits (until 2286) and inside int32 (until 2038)."""
    taken = {int(i) for i in existing}
    mid = int(now)
    while mid in taken:
        mid += 1
    if not 10**9 <= mid < 2**31:
        raise ValueError(f"cannot make a map id from time {now}")
    return mid


def rooms_of(area_list) -> list[dict]:
    """A map's rooms as setAreaInfo takes them back."""
    return [{k: a[k] for k in _ROOM_FIELDS if a.get(k) is not None}
            for a in area_list or [] if isinstance(a, dict) and a.get("type") == "room"]


def furniture_of(furniture_list) -> list[dict]:
    return [{k: f[k] for k in _FURNITURE_FIELDS if f.get(k) is not None}
            for f in furniture_list or [] if isinstance(f, dict)]


def layers(map_data: dict) -> dict[str, list]:
    """What a restore can overwrite on its carrier: the rooms' attributes and the furniture."""
    return {"rooms": rooms_of(map_data.get("area_list")),
            "furniture": furniture_of(map_data.get("furniture_list"))}


def _norm(items: list[dict]) -> list:
    return sorted((sorted(i.items(), key=lambda kv: kv[0]) for i in items), key=repr)


def same(a: list[dict], b: list[dict]) -> bool:
    return _norm(a) == _norm(b)


def repair(before: dict[str, list], after_data: dict) -> dict[str, list | None]:
    """What to write so the carrier matches its snapshot again: rooms (only if it had rooms,
    and only the attributes, onto the room ids it still has) and furniture (also when it had
    none, to clear what the restore added). None means leave it."""
    now = layers(after_data)
    rooms = None
    if before["rooms"] and not same(before["rooms"], now["rooms"]):
        have = {r["id"] for r in now["rooms"]}
        rooms = [r for r in before["rooms"] if r.get("id") in have]
    furniture = None if same(before["furniture"], now["furniture"]) else before["furniture"]
    return {"rooms": rooms or None, "furniture": furniture}


def tail_layers(tail: dict | None, map_data: dict) -> dict[str, list | None]:
    """The backup's tail written onto the map it restored: names, colours and carpet strategy
    for the room ids the restored map has, and the tail's furniture."""
    tail = tail or {}
    by_id = {a.get("id"): a for a in tail.get("area_list") or []
             if isinstance(a, dict) and a.get("type") == "room"}
    rooms, changed = [], False
    for r in rooms_of(map_data.get("area_list")):
        t = by_id.get(r.get("id")) or {}
        for k in _TAIL_ROOM_KEYS:
            if t.get(k) is not None and t[k] != r.get(k):
                r[k] = t[k]
                changed = True
        rooms.append(r)
    furniture = furniture_of(tail.get("furniture_list"))
    have = furniture_of(map_data.get("furniture_list"))
    return {"rooms": rooms if changed else None,
            "furniture": furniture if furniture and not same(furniture, have) else None}


def tail_subset(tail: dict | None) -> dict | None:
    """The part of a backup's tail worth keeping for the tidy-up (it is stored until then)."""
    if not tail:
        return None
    rooms = [{k: a[k] for k in ("type", "id", *_TAIL_ROOM_KEYS) if a.get(k) is not None}
             for a in tail.get("area_list") or [] if isinstance(a, dict) and a.get("type") == "room"]
    return {"area_list": rooms, "furniture_list": furniture_of(tail.get("furniture_list"))}


def _names(map_list) -> dict[int, str]:
    import base64
    out = {}
    for m in map_list or []:
        try:
            out[m.get("map_id")] = base64.b64decode(m.get("map_name") or "").decode("utf-8", "replace")
        except Exception:
            out[m.get("map_id")] = ""
    return out


def carry(client, map_id: int, setup: dict) -> dict:
    """Put a copied map's presets (and its schedules, switched off, if they came along) onto
    the new map (blocking). Presets keep their names, rooms, order and per-room settings; one
    whose name the map already has is left alone, so a retry adds only what is missing.
    Schedules are pointed at the new presets' ids. Returns counts, what was skipped, and
    failed: a write the robot refused or did not answer (worth another go, unlike a skip)."""
    from . import mapsnapshot
    data = client.get_map_data(map_id)

    def presets_now() -> list:
        return [{**client.get_preset_detail(map_id, r["rule_id"]), "rule_id": r["rule_id"], "map_id": map_id}
                for r in client.get_presets() if r.get("map_id") == map_id and r.get("rule_id") is not None]

    plan = mapsnapshot.plan(setup, map_id, data.get("area_list", []), data.get("furniture_list", []),
                            presets_now(), client.get_schedules())
    out = {"presets": 0, "schedules": 0, "skipped": list(plan["skipped"]), "failed": False}
    for body in plan["presets"]:
        try:
            if client.add_preset(body) == 0:
                out["presets"] += 1
            else:
                out["skipped"].append(f"preset {mapsnapshot._b64(body.get('rule_name'))!r}: refused")
                out["failed"] = True
        except Exception as exc:
            out["skipped"].append(f"preset {mapsnapshot._b64(body.get('rule_name'))!r}: {exc}")
            out["failed"] = True
    if plan["schedules"]:
        ready, why = mapsnapshot.resolve_schedules(plan["schedules"], presets_now(), map_id)
        out["skipped"] += why
        for rule in ready:
            try:
                client.add_schedule(rule)
                out["schedules"] += 1
            except Exception as exc:
                out["skipped"].append(f"schedule at {rule.get('s_min')} min: {exc}")
                out["failed"] = True
    return out


def carried_text(got: dict | None) -> str:
    """", plus 2 presets and 1 schedule (switched off)" for a message, or "" for nothing."""
    got = got or {}
    took = [f"{got[k]} {k if got[k] != 1 else k[:-1]}" for k in ("presets", "schedules") if got.get(k)]
    if not took:
        return ""
    return ", plus " + " and ".join(took) + (" (switched off)" if got.get("schedules") else "")


ONE_OFF_TRIES = 3       # goes at saving the restored map / switching back before giving up on them


def tidy(client, pend: dict) -> dict:
    """After a restore onto a carrier (blocking, map lock held): put the carrier's rooms and
    furniture back first, then save the restored map under its name if it is the current
    unsaved map and the name is free, give it the backup's room names and furniture, and for a
    copy make the carrier current again. Each step on its own, so one failing does not skip the
    others. pend["done"] records the steps that worked, so a retry only redoes the rest; the
    restored map's steps are "finished" once they worked, could not apply, or had
    ONE_OFF_TRIES goes. A carrier that is no longer on the robot has nothing to put back."""
    from .mapdata import fold
    carrier, landed, name = pend["carrier"], pend["map_id"], pend.get("name")
    done = pend.setdefault("done", {})
    out: dict = {"carrier": None, "carrier_ok": bool(done.get("carrier")), "saved": bool(done.get("saved")),
                 "switched": bool(done.get("switched")), "errors": []}
    try:
        current, map_list = client.get_map_info()
    except Exception as exc:
        out["errors"].append(f"reading the maps: {exc}")
        return out
    if not done.get("carrier"):
        if not any(m.get("map_id") == carrier for m in map_list):
            out["carrier_ok"] = done["carrier"] = True      # deleted meanwhile: nothing to put back
        else:
            try:
                fix = repair(pend.get("before") or {"rooms": [], "furniture": []}, client.get_map_data(carrier))
                if fix["rooms"]:
                    client.set_areas(carrier, "room", fix["rooms"])
                if fix["furniture"] is not None:
                    client.set_furniture(carrier, fix["furniture"])
                out["carrier"] = {"rooms": len(fix["rooms"] or []),
                                  "furniture": None if fix["furniture"] is None else len(fix["furniture"])}
                out["carrier_ok"] = done["carrier"] = True
            except Exception as exc:
                out["errors"].append(f"putting back map {carrier}: {exc}")
    if done.get("finished"):
        return out
    entry = next((m for m in map_list if m.get("map_id") == landed), None)
    if entry is None:
        return out          # not there (yet, or the restore failed): nothing more to do on it
    done["tries"] = tries = done.get("tries", 0) + 1
    retry = False
    if entry.get("is_saved") is False:
        others = [n for mid, n in _names(map_list).items() if mid != landed]
        why = ("it has no name to save it under" if not name
               else "it is not the current map" if current != landed
               else "another map already has that name" if any(fold(n) == fold(name) for n in others) else None)
        if why:
            out["errors"].append(f"map {landed} was not saved: {why}")
        else:
            try:
                if client.save_current_map(name) == 0:
                    current, map_list = client.get_map_info()
                    entry = next((m for m in map_list if m.get("map_id") == landed), None) or {}
                    if entry.get("is_saved") is False:
                        out["errors"].append(f"map {landed} still reads as unsaved after saving it")
                        retry = True
                else:
                    out["errors"].append(f"the robot did not save map {landed}")
                    retry = True
            except Exception as exc:
                out["errors"].append(f"saving map {landed}: {exc}")
                retry = True
    out["saved"] = done["saved"] = entry.get("is_saved") is not False
    if out["saved"] and pend.get("tail") and not done.get("tail"):
        try:
            new = tail_layers(pend["tail"], client.get_map_data(landed))
            if new["rooms"]:
                client.set_areas(landed, "room", new["rooms"])
            if new["furniture"]:
                client.set_furniture(landed, new["furniture"])
            done["tail"] = True
        except Exception as exc:
            out["errors"].append(f"room names and furniture of map {landed}: {exc}")
            retry = True
    # The source map's presets (and schedules, if asked), while the new map is still current.
    if out["saved"] and pend.get("carry") and not done.get("carry"):
        try:
            got = carry(client, landed, pend["carry"])
            out["carried"] = got
            out["errors"] += [f"map {landed}: {s}" for s in got["skipped"]]
            if got["failed"]:
                retry = True        # a retry adds only what is still missing (matched by name)
            else:
                done["carry"] = True
        except Exception as exc:
            out["errors"].append(f"presets of map {landed}: {exc}")
            retry = True
    if pend.get("copy") and out["saved"] and not done.get("switched"):
        if current != landed:
            out["switched"] = done["switched"] = True       # already off the copy (the user moved)
        else:
            try:
                client.set_current_map(carrier)
                out["switched"] = done["switched"] = True
            except Exception as exc:
                out["errors"].append(f"switching back to map {carrier}: {exc}")
                retry = True
    if not retry or tries >= ONE_OFF_TRIES:
        done["finished"] = True
    return out
