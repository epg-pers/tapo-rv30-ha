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


def tidy(client, pend: dict) -> dict:
    """After a restore onto a carrier (blocking, map lock held): put the carrier's rooms and
    furniture back first, then save the restored map under its name if it is the current
    unsaved map and the name is free, give it the backup's room names and furniture, and for a
    copy make the carrier current again. Each step on its own, so one failing does not skip the
    others; the carrier step failing is the only one worth retrying (carrier_ok False)."""
    from .mapdata import fold
    carrier, landed, name = pend["carrier"], pend["map_id"], pend.get("name")
    out: dict = {"carrier": None, "carrier_ok": False, "saved": False, "errors": []}
    try:
        fix = repair(pend.get("before") or {"rooms": [], "furniture": []}, client.get_map_data(carrier))
        if fix["rooms"]:
            client.set_areas(carrier, "room", fix["rooms"])
        if fix["furniture"] is not None:
            client.set_furniture(carrier, fix["furniture"])
        out["carrier"] = {"rooms": len(fix["rooms"] or []),
                          "furniture": None if fix["furniture"] is None else len(fix["furniture"])}
        out["carrier_ok"] = True
    except Exception as exc:
        out["errors"].append(f"putting back map {carrier}: {exc}")
    try:
        current, map_list = client.get_map_info()
        entry = next((m for m in map_list if m.get("map_id") == landed), None)
        others = [n for mid, n in _names(map_list).items() if mid != landed]
        if (entry is not None and entry.get("is_saved") is False and name and current == landed
                and not any(fold(n) == fold(name) for n in others) and client.save_current_map(name) == 0):
            _, map_list = client.get_map_info()
            entry = next((m for m in map_list if m.get("map_id") == landed), None)
        out["saved"] = entry is not None and entry.get("is_saved") is not False
    except Exception as exc:
        out["errors"].append(f"saving map {landed}: {exc}")
    if out["saved"] and pend.get("tail"):
        try:
            new = tail_layers(pend["tail"], client.get_map_data(landed))
            if new["rooms"]:
                client.set_areas(landed, "room", new["rooms"])
            if new["furniture"]:
                client.set_furniture(landed, new["furniture"])
        except Exception as exc:
            out["errors"].append(f"room names and furniture of map {landed}: {exc}")
    if pend.get("copy") and out["saved"]:
        try:
            client.set_current_map(carrier)
        except Exception as exc:
            out["errors"].append(f"switching back to map {carrier}: {exc}")
    return out
