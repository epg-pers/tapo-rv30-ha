"""Map setup snapshots: everything layered on a map that a backup restore does not bring back.

A map backup (.bkmap) restores the robot's grid and room segmentation, but not reliably the
room names, every no-go zone, the furniture, or the presets and schedules that point at the
map. A snapshot holds those, taken from data the coordinator already polls, so after a restore
(or a re-map) they can be put back. No Home Assistant imports, so it can be unit-tested.
"""
from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

VERSION = 2
ZONE_TYPES = ("forbid", "virtual_wall", "carpet_rectangle", "carpet_round")
AREA_TYPES = ("room", *ZONE_TYPES)
_ROOM_KEEP = ("name", "carpet_strategy", "floor_texture", "floor_material")
_ROOM_WRITE = ("type", "id", "name", "color", "define_type", "floor_material",
               "floor_texture", "carpet_strategy", "label")
_ZONE_WRITE = ("type", "id", "vertexs", "carpet_strategy", "label", "define_type")
_PRESET_ITEM = ("id", "type", "suction", "cistern", "clean_number", "carpet_strategy")


def _b64(text: str) -> str:
    try:
        return base64.b64decode(text or "").decode(errors="replace").strip()
    except Exception:
        return str(text or "")


def build(map_id: int, map_name: str | None, area_list: list, furniture: list,
          presets: list, schedules: list, saved_at: str) -> dict[str, Any]:
    """Snapshot one map. presets: raw getCustomizationRuleData results; schedules: raw rules."""
    areas: dict[str, list] = {}
    for a in area_list or []:
        if a.get("type") in AREA_TYPES:
            areas.setdefault(a["type"], []).append(a)
    return {
        "version": VERSION,
        "map_id": map_id,
        "map_name": map_name,
        "saved_at": saved_at,
        "areas": areas,
        "counts": {t: len(v) for t, v in areas.items()},
        "furniture": list(furniture or []),
        "presets": [p for p in presets or [] if p and p.get("map_id") == map_id],
        "schedules": [s for s in schedules or []
                      if (s.get("clean_attr") or {}).get("map_id") in (map_id, None)],
    }


def content_hash(snap: dict) -> str:
    """Hash of the parts that matter, so an unchanged map is not written again."""
    body = {k: snap.get(k) for k in ("map_id", "areas", "furniture", "presets", "schedules")}
    return hashlib.sha1(json.dumps(body, sort_keys=True).encode()).hexdigest()


def named_rooms(snap: dict | None) -> int:
    return sum(1 for r in ((snap or {}).get("areas") or {}).get("room", []) if _b64(r.get("name")))


def is_degraded(old: dict | None, new: dict) -> bool:
    """Would new lose what old had? A map that has just been lost or restored shows up with
    no rooms or unnamed rooms; that must never replace a good snapshot."""
    if not old:
        return False
    old_rooms = len((old.get("areas") or {}).get("room", []))
    new_rooms = len((new.get("areas") or {}).get("room", []))
    if old_rooms and not new_rooms:
        return True
    return named_rooms(new) < named_rooms(old)


def _norm_zone(a: dict) -> dict:
    return {k: a[k] for k in _ZONE_WRITE if a.get(k) is not None}


def _shape(zone: dict) -> str:
    return json.dumps(zone.get("vertexs"))


def _hhmm(s_min) -> str:
    try:
        return f"{int(s_min) // 60:02d}:{int(s_min) % 60:02d}"
    except (TypeError, ValueError):
        return str(s_min)


def _norm_furn(f: dict) -> dict:
    return {k: f[k] for k in ("type", "id", "angle", "vertexs") if f.get(k) is not None}


def _sched_key(rule: dict, map_id: int | None = None, preset_names: dict | None = None) -> tuple:
    """What makes two schedules the same clean: time, days, what and where. The map id is
    the target's (a setup may come from another map) and a preset is compared by name,
    since a recreated preset gets a new id."""
    attr = rule.get("clean_attr") or {}
    preset = attr.get("custom_rule_id")
    if preset is not None and preset_names is not None:
        preset = preset_names.get(preset, preset)
    return (rule.get("s_min"), rule.get("week_day"), rule.get("mode"), attr.get("clean_mode"),
            map_id if map_id is not None else attr.get("map_id"),
            tuple(attr.get("room_list") or ()), preset)


def plan(snap: dict, target_map_id: int, area_list: list, furniture: list,
         presets_now: list, schedules_now: list) -> dict[str, Any]:
    """What to write so the target map matches the snapshot again. Only things the snapshot
    has and the map lacks or has differently; nothing is deleted that the snapshot does not
    replace. presets_now: raw preset details on the robot; schedules_now: raw rules."""
    out: dict[str, Any] = {"rooms": None, "zones": {}, "zones_added": {}, "furniture": None,
                           "presets": [], "schedules": [], "skipped": []}
    current = {t: [a for a in area_list or [] if a.get("type") == t] for t in AREA_TYPES}
    saved = snap.get("areas") or {}

    # Rooms: the shapes are in the grid; only names and per-room flags are put back, and only
    # onto room ids that exist on the target map.
    snap_rooms = {r["id"]: r for r in saved.get("room", []) if "id" in r}
    rooms, changed = [], False
    for r in current["room"]:
        entry = {k: r[k] for k in _ROOM_WRITE if r.get(k) is not None}
        old = snap_rooms.get(r.get("id"))
        if old:
            for k in _ROOM_KEEP:
                if k == "name" and not _b64(old.get(k)):
                    continue        # an unnamed saved room never blanks a name the map has
                if old.get(k) is not None and old.get(k) != r.get(k):
                    entry[k] = old[k]
                    changed = True
        entry["type"] = "room"
        rooms.append(entry)
    if changed:
        out["rooms"] = rooms
    missing = sorted(set(snap_rooms) - {r.get("id") for r in current["room"]})
    if missing:
        out["skipped"].append(f"rooms {missing} are not on the target map")

    # Zones are matched by outline, not id (the robot renumbers them). Saved zones the map
    # lacks are added next to the ones it has; zones drawn on the map since are kept.
    for zt in ZONE_TYPES:
        have = [_norm_zone(a) for a in current[zt]]
        shapes = {_shape(z) for z in have}
        used = {z.get("id") for z in have}
        add = []
        for z in (_norm_zone(a) for a in saved.get(zt, [])):
            if _shape(z) in shapes:
                continue
            shapes.add(_shape(z))
            if z.get("id") in used or z.get("id") is None:
                z["id"] = max([i for i in used if isinstance(i, int)] + [0]) + 1
            used.add(z["id"])
            add.append(z)
        if add:
            out["zones"][zt] = have + add
            out["zones_added"][zt] = len(add)

    want_f = [_norm_furn(f) for f in snap.get("furniture") or []]
    if want_f and want_f != [_norm_furn(f) for f in furniture or []]:
        out["furniture"] = want_f

    room_ids = {r.get("id") for r in current["room"]}
    have_names = {_b64(p.get("rule_name")) for p in presets_now or [] if p.get("map_id") == target_map_id}
    for p in snap.get("presets") or []:
        name = _b64(p.get("rule_name"))
        if not name or name in have_names:
            continue
        items = [{k: a[k] for k in _PRESET_ITEM if a.get(k) is not None}
                 for a in p.get("area_list") or [] if a.get("id") in room_ids]
        if not items:
            out["skipped"].append(f"preset '{name}': none of its rooms are on the target map")
            continue
        lost = [a.get("id") for a in p.get("area_list") or [] if a.get("id") not in room_ids]
        if lost:
            out["skipped"].append(f"preset '{name}': rooms {lost} are not on the target map, "
                                  "recreated without them")
        out["presets"].append({"rule_name": p.get("rule_name"), "mode": p.get("mode") or "room",
                               "map_id": target_map_id, "clean_order": p.get("clean_order", True),
                               "area_list": items})

    names_by_id = {p.get("rule_id"): _b64(p.get("rule_name")) for p in snap.get("presets") or []}
    names_now = {p.get("rule_id"): _b64(p.get("rule_name")) for p in presets_now or []}
    # A schedule with no map_id (whole house) belongs to whichever map is active, so on both
    # sides it counts as the target map's.
    have = {_sched_key(s, (s.get("clean_attr") or {}).get("map_id") or target_map_id, names_now)
            for s in schedules_now or []}
    for s in snap.get("schedules") or []:
        if _sched_key(s, target_map_id, names_by_id) in have:
            continue
        attr = dict(s.get("clean_attr") or {})
        if attr.get("custom_rule_id") is not None and not names_by_id.get(attr["custom_rule_id"]):
            out["skipped"].append(f"schedule at {_hhmm(s.get('s_min'))}: its preset is not in the saved setup")
            continue
        gone = [r for r in attr.get("room_list") or [] if r not in room_ids]
        if gone:
            out["skipped"].append(f"schedule at {_hhmm(s.get('s_min'))}: rooms {gone} are not on the "
                                  "target map")
            continue
        if attr.get("map_id") is not None:
            attr["map_id"] = target_map_id
        keys = ("enable", "mode", "week_day", "s_min", "start_remind", "alarm_min")
        if s.get("mode") == "once":
            keys += ("year", "month", "day")
        rule = {k: s[k] for k in keys if s.get(k) is not None}
        rule["clean_attr"] = attr
        out["schedules"].append({"rule": rule, "preset_name": names_by_id.get(attr.get("custom_rule_id"))})
    return out


def resolve_schedules(planned: list, presets_now: list, target_map_id: int) -> tuple[list, list]:
    """Point each planned schedule at the preset's id on the robot now (ids change when a
    preset is recreated). Returns (rules ready to add, reasons for any skipped)."""
    ids = {_b64(p.get("rule_name")): p.get("rule_id") for p in presets_now or []
           if p.get("map_id") == target_map_id}
    ready, skipped = [], []
    for item in planned:
        rule = json.loads(json.dumps(item["rule"]))
        name = item.get("preset_name")
        if rule["clean_attr"].get("custom_rule_id") is not None and name:
            if name not in ids:
                skipped.append(f"schedule at {rule.get('s_min')} min: preset '{name}' not on the robot")
                continue
            rule["clean_attr"]["custom_rule_id"] = ids[name]
        ready.append(rule)
    return ready, skipped


def restore_target(maps: dict, current_id, backup_id: int) -> tuple[int, bool]:
    """(map id to hand mapRecovery, carrier). The robot only takes a restore onto a map it has,
    but brings the backup back under the backup's own map id - as a new, unsaved map when that
    id is gone - so when the backup's map is lost any existing map can carry it."""
    if backup_id in maps:
        return backup_id, False
    if not maps:
        raise ValueError("the robot has no maps at all, and it only takes a restore onto an existing map. "
                         "Make any map in the Tapo app (a quick mapping run is enough), then run this again: "
                         "the backup comes back under its own map id and that throwaway map can be deleted")
    return (current_id if current_id in maps else next(iter(maps))), True


def describe(snap: dict) -> dict:
    """What a snapshot holds, so the safety net can be checked at a glance."""
    areas = snap.get("areas") or {}
    return {
        "saved_at": snap.get("saved_at"),
        "rooms": [_b64(r.get("name")) or f"Room {r.get('id')}" for r in areas.get("room", [])],
        "zones": {t: len(areas[t]) for t in ZONE_TYPES if areas.get(t)},
        "furniture": len(snap.get("furniture") or []),
        "presets": [_b64(p.get("rule_name")) for p in snap.get("presets") or []],
        "schedules": len(snap.get("schedules") or []),
    }


def summary(p: dict) -> dict:
    """A short, JSON-safe account of a plan for service responses and dry runs."""
    return {
        "room_names": [_b64(r.get("name")) for r in p["rooms"]] if p["rooms"] else [],
        # zones the plan adds (the list it writes also carries the ones already there)
        "zones": dict(p.get("zones_added") or {t: len(v) for t, v in p["zones"].items()}),
        "furniture": len(p["furniture"]) if p["furniture"] else 0,
        "presets": [_b64(x["rule_name"]) for x in p["presets"]],
        "schedules": [x["rule"].get("s_min") for x in p["schedules"]],
        "skipped": p["skipped"],
    }
