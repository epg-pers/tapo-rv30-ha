"""The sidebar page's preset editor: what it shows and what it writes. No Home Assistant
imports, so it can be unit-tested.

A preset ("customisation rule") belongs to one map and holds its rooms in cleaning order, each
with its own suction, water and passes, plus whether the order is kept (clean_order). That is
everything the Tapo app's editor sets; carpet handling is copied from the map's room, as the
app does (checked against a preset made in the app, firmware 1.3.3).
"""
from __future__ import annotations

from .mapdata import b64name, fold, preset_body

NAME_MAX = 40
SUCTION = range(1, 6)       # Quiet .. Ultra
WATER = range(0, 4)         # off .. high
PASSES = range(1, 4)


class PresetError(ValueError):
    """A preset the robot should not be sent, with a reason the user can act on."""


def view(rules: list[dict], details: dict[int, dict], room_names: dict[int, dict[int, str]],
         schedules: list[dict]) -> list[dict]:
    """Presets as the editor lists them. rules: getCustomizationRulesInfo's rule_list;
    details: rule_id -> getCustomizationRuleData; room_names: map_id -> {room id: name};
    schedules: decoded schedules (mapdata.decode_schedule), to show which run each preset."""
    out = []
    for rule in rules or []:
        rid = rule.get("rule_id")
        if rid is None:
            continue
        detail = details.get(rid) or {}
        names = room_names.get(rule.get("map_id")) or {}
        rooms = [{"id": a.get("id"), "name": names.get(a.get("id")) or f"Room {a.get('id')}",
                  "suction": a.get("suction"), "water": a.get("cistern"), "passes": a.get("clean_number")}
                 for a in detail.get("area_list") or [] if a.get("type") == "room"]
        out.append({
            "id": rid, "map_id": rule.get("map_id"),
            "name": b64name(rule.get("rule_name", "")) or f"Preset {rid}",
            "clean_order": detail.get("clean_order", True), "valid": not rule.get("invalid"),
            "rooms": rooms,
            "schedules": [{"id": s.get("id"), "time": s.get("time"), "days": s.get("days") or [],
                           "enabled": s.get("enabled", False)}
                          for s in schedules or [] if s.get("preset_id") == rid],
        })
    return out


def body(name, map_id: int, rooms: list, clean_order: bool, map_rooms: list[dict],
         others: list[dict], preset_id: int | None = None) -> dict:
    """The addCustomizationRule body for a preset made or changed in the editor, after checking
    it. map_rooms: the map's area_list rooms (for ids and carpet handling); others: the presets
    already on that map ({id, name}), whose names it must not take."""
    name = str(name or "").strip()
    if not name:
        raise PresetError("give the preset a name")
    if len(name) > NAME_MAX:
        raise PresetError(f"the name is too long (at most {NAME_MAX} characters)")
    if any(fold(p["name"]) == fold(name) and p["id"] != preset_id for p in others):
        raise PresetError(f"this map already has a preset called '{name}'")
    if not rooms:
        raise PresetError("pick at least one room")
    carpet = {a.get("id"): a.get("carpet_strategy") for a in map_rooms}
    seen, items = set(), []
    for r in rooms:
        try:
            rid, su, wa, pa = (int(r["id"]), int(r["suction"]), int(r["water"]), int(r["passes"]))
        except (KeyError, TypeError, ValueError) as exc:
            raise PresetError(f"a room is missing its settings ({exc})") from exc
        if rid not in carpet:
            raise PresetError(f"room {rid} is not on this map")
        if rid in seen:
            raise PresetError(f"room {rid} is in the preset twice")
        if su not in SUCTION or wa not in WATER or pa not in PASSES:
            raise PresetError(f"room {rid}: suction 1-5, water 0-3 and passes 1-3")
        seen.add(rid)
        items.append({"id": rid, "suction": su, "cistern": wa, "clean_number": pa,
                      "carpet_strategy": carpet[rid]})
    return preset_body(name, map_id, items, bool(clean_order), rule_id=preset_id)
