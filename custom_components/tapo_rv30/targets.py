"""Which Tapo robots a service call is aimed at.

Pure logic with no Home Assistant imports, so it is tested on its own; services.py feeds it
the call's targets, the expanded device / area / floor / label targets and a registry lookup.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any

INDIRECT_TARGET_KEYS = ("device_id", "area_id", "floor_id", "label_id")


class TargetError(ValueError):
    """The call's target does not point at a usable Tapo robot."""


def as_list(value: Any) -> list[str]:
    if not value:
        return []
    return [value] if isinstance(value, str) else [str(v) for v in value]


def has_indirect_target(data: dict) -> bool:
    return any(as_list(data.get(key)) for key in INDIRECT_TARGET_KEYS)


def resolve(loaded: dict[str, Any], explicit: list[str], indirect: list[str],
            entry_of: Callable[[str], tuple[str | None, str | None] | None],
            domain: str, indirect_given: bool) -> list[Any]:
    """The coordinators a call targets, in a stable order and each once.

    loaded: config entry id -> coordinator, for this integration's robots.
    explicit: entity ids the caller named; each must be one of ours.
    indirect: entity ids reached through a device, area, floor or label; anything not ours
    (a light in the same area, the robot's own sensors are fine) is skipped.
    entry_of(entity_id) -> (platform, config_entry_id), or None when not registered.
    With no target at all and a single robot set up, that robot is used.
    """
    if not explicit and not indirect:
        if indirect_given:
            raise TargetError("no Tapo robot vacuum in the targeted device, area, floor or label")
        if len(loaded) == 1:
            return list(loaded.values())
        if not loaded:
            raise TargetError("no Tapo vacuum is connected yet (still starting up or retrying)")
        raise TargetError(f"pick a target vacuum entity ({len(loaded)} Tapo vacuums are set up)")
    found: dict[str, Any] = {}
    for eid in explicit:
        info = entry_of(eid)
        coord = loaded.get(info[1]) if info and info[0] == domain and info[1] else None
        if coord is None:
            if info and info[0] == domain:
                raise TargetError(f"{eid}: its vacuum is not connected yet (Home Assistant is still "
                                  "retrying to reach it); try again shortly")
            raise TargetError(f"{eid} is not a Tapo RV30 entity")
        found.setdefault(info[1], coord)
    for eid in indirect:
        info = entry_of(eid)
        if info and info[0] == domain and info[1] in loaded:
            found.setdefault(info[1], loaded[info[1]])
    if not found:
        raise TargetError("no Tapo robot vacuum in the targeted device, area, floor or label")
    return list(found.values())
