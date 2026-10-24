"""Putting a map's saved setup back onto the robot. Shared by apply_map_setup and the coordinator,
which finishes a lost-map restore by itself once the restored map has been saved in the app."""
from __future__ import annotations

import asyncio
import glob
import json
import os
from typing import Any

from . import mapsnapshot
from .const import DOMAIN


class ApplyError(Exception):
    """A write failed part way; .written says what had already been written."""

    def __init__(self, message: str, written: dict) -> None:
        super().__init__(message)
        self.written = written


def snapshots_folder(hass) -> str:
    return hass.config.path(DOMAIN, "map_setups")


def find_snapshot(folder: str, map_id: int | None, ref=None) -> dict | None:
    """The saved snapshot for map_id, or (ref given) the one whose saved id or name matches.
    Blocking."""
    from .mapdata import fold
    if ref in (None, ""):
        p = os.path.join(folder, f"{map_id}.json")
        if not os.path.exists(p):
            return None
        with open(p) as fh:
            return json.load(fh)
    want = fold(str(ref).strip())
    for p in sorted(glob.glob(os.path.join(folder, "*.json"))):
        try:
            with open(p) as fh:
                d = json.load(fh)
        except (OSError, ValueError):
            continue
        if str(d.get("map_id")) == want or fold(d.get("map_name") or "") == want:
            return d
    return None


def robot_state(client, map_id: int) -> tuple[dict, list, list]:
    """(map data, raw preset details, raw schedules) as the robot has them now. Blocking."""
    data = client.get_map_data(map_id)
    presets = []
    for rule in client.get_presets():
        if rule.get("map_id") == map_id:
            detail = client.get_preset_detail(map_id, rule["rule_id"])
            presets.append({**detail, "rule_id": rule["rule_id"], "map_id": map_id})
    return data, presets, client.get_schedules()


async def apply_setup(hass, coord, map_id: int, snap: dict, dry_run: bool = False) -> dict[str, Any]:
    """Compare map_id with snap and write whatever is missing or different. Returns a summary;
    raises ApplyError if a write fails part way."""
    client = coord.client
    data, presets, schedules = await hass.async_add_executor_job(robot_state, client, map_id)
    plan = mapsnapshot.plan(snap, map_id, data.get("area_list", []), data.get("furniture_list", []),
                            presets, schedules)
    result: dict[str, Any] = {
        "map_id": map_id, "from_setup": snap.get("map_name") or snap.get("map_id"),
        "saved_at": snap.get("saved_at"), "snapshot": mapsnapshot.describe(snap),
        "plan": mapsnapshot.summary(plan), "dry_run": dry_run}
    if dry_run:
        return result
    # setAreaInfo writes the active map; switch to the target first.
    info = await hass.async_add_executor_job(client.send, "getMapInfo")
    if (info.get("result") or {}).get("current_map_id") != map_id:
        await hass.async_add_executor_job(client.set_current_map, map_id)
        await asyncio.sleep(5)
    written: dict[str, int] = {}
    skipped = list(plan["skipped"])
    try:
        if plan["rooms"]:
            written["room"] = await hass.async_add_executor_job(client.set_areas, map_id, "room", plan["rooms"])
        for t, items in plan["zones"].items():
            written[t] = await hass.async_add_executor_job(client.set_areas, map_id, t, items)
        if plan["furniture"]:
            written["furniture"] = await hass.async_add_executor_job(client.set_furniture, map_id, plan["furniture"])
        for body in plan["presets"]:
            written.setdefault("presets", 0)
            if await hass.async_add_executor_job(client.add_preset, body) == 0:
                written["presets"] += 1
        if plan["schedules"]:
            _, presets_now, _ = await hass.async_add_executor_job(robot_state, client, map_id)
            ready, why = mapsnapshot.resolve_schedules(plan["schedules"], presets_now, map_id)
            skipped += why
            for rule in ready:
                await hass.async_add_executor_job(client.add_schedule, rule)
            written["schedules"] = len(ready)
    except Exception as exc:
        raise ApplyError(f"{exc} (written so far: {written})", written) from exc
    await coord.async_settings_changed()
    await coord.async_request_map_refresh()
    result.update(written=written, skipped=skipped)
    return result
