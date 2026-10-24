"""Putting a map's saved setup back onto the robot. Shared by apply_map_setup and the coordinator,
which finishes a lost-map restore by itself once the restored map has been saved in the app."""
from __future__ import annotations

import asyncio
import glob
import json
import os
import re
from typing import Any

from . import mapsnapshot
from .const import DOMAIN


class ApplyError(Exception):
    """A write failed part way; .written says what had already been written."""

    def __init__(self, message: str, written: dict) -> None:
        super().__init__(message)
        self.written = written


def robot_key(coord) -> str:
    """Folder name for one robot's files: its MAC (stable across re-adding the integration),
    else its config entry id."""
    mac = ((coord.settings or {}).get("device") or {}).get("mac") or coord.device_mac
    if mac:
        return re.sub(r"[^0-9a-f]", "", str(mac).lower())
    return coord.entry.entry_id if coord.entry else "robot"


def snapshots_folder(hass, coord) -> str:
    """Where this robot's map setups are written."""
    return os.path.join(hass.config.path(DOMAIN, "map_setups"), robot_key(coord))


def snapshot_folders(hass, coord) -> list[str]:
    """Where this robot's map setups are read from: its own folder, then the shared folder
    versions before 0.28 wrote every robot's setups to."""
    return [snapshots_folder(hass, coord), hass.config.path(DOMAIN, "map_setups")]


def backups_folder(hass, coord) -> str:
    return os.path.join(hass.config.path(DOMAIN, "map_backups"), robot_key(coord))


def backup_folders(hass, coord) -> list[str]:
    return [backups_folder(hass, coord), hass.config.path(DOMAIN, "map_backups")]


def find_snapshot(folders, map_id: int | None, ref=None) -> dict | None:
    """The saved snapshot for map_id, or (ref given) the one whose saved id or name matches,
    looking in each folder in turn. Blocking."""
    from .mapdata import fold
    if isinstance(folders, str):
        folders = [folders]
    for folder in folders:
        if ref in (None, ""):
            p = os.path.join(folder, f"{map_id}.json")
            if os.path.exists(p):
                with open(p) as fh:
                    return json.load(fh)
            continue
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
    if coord.map_lock.locked():
        raise ApplyError(f"another map write to {coord.device_name} is still running; try again shortly", {})
    async with coord.map_lock:     # one map write per robot at a time (each switches maps)
        return await _write_plan(hass, coord, map_id, plan, result)


async def _write_plan(hass, coord, map_id: int, plan: dict, result: dict) -> dict[str, Any]:
    client = coord.client
    # setAreaInfo writes the active map; switch to the target first, and back afterwards so
    # the next clean does not start on the wrong floor.
    written: dict[str, int] = {}
    skipped = list(plan["skipped"])
    previous = None
    try:
        info = await hass.async_add_executor_job(client.send, "getMapInfo")
        current = (info.get("result") or {}).get("current_map_id")
        if current != map_id:
            # Remembered before the switch: if its reply is lost the robot may have switched.
            previous = current
            await hass.async_add_executor_job(client.set_current_map, map_id)
            await asyncio.sleep(5)
        if plan["rooms"]:
            written["room"] = await hass.async_add_executor_job(client.set_areas, map_id, "room", plan["rooms"])
        for t, items in plan["zones"].items():
            written[t] = await hass.async_add_executor_job(client.set_areas, map_id, t, items)
        if plan["furniture"]:
            written["furniture"] = await hass.async_add_executor_job(client.set_furniture, map_id, plan["furniture"])
        for body in plan["presets"]:
            # One preset the robot refuses (a room gone after a remap) must not stop the rest.
            written.setdefault("presets", 0)
            try:
                await hass.async_add_executor_job(client.add_preset, body)
                written["presets"] += 1
            except Exception as exc:
                skipped.append(f"preset {mapsnapshot._b64(body.get('rule_name'))!r}: {exc}")
        if plan["schedules"]:
            _, presets_now, _ = await hass.async_add_executor_job(robot_state, client, map_id)
            ready, why = mapsnapshot.resolve_schedules(plan["schedules"], presets_now, map_id)
            skipped += why
            written["schedules"] = 0
            for rule in ready:
                try:
                    await hass.async_add_executor_job(client.add_schedule, rule)
                    written["schedules"] += 1
                except Exception as exc:
                    skipped.append(f"schedule at {rule.get('s_min')} min: {exc}")
    except Exception as exc:
        raise ApplyError(f"{exc} (written so far: {written})", written) from exc
    finally:
        if previous is not None:
            try:
                await hass.async_add_executor_job(client.set_current_map, previous)
            except Exception as exc:
                skipped.append(f"could not switch back to map {previous}: {exc}")
    await coord.async_settings_changed()
    await coord.async_request_map_refresh()
    result.update(written=written, skipped=skipped)
    return result
