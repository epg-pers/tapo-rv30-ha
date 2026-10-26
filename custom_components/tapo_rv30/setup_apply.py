"""Putting a map's saved setup back onto the robot. Shared by apply_map_setup and the coordinator,
which finishes a lost-map restore by itself once the restored map has been saved in the app."""
from __future__ import annotations

import asyncio
import glob
import json
import logging
import os
import re
from typing import Any

from . import mapsnapshot
from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)


class ApplyError(Exception):
    """A write failed part way; .written says what had already been written."""

    def __init__(self, message: str, written: dict) -> None:
        super().__init__(message)
        self.written = written


class MapBusy(ApplyError):
    """Nothing was written: the robot is working or another map write is running. Try later."""

    def __init__(self, message: str) -> None:
        super().__init__(message, {})


def write_json(path: str, data) -> None:
    """Write through a temporary file, so a crash or power cut part way leaves the old file
    rather than a truncated one. Blocking."""
    tmp = f"{path}.tmp"
    with open(tmp, "w") as fh:
        json.dump(data, fh)
    os.replace(tmp, path)


def write_bytes(path: str, data: bytes) -> None:
    """write_json for bytes. Blocking."""
    tmp = f"{path}.tmp"
    with open(tmp, "wb") as fh:
        fh.write(data)
    os.replace(tmp, path)


def _legacy(hass) -> bool:
    """Before 0.28 every robot's files went into one shared folder. With one robot they are its
    own; with several there is no telling whose they are, so they are not offered (a backup of
    one robot restored onto another would bring that robot's schedules with it)."""
    return len(hass.config_entries.async_entries(DOMAIN, include_ignore=False)) <= 1


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
    return [snapshots_folder(hass, coord)] + ([hass.config.path(DOMAIN, "map_setups")] if _legacy(hass) else [])


def backups_folder(hass, coord) -> str:
    return os.path.join(hass.config.path(DOMAIN, "map_backups"), robot_key(coord))


def backup_folders(hass, coord) -> list[str]:
    return [backups_folder(hass, coord)] + ([hass.config.path(DOMAIN, "map_backups")] if _legacy(hass) else [])


def _saved_when(d: dict) -> float | None:
    """A setup's saved_at as a timestamp, or None when it is missing or not an ISO date."""
    from datetime import datetime
    try:
        return datetime.fromisoformat(d["saved_at"]).timestamp()
    except (KeyError, TypeError, ValueError, OverflowError, OSError):
        return None


def find_snapshot(folders, map_id: int | None, ref=None, exclude=None, prefer=()) -> dict | None:
    """The saved snapshot for map_id, or (ref given) the one whose saved id or name matches,
    looking in each folder in turn. An exact id wins (the first folder first); by name, across
    every folder, the newest saved setup does, as setups of deleted maps are kept and a
    re-mapped floor often keeps its old name. exclude (a map id or several: the target map,
    or maps the robot still has) is only taken by name when nothing else matches; prefer
    (map ids) ranks those first. Blocking."""
    from .mapdata import fold
    if isinstance(folders, str):
        folders = [folders]
    if ref in (None, ""):
        for folder in folders:
            p = os.path.join(folder, f"{map_id}.json")
            if os.path.exists(p):
                try:
                    with open(p) as fh:
                        return json.load(fh)
                except (OSError, ValueError) as exc:   # damaged: try the next folder
                    _LOGGER.warning("Map setup %s is unreadable (%s); looking for another copy", p, exc)
        return None
    skip = {str(exclude)} if isinstance(exclude, (int, str)) else {str(x) for x in exclude or ()}
    best = {str(x) for x in prefer}
    want = fold(str(ref).strip())
    named = []
    for n, folder in enumerate(folders):
        for p in sorted(glob.glob(os.path.join(folder, "*.json"))):
            try:
                with open(p) as fh:
                    d = json.load(fh)
            except (OSError, ValueError):
                continue
            if not isinstance(d, dict):
                continue
            if str(d.get("map_id")) == want:
                return d
            if fold(str(d.get("map_name") or "")) == want:
                named.append((n, d))

    def _rank(item: tuple) -> tuple:
        n, d = item
        mid, when = d.get("map_id"), _saved_when(d)
        return (str(mid) not in skip, str(mid) in best, when is not None, when or 0.0,
                mid if isinstance(mid, int) else -1, -n)
    return max(named, key=_rank)[1] if named else None


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
        raise MapBusy(f"another map write to {coord.device_name} is still running; try again shortly")
    async with coord.map_lock:     # one map write per robot at a time (each switches maps)
        # Tidying a restore writes the carrier's earlier setup back (and the backup's onto the
        # restored map) over whatever is applied now.
        # The coordinator finishes a restore with this only once it is tidied, so that still runs.
        if (pend := coord.restore_unfinished()) is not None and map_id in (pend.get("carrier"), pend.get("map_id")):
            raise MapBusy("this map is part of a restore that is still being tidied up; try again once the "
                          "robot is docked and the restore has finished")
        # Asked live: the last poll may predate the robot's own schedule starting it.
        if await coord._robot_working():
            raise MapBusy(f"{coord.device_name} is working (or part way through a clean); map writes wait "
                          "until it is docked and idle")
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
