"""Custom services. Registered once per Home Assistant instance and routed to
the right vacuum from the call's target, so several vacuums can coexist."""
from __future__ import annotations

import logging

from homeassistant.core import HomeAssistant, ServiceCall, ServiceResponse, SupportsResponse
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError
from homeassistant.helpers import entity_registry as er

from .const import DOMAIN, FAN_NAME_TO_INT, REMOTE_CONTROL_CODE, REMOTE_DIRECTIONS, WATER_NAME_TO_INT
from .coordinator import TapoCoordinator
from .mapdata import build_schedule_rule, decode_clean_record, dnd_active, dnd_window, encode_weekdays, parse_hhmm
from .targets import INDIRECT_TARGET_KEYS, TargetError, as_list, has_indirect_target, resolve

_LOGGER = logging.getLogger(__name__)
SERVICES = ("clean_rooms", "set_room_settings", "clean_zone", "run_schedule", "send_raw",
            "get_clean_records", "run_preset", "set_map", "go_to",
            "add_schedule", "set_schedule", "remove_schedule", "remove_matter_fabric",
            "fetch_cloud_map_backups", "restore_map_backup", "cloud_firmware_info")


# Methods the integration itself calls while the robot is working.
SAFE_WHILE_BUSY = frozenset({
    "getVacStatus", "getCleanStatus", "getCleanInfo", "getCleanAttr", "getBatteryInfo",
    "getMopState", "getConsumablesInfo", "getAreaUnit", "getMapInfo", "getMapData",
    "getPathData", "get_device_info", "getDeviceInfo", "getCleanRecords", "getComponentList",
    "setSwitchClean", "setRobotPause", "setSwitchCharge", "playSelectAudio",
})


def _coordinators(hass: HomeAssistant, call: ServiceCall) -> list[TapoCoordinator]:
    """The coordinator(s) a call targets: named vacuum entities, or a device, area, floor or
    label that holds one. With no target, the only vacuum set up."""
    loaded: dict[str, TapoCoordinator] = hass.data.get(DOMAIN, {})
    explicit = as_list(call.data.get("entity_id"))
    indirect: list[str] = []
    indirect_given = has_indirect_target(call.data)
    if indirect_given:
        from homeassistant.helpers.target import TargetSelection, async_extract_referenced_entity_ids
        selection = TargetSelection({k: call.data[k] for k in INDIRECT_TARGET_KEYS if call.data.get(k)})
        selected = async_extract_referenced_entity_ids(hass, selection)
        indirect = sorted(selected.referenced | selected.indirectly_referenced)
    registry = er.async_get(hass)

    def entry_of(eid: str) -> tuple[str | None, str | None] | None:
        entry = registry.async_get(eid)
        return (entry.platform, entry.config_entry_id) if entry else None

    try:
        return resolve(loaded, explicit, indirect, entry_of, DOMAIN, indirect_given)
    except TargetError as exc:
        raise ServiceValidationError(f"{call.service}: {exc}") from None


def _one(hass: HomeAssistant, call: ServiceCall) -> TapoCoordinator:
    coords = _coordinators(hass, call)
    if len(coords) > 1:
        raise ServiceValidationError(f"{call.service}: target a single vacuum")
    return coords[0]


def _rooms_list(call: ServiceCall) -> list[str]:
    """'rooms' as a list. Templates give a bare string when one room is picked,
    and iterating a string would yield single characters."""
    raw = call.data.get("rooms", [])
    rooms = [raw] if isinstance(raw, str) else list(raw)
    if not rooms:
        raise ServiceValidationError(f"{call.service}: 'rooms' is required")
    return rooms


def _levels(call: ServiceCall) -> dict:
    out = {}
    try:
        if "suction" in call.data:
            out["suction"] = FAN_NAME_TO_INT[str(call.data["suction"]).strip().lower()]
        if "water" in call.data:
            out["cistern"] = WATER_NAME_TO_INT[str(call.data["water"]).strip().lower()]
        if "passes" in call.data:
            out["clean_number"] = int(call.data["passes"])
    except (KeyError, ValueError) as exc:
        raise ServiceValidationError(
            f"{call.service}: invalid value {exc}. suction: {list(FAN_NAME_TO_INT)}, "
            f"water: {list(WATER_NAME_TO_INT)}, passes: 1-3"
        ) from exc
    return out


async def _resolve(hass: HomeAssistant, call: ServiceCall, coord: TapoCoordinator) -> tuple[list[int], int]:
    """Resolve rooms/map from the call, raising a user-facing error on failure."""
    rooms = _rooms_list(call)
    try:
        return await hass.async_add_executor_job(
            coord.resolve_rooms_live, rooms, call.data.get("map")
        )
    except ValueError as exc:          # MapNotFound / RoomNotFound
        raise ServiceValidationError(f"{call.service}: {exc}") from exc
    except Exception as exc:
        raise HomeAssistantError(
            f"{call.service}: could not read maps from the vacuum: {exc}"
        ) from exc


def _require_idle(call: ServiceCall, coord: TapoCoordinator) -> None:
    """A new clean is refused by the robot (-3002) while one is running or
    paused; say so up front instead of relaying the bare device error."""
    busy = coord.busy
    if busy == "cleaning":
        raise ServiceValidationError(
            f"{call.service}: {coord.device_name} is already cleaning; stop or pause it first")
    if busy == "paused":
        raise ServiceValidationError(
            f"{call.service}: {coord.device_name} is paused; resume (vacuum.start) or stop it first")


async def _send(hass: HomeAssistant, call: ServiceCall, fn, *args) -> None:
    """Run a client write, surfacing device errors to the caller."""
    try:
        await hass.async_add_executor_job(fn, *args)
    except Exception as exc:
        raise HomeAssistantError(f"{call.service}: vacuum rejected the command: {exc}") from exc


def async_setup_services(hass: HomeAssistant) -> None:
    """Register the services once (safe to call per config entry)."""
    if hass.services.has_service(DOMAIN, SERVICES[0]):
        return

    async def handle_clean_rooms(call: ServiceCall) -> None:
        for coord in _coordinators(hass, call):
            _require_idle(call, coord)
            room_ids, map_id = await _resolve(hass, call, coord)
            await _send(hass, call, coord.client.clean_rooms, room_ids, map_id, True, _levels(call) or None)
            await coord.async_refresh_soon()

    async def handle_set_room_settings(call: ServiceCall) -> None:
        for coord in _coordinators(hass, call):
            room_ids, map_id = await _resolve(hass, call, coord)
            lv = _levels(call)
            try:
                await hass.async_add_executor_job(coord.client.set_room_settings, map_id, dict.fromkeys(room_ids, lv))
            except Exception as exc:
                if "-1001" in str(exc):
                    raise ServiceValidationError(
                        f"{call.service}: {coord.device_name}'s firmware does not store per-room settings "
                        "(it rejects setCleanAttr type custom). Give suction / water / passes to "
                        "tapo_rv30.clean_rooms for a single run, or save a preset in the Tapo app and use "
                        "tapo_rv30.run_preset.") from exc
                raise HomeAssistantError(f"{call.service}: vacuum rejected the command: {exc}") from exc
            await coord.async_request_refresh()

    async def handle_clean_zone(call: ServiceCall) -> None:
        coord = _one(hass, call)        # zones are in one map's coordinate frame
        _require_idle(call, coord)
        g = coord.data or {}
        lv = {"suction": g.get("suction", 3), "cistern": g.get("cistern", 0),
              "clean_number": 1, **_levels(call)}
        try:
            map_id, _ = await hass.async_add_executor_job(coord.client.get_map_info)
        except Exception as exc:
            raise HomeAssistantError(f"{call.service}: could not read maps from the vacuum: {exc}") from exc
        await _send(hass, call, coord.client.clean_zones, map_id, call.data["zones"],
                    lv["suction"], lv["cistern"], lv["clean_number"])
        await coord.async_refresh_soon()

    async def handle_go_to(call: ServiceCall) -> None:
        """Drive to a point given in map mm (same frame as position_mm / clean_zone)."""
        coord = _one(hass, call)
        if not coord.has("goto_point"):
            raise ServiceValidationError(f"{call.service}: {coord.device_name} does not support go-to-point")
        _require_idle(call, coord)
        try:
            x, y = int(call.data["x"]), int(call.data["y"])
        except (KeyError, TypeError, ValueError):
            raise ServiceValidationError(f"{call.service}: 'x' and 'y' (integers, mm) are required") from None
        await _send(hass, call, coord.client.goto_point, x, y)
        await coord.async_refresh_soon()

    async def handle_remote_drive(call: ServiceCall) -> ServiceResponse:
        """The app's remote control: enter, hold a direction, stop, exit. One call per step;
        the sidebar page repeats the held direction like the app does."""
        coord = _one(hass, call)
        if not coord.has("direction_control"):
            raise ServiceValidationError(f"{call.service}: {coord.device_name} has no remote control")
        command = str(call.data.get("command", "")).strip().lower()
        if command not in ("enter", "exit", *REMOTE_DIRECTIONS):
            raise ServiceValidationError(f"{call.service}: 'command' must be one of enter, forward, backward, left, "
                                         f"right, stop, exit (got {command!r})")
        if command == "exit":
            await _send(hass, call, coord.client.remote_control, False)
            await coord.async_refresh_soon()
            return {}
        if coord.status_code != REMOTE_CONTROL_CODE and coord.busy:
            raise ServiceValidationError(f"{call.service}: {coord.device_name} is {coord.busy}; stop it before taking control")
        if command == "enter":
            try:
                away_ms = await hass.async_add_executor_job(coord.client.remote_control, True)
            except Exception as exc:
                raise HomeAssistantError(f"{call.service}: vacuum rejected the command: {exc}") from exc
            await coord.async_refresh_soon()
            return {"leaving_dock_ms": away_ms or 4000}
        await _send(hass, call, coord.client.remote_drive, REMOTE_DIRECTIONS[command])
        return {"direction": REMOTE_DIRECTIONS[command]}

    async def _schedule_clean_attr(call: ServiceCall, coord: TapoCoordinator, base: dict | None) -> dict:
        """clean_attr for a schedule from rooms / preset / whole house plus levels.
        Starts from `base` (an existing rule's clean_attr) when editing."""
        attr = dict(base or {})
        g = coord.data or {}
        if "rooms" in call.data or "preset" in call.data:
            attr.pop("room_list", None); attr.pop("custom_rule_id", None)
            if call.data.get("preset") not in (None, ""):
                preset = coord.find_preset(call.data["preset"])
                if preset is None:
                    raise ServiceValidationError(f"{call.service}: no preset matching {call.data['preset']!r}")
                attr.update({"clean_mode": 5, "custom_rule_id": preset["id"], "map_id": preset.get("map_id") or coord.map_id})
            elif call.data.get("rooms"):
                room_ids, map_id = await _resolve(hass, call, coord)
                attr.update({"clean_mode": 3, "room_list": room_ids, "map_id": map_id})
            else:
                attr.update({"clean_mode": 0, "map_id": coord.map_id})
        elif "clean_mode" not in attr:
            attr.update({"clean_mode": 0, "map_id": coord.map_id})
        attr.setdefault("suction", g.get("suction", 2))
        attr.setdefault("cistern", g.get("cistern", 0))
        attr.setdefault("clean_number", g.get("clean_number", 1))
        attr.setdefault("clean_order", True)
        attr.update(_levels(call))
        return attr

    def _check_dnd(call: ServiceCall, coord: TapoCoordinator, minutes: int, enabled: bool) -> None:
        """The robot does not run a schedule whose start falls inside Do Not Disturb
        (verified: it stays docked, nothing is logged). The app warns; we refuse unless
        the caller says ignore_dnd, so an automation can't quietly create a dead schedule."""
        dnd = coord.settings.get("dnd")
        if not enabled or call.data.get("ignore_dnd") or not dnd_active(dnd, minutes):
            return
        w = dnd_window(dnd)
        raise ServiceValidationError(
            f"{call.service}: {minutes // 60:02d}:{minutes % 60:02d} is inside {coord.device_name}'s Do Not Disturb "
            f"window ({w['start']} to {w['end']}), so the robot would never run it. Move the time, change the "
            f"Do Not Disturb times, or pass ignore_dnd: true to save it anyway.")

    async def handle_add_schedule(call: ServiceCall) -> ServiceResponse:
        coord = _one(hass, call)
        try:
            minutes = parse_hhmm(call.data.get("time"))
            mask = encode_weekdays(call.data.get("days"))
        except ValueError as exc:
            raise ServiceValidationError(f"{call.service}: {exc}") from exc
        if not mask:
            raise ServiceValidationError(f"{call.service}: 'days' is required (Mon..Sun, daily, weekdays or weekend); "
                                         "one-off schedules are not supported, the robot stored a different date in testing")
        _check_dnd(call, coord, minutes, call.data.get("enabled", True))
        attr = await _schedule_clean_attr(call, coord, None)
        rule = build_schedule_rule(minutes, mask, attr, enabled=call.data.get("enabled", True))
        try:
            new_id = await hass.async_add_executor_job(coord.client.add_schedule, rule)
        except Exception as exc:
            raise HomeAssistantError(f"{call.service}: vacuum rejected the schedule: {exc}") from exc
        await coord.async_settings_changed()
        return {"id": new_id}

    def _find_rule(call: ServiceCall, coord: TapoCoordinator) -> dict:
        sid = str(call.data.get("schedule_id", "")).strip()
        if not sid:
            raise ServiceValidationError(f"{call.service}: 'schedule_id' is required (e.g. S1)")
        rules = (coord.settings.get("schedules") or {}).get("rule_list") or []
        rule = next((r for r in rules if str(r.get("id")) == sid), None)
        if rule is None:
            raise ServiceValidationError(f"{call.service}: no schedule {sid!r}; known: {[r.get('id') for r in rules]}")
        return rule

    async def handle_set_schedule(call: ServiceCall) -> None:
        coord = _one(hass, call)
        rule = dict(_find_rule(call, coord))
        try:
            minutes = parse_hhmm(call.data["time"]) if "time" in call.data else rule.get("s_min", 0)
            mask = encode_weekdays(call.data["days"]) if "days" in call.data else rule.get("week_day", 0)
        except ValueError as exc:
            raise ServiceValidationError(f"{call.service}: {exc}") from exc
        if not mask:
            raise ServiceValidationError(f"{call.service}: 'days' must leave at least one day")
        enabled = call.data.get("enabled", rule.get("enable", True))
        if "time" in call.data or call.data.get("enabled"):
            _check_dnd(call, coord, minutes, enabled)
        attr = await _schedule_clean_attr(call, coord, rule.get("clean_attr") or {})
        body = build_schedule_rule(minutes, mask, attr, enabled=enabled, rule_id=rule["id"])
        try:
            await hass.async_add_executor_job(coord.client.edit_schedule, body)
        except Exception as exc:
            raise HomeAssistantError(f"{call.service}: vacuum rejected the change: {exc}") from exc
        await coord.async_settings_changed()

    async def handle_remove_schedule(call: ServiceCall) -> None:
        coord = _one(hass, call)
        if call.data.get("all"):
            ids, remove_all = [], True
        else:
            ids, remove_all = [_find_rule(call, coord)["id"]], False
        try:
            await hass.async_add_executor_job(coord.client.remove_schedules, ids, remove_all)
        except Exception as exc:
            raise HomeAssistantError(f"{call.service}: vacuum rejected the removal: {exc}") from exc
        await coord.async_settings_changed()

    async def handle_remove_matter_fabric(call: ServiceCall) -> None:
        """Unpair the robot from one Matter ecosystem (fabric_index from the Matter sensor)."""
        coord = _one(hass, call)
        if not coord.has("matter"):
            raise ServiceValidationError(f"{call.service}: {coord.device_name} has no Matter support")
        try:
            idx = int(call.data["fabric_index"])
        except (KeyError, TypeError, ValueError):
            raise ServiceValidationError(f"{call.service}: 'fabric_index' (integer, see the Matter sensor) is required") from None
        known = [f.get("fabric_index") for f in ((coord.settings.get("matter_status") or {}).get("bind_fabrics") or [])]
        if known and idx not in known:
            raise ServiceValidationError(f"{call.service}: fabric {idx} is not paired; known fabrics: {known}")
        await _send(hass, call, coord.client.remove_matter_fabric, idx)
        await coord.async_settings_changed()

    async def handle_run_schedule(call: ServiceCall) -> None:
        """Replays a saved schedule's settings; see services.yaml."""
        coord = _one(hass, call)
        _require_idle(call, coord)
        sid = call.data.get("schedule_id")
        if sid is None:
            raise ServiceValidationError(f"{call.service}: 'schedule_id' is required")
        try:
            sid = int(sid)
        except (TypeError, ValueError):
            pass
        try:
            await hass.async_add_executor_job(coord.client.run_schedule, sid)
        except ValueError as exc:
            raise ServiceValidationError(f"{call.service}: {exc}") from exc
        except Exception as exc:
            raise HomeAssistantError(f"{call.service}: vacuum rejected the command: {exc}") from exc
        await coord.async_refresh_soon()

    async def handle_send_raw(call: ServiceCall) -> ServiceResponse:
        coord = _one(hass, call)
        method = str(call.data.get("method", "")).strip()
        if not method:
            raise ServiceValidationError(f"{call.service}: 'method' is required")
        params = call.data.get("params") or {}
        if not isinstance(params, dict):
            raise ServiceValidationError(f"{call.service}: 'params' must be a mapping")
        # Probing a robot mid-run is how the author lost a map set and the robot's
        # clean history (see README, "Protocol notes"). Known-safe status reads are
        # allowed; anything else waits for the robot to be idle unless forced.
        if coord.busy and method not in SAFE_WHILE_BUSY and not call.data.get("force"):
            raise ServiceValidationError(
                f"{call.service}: {coord.device_name} is {coord.busy}; '{method}' is not on the "
                f"known-safe list, so it is refused until the robot is idle (pass force: true to override)")
        try:
            resp = await hass.async_add_executor_job(coord.client.send, method, params)
        except Exception as exc:
            raise HomeAssistantError(f"{call.service}: {method} failed: {exc}") from exc
        return {"result": resp.get("result"), "error_code": resp.get("error_code", 0)}

    async def handle_get_clean_records(call: ServiceCall) -> ServiceResponse:
        coord = _one(hass, call)
        try:
            raw = await hass.async_add_executor_job(coord.client.get_clean_records)
        except Exception as exc:
            raise HomeAssistantError(f"{call.service}: {exc}") from exc
        records = sorted((decode_clean_record(r) for r in raw.get("record_list") or []),
                         key=lambda r: r["started"] or 0, reverse=True)
        limit = call.data.get("limit")
        if limit:
            records = records[:int(limit)]
        return {
            "total_runs": raw.get("total_number"),
            "total_area": raw.get("total_area"),
            "total_minutes": raw.get("total_time"),
            "records": records,
        }

    async def handle_run_preset(call: ServiceCall) -> None:
        coord = _one(hass, call)
        _require_idle(call, coord)
        ref = call.data.get("preset")
        if ref in (None, ""):
            raise ServiceValidationError(f"{call.service}: 'preset' (name or id) is required")
        preset = coord.find_preset(ref)
        if preset is None:
            names = [p["name"] for p in coord.presets]
            raise ServiceValidationError(
                f"{call.service}: no unique preset matching '{ref}'. Available: {names}")
        await _send(hass, call, coord.client.run_preset, preset["id"], preset["map_id"],
                    preset.get("clean_order", True))
        await coord.async_refresh_soon()

    async def handle_set_map(call: ServiceCall) -> None:
        coord = _one(hass, call)
        _require_idle(call, coord)
        ref = call.data.get("map")
        if ref in (None, ""):
            raise ServiceValidationError(f"{call.service}: 'map' (name or id) is required")
        try:
            names = await hass.async_add_executor_job(coord.map_names)
        except Exception as exc:
            raise HomeAssistantError(f"{call.service}: could not read maps from the vacuum: {exc}") from exc
        from .mapdata import fold
        wanted = fold(str(ref).strip())
        hits = [mid for mid, n in names.items() if str(mid) == wanted or fold(n) == wanted]
        hits = hits or [mid for mid, n in names.items() if wanted and wanted in fold(n)]
        if len(hits) != 1:
            raise ServiceValidationError(
                f"{call.service}: no unique map matching '{ref}'. Available: {sorted(names.values())}")
        await _send(hass, call, coord.client.set_current_map, hits[0])
        await coord.async_request_map_refresh()

    async def handle_fetch_cloud_map_backups(call: ServiceCall) -> ServiceResponse:
        import uuid

        from homeassistant.const import CONF_PASSWORD, CONF_USERNAME

        from .cloud import CloudError, fetch_backups
        coord = _one(hass, call)
        if coord.entry is None:
            raise ServiceValidationError(f"{call.service}: no config entry")
        folder = hass.config.path(DOMAIN, "map_backups")
        terminal = str(uuid.uuid5(uuid.NAMESPACE_URL, f"{DOMAIN}:{coord.entry.entry_id}"))
        try:
            return await hass.async_add_executor_job(
                fetch_backups, coord.client, coord.entry.data[CONF_USERNAME], coord.entry.data[CONF_PASSWORD],
                terminal, folder, not coord.busy, call.data.get("verification_code"))
        except CloudError as exc:
            raise HomeAssistantError(f"{call.service}: {exc}") from exc
        except Exception as exc:
            raise HomeAssistantError(f"{call.service}: {type(exc).__name__}: {exc}") from exc

    async def handle_restore_map_backup(call: ServiceCall) -> ServiceResponse:
        import asyncio
        import os
        import uuid

        from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
        from homeassistant.helpers.network import NoURLAvailableError, get_url

        from .cloud import CloudError, cloud_backup_link, local_backup_file
        from .maprestore import serve_data
        coord = _one(hass, call)
        if not call.data.get("confirm"):
            raise ServiceValidationError(f"{call.service}: this overwrites a map on the robot; set confirm: true")
        if coord.busy or coord.entry is None:
            raise ServiceValidationError(f"{call.service}: {coord.device_name} must be docked and idle")
        map_id = int(call.data["map_id"])
        names = await hass.async_add_executor_job(coord.map_names)
        if map_id not in names and not call.data.get("allow_missing_map"):
            raise ServiceValidationError(f"{call.service}: no map {map_id} on the robot ({names})")
        source = call.data.get("source", "local")
        out: dict = {"map_id": map_id, "map_name": names.get(map_id, "(not on the robot)"), "source": source,
                     "maps_before": {str(k): v for k, v in names.items()}}
        link = None
        try:
            if source in ("cloud", "redirect"):
                terminal = str(uuid.uuid5(uuid.NAMESPACE_URL, f"{DOMAIN}:{coord.entry.entry_id}"))
                url, md5 = await hass.async_add_executor_job(
                    cloud_backup_link, coord.client, coord.entry.data[CONF_USERNAME],
                    coord.entry.data[CONF_PASSWORD], terminal, map_id)
                out["url"] = "TP-Link cloud link"
                if source == "redirect":
                    # Diagnostic: our link, answering 302 to TP-Link's.
                    base = call.data.get("base_url") or get_url(
                        hass, allow_external=False, allow_cloud=False, prefer_external=False)
                    url_path, _, link = serve_data(hass, "redirect", b"", f"robotVacMap/{map_id}", redirect=url)
                    url = base.rstrip("/") + url_path
                    out["url"] = base.rstrip("/") + "/api/tapo_rv30/map_backup/... -> TP-Link cloud link"
            else:
                path = await hass.async_add_executor_job(
                    local_backup_file, hass.config.path(DOMAIN, "map_backups"), map_id)
                if path is None:
                    raise ServiceValidationError(f"{call.service}: no saved backup of map {map_id}; "
                                                 "run fetch_cloud_map_backups first")
                from pathlib import Path
                data = await hass.async_add_executor_job(Path(path).read_bytes)
                try:
                    base = call.data.get("base_url") or get_url(
                        hass, allow_external=False, allow_cloud=False, prefer_external=False)
                except NoURLAvailableError as exc:
                    raise ServiceValidationError(f"{call.service}: no internal URL for Home Assistant; "
                                                 "set one or pass base_url") from exc
                url_path, md5, link = serve_data(hass, os.path.basename(path), data, f"robotVacMap/{map_id}")
                url = base.rstrip("/") + url_path
                out.update(file=os.path.basename(path), url=base.rstrip("/") + "/api/tapo_rv30/map_backup/...")
            out["md5"] = md5
            if call.data.get("dry_run"):
                # Serve the file but leave the robot alone, to check what a download returns.
                if source == "local":
                    out["url"] = url
                else:
                    import hashlib

                    import requests
                    resp = await hass.async_add_executor_job(
                        lambda: requests.get(url, timeout=30, headers={"User-Agent": "SHIP/2.0"}))
                    out["cloud_headers"] = {k: v for k, v in resp.headers.items() if not k.lower().startswith("x-amz-id")}
                    out["cloud_status"] = resp.status_code
                    out["cloud_body_md5"] = hashlib.md5(resp.content).hexdigest()
                    from urllib.parse import urlparse
                    parsed = urlparse(url)
                    out["cloud_host"], out["cloud_path"] = parsed.hostname, parsed.path
                return out
            resp = await hass.async_add_executor_job(
                coord.client.send, "mapRecovery", {"map_id": map_id, "map_md5": md5, "url": url})
            out["mapRecovery"] = resp
            progress, seen_restore = [], False
            for _ in range(int(call.data.get("wait", 180)) // 5):
                await asyncio.sleep(5)
                try:
                    p = (await hass.async_add_executor_job(
                        coord.client.send, "getMapBRProcess", {"map_id": map_id})).get("result")
                except Exception as exc:
                    p = {"error": str(exc)}
                if not progress or progress[-1] != p:
                    progress.append(p)
                if isinstance(p, dict) and p.get("type") == 2:
                    seen_restore = True
                elif seen_restore and isinstance(p, dict) and p.get("type") == 0:
                    break
            out["progress"] = progress
        except CloudError as exc:
            raise HomeAssistantError(f"{call.service}: {exc}") from exc
        except ServiceValidationError:
            raise
        except Exception as exc:
            out["error"] = f"{type(exc).__name__}: {exc}"
        if link is not None:
            out["robot_downloads"] = link["hits"]
        try:
            after = await hass.async_add_executor_job(coord.map_names)
            out["maps_after"] = {str(k): v for k, v in after.items()}
        except Exception as exc:
            out["maps_after"] = f"could not read: {exc}"
        await coord.async_request_map_refresh()
        return out

    async def handle_cloud_firmware_info(call: ServiceCall) -> ServiceResponse:
        import uuid

        from homeassistant.const import CONF_PASSWORD, CONF_USERNAME

        from .cloud import CloudError, firmware_info
        coord = _one(hass, call)
        if coord.entry is None:
            raise ServiceValidationError(f"{call.service}: no config entry")
        terminal = str(uuid.uuid5(uuid.NAMESPACE_URL, f"{DOMAIN}:{coord.entry.entry_id}"))
        try:
            return await hass.async_add_executor_job(
                firmware_info, coord.client, coord.entry.data[CONF_USERNAME], coord.entry.data[CONF_PASSWORD],
                terminal, call.data.get("current_version") or "1.0.0 Build 000000 Rel.000000")
        except CloudError as exc:
            raise HomeAssistantError(f"{call.service}: {exc}") from exc

    hass.services.async_register(DOMAIN, "cloud_firmware_info", handle_cloud_firmware_info,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN, "fetch_cloud_map_backups", handle_fetch_cloud_map_backups,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN, "restore_map_backup", handle_restore_map_backup,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN, "clean_rooms", handle_clean_rooms)
    hass.services.async_register(DOMAIN, "run_preset", handle_run_preset)
    hass.services.async_register(DOMAIN, "set_map", handle_set_map)
    hass.services.async_register(DOMAIN, "go_to", handle_go_to)
    hass.services.async_register(DOMAIN, "remote_drive", handle_remote_drive,
                                 supports_response=SupportsResponse.OPTIONAL)
    hass.services.async_register(DOMAIN, "add_schedule", handle_add_schedule,
                                 supports_response=SupportsResponse.OPTIONAL)
    hass.services.async_register(DOMAIN, "set_schedule", handle_set_schedule)
    hass.services.async_register(DOMAIN, "remove_schedule", handle_remove_schedule)
    hass.services.async_register(DOMAIN, "remove_matter_fabric", handle_remove_matter_fabric)
    hass.services.async_register(DOMAIN, "get_clean_records", handle_get_clean_records,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN, "set_room_settings", handle_set_room_settings)
    hass.services.async_register(DOMAIN, "clean_zone", handle_clean_zone)
    hass.services.async_register(DOMAIN, "run_schedule", handle_run_schedule)
    hass.services.async_register(DOMAIN, "send_raw", handle_send_raw,
                                 supports_response=SupportsResponse.ONLY)


def async_unload_services(hass: HomeAssistant) -> None:
    """Remove the services once the last config entry is gone."""
    for svc in SERVICES:
        hass.services.async_remove(DOMAIN, svc)
