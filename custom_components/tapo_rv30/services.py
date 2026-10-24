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
            "fetch_cloud_map_backups", "save_map_setup", "apply_map_setup", "restore_map_backup")


# Methods the integration itself calls while the robot is working.
SAFE_WHILE_BUSY = frozenset({
    "getVacStatus", "getCleanStatus", "getCleanInfo", "getCleanAttr", "getBatteryInfo",
    "getMopState", "getConsumablesInfo", "getAreaUnit", "getMapInfo", "getMapData",
    "getPathData", "get_device_info", "getDeviceInfo", "getCleanRecords", "getComponentList",
    "setSwitchClean", "setRobotPause", "setSwitchCharge", "playSelectAudio",
})

# Onboarding, system and factory calls from the robot's dispatcher. Never sent from HA, even
# with force: setInheritInfo belongs to first-time setup (keep the old maps or start fresh) and
# is the prime suspect for a total map wipe on this robot.
BLOCKED_METHODS = frozenset({
    "setInheritInfo", "setQuickSetupInfo", "setQuickSetupExtraInfo", "setIotCheckFlag",
    "deviceReset", "deviceReboot", "firmwareUpgrade", "setWifiInfo", "unbindDevice",
    "setDeviceInfo", "setLidarEnabled", "closeDeviceBLE",
    "set_inherit_info", "set_quick_setup_info", "set_wifi_info", "set_wireless_info",
    "set_factory_mode", "exec_atcmd", "erase_flash", "fw_download", "account_sync",
    "connect_cloud", "device_reset", "device_reboot", "unbind_device", "set_lidar_enabled",
    "set_forwarding", "debug_nbus", "test",
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
        if method in BLOCKED_METHODS or method.lower() in BLOCKED_METHODS:
            raise ServiceValidationError(
                f"{call.service}: '{method}' is an onboarding, system or factory call and is blocked. "
                "Calls like this have wiped this robot's maps; use the Tapo app for them.")
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

    async def _setup_map_id(call: ServiceCall, coord: TapoCoordinator) -> tuple[int, dict]:
        """(map_id, names) for a map-setup call: the 'map' field (name or id), else active."""
        names = await hass.async_add_executor_job(coord.map_names)
        ref = call.data.get("map")
        if ref in (None, ""):
            return coord.map_id, names
        from .mapdata import fold
        wanted = fold(str(ref).strip())
        hits = [mid for mid, n in names.items() if str(mid) == wanted or fold(n) == wanted]
        if len(hits) != 1:
            raise ServiceValidationError(
                f"{call.service}: no unique map matching '{ref}'. Available: {sorted(names.values())}")
        return hits[0], names

    def _robot_state(coord: TapoCoordinator, map_id: int) -> tuple[dict, list, list]:
        """(map data, raw preset details, raw schedules) as the robot has them now. Blocking."""
        data = coord.client.get_map_data(map_id)
        presets = []
        for rule in coord.client.get_presets():
            if rule.get("map_id") == map_id:
                detail = coord.client.get_preset_detail(map_id, rule["rule_id"])
                presets.append({**detail, "rule_id": rule["rule_id"], "map_id": map_id})
        return data, presets, coord.client.get_schedules()

    def _snapshots_folder() -> str:
        return hass.config.path(DOMAIN, "map_setups")

    def _find_snapshot(map_id: int | None, ref) -> dict | None:
        """The saved snapshot for map_id, or (ref given) the one whose saved id or name matches."""
        import glob
        import json
        import os

        from .mapdata import fold
        folder = _snapshots_folder()
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

    async def handle_save_map_setup(call: ServiceCall) -> ServiceResponse:
        import json
        import os
        import time

        from . import mapsnapshot
        coord = _one(hass, call)
        map_id, names = await _setup_map_id(call, coord)
        data, presets, schedules = await hass.async_add_executor_job(_robot_state, coord, map_id)
        snap = mapsnapshot.build(map_id, names.get(map_id), data.get("area_list", []),
                                 data.get("furniture_list", []), presets, schedules,
                                 time.strftime("%Y-%m-%dT%H:%M:%S"))
        folder = _snapshots_folder()

        def _write() -> None:
            os.makedirs(os.path.join(folder, "history"), exist_ok=True)
            stamp = time.strftime("%Y%m%d-%H%M%S")
            for path in (os.path.join(folder, f"{map_id}.json"),
                         os.path.join(folder, "history", f"{map_id}_{stamp}.json")):
                with open(path, "w") as fh:
                    json.dump(snap, fh)

        await hass.async_add_executor_job(_write)
        return {"map_id": map_id, "map_name": names.get(map_id), "saved": snap["counts"],
                "furniture": len(snap["furniture"]), "presets": len(snap["presets"]),
                "schedules": len(snap["schedules"]), "file": f"map_setups/{map_id}.json"}

    async def handle_apply_map_setup(call: ServiceCall) -> ServiceResponse:
        import asyncio

        from . import mapsnapshot
        coord = _one(hass, call)
        dry_run = bool(call.data.get("dry_run"))
        if not dry_run and not call.data.get("confirm"):
            raise ServiceValidationError(
                f"{call.service}: this writes rooms, zones, furniture, presets and schedules; "
                "set confirm: true (or dry_run: true to see what it would do)")
        if coord.busy and not dry_run:
            raise ServiceValidationError(f"{call.service}: {coord.device_name} must be docked and idle")
        map_id, names = await _setup_map_id(call, coord)
        src = call.data.get("source_map")
        snap = await hass.async_add_executor_job(_find_snapshot, map_id, src)
        if snap is None:
            where = f"matching source_map '{src}'" if src else f"for map {map_id}"
            raise ServiceValidationError(f"{call.service}: no saved setup {where}; run save_map_setup first")
        data, presets, schedules = await hass.async_add_executor_job(_robot_state, coord, map_id)
        plan = mapsnapshot.plan(snap, map_id, data.get("area_list", []), data.get("furniture_list", []),
                                presets, schedules)
        result = {"map_id": map_id, "map_name": names.get(map_id),
                  "from_setup": snap.get("map_name") or snap.get("map_id"), "saved_at": snap.get("saved_at"),
                  "plan": mapsnapshot.summary(plan), "dry_run": dry_run}
        if dry_run:
            return result
        # setAreaInfo writes the active map; switch to the target first.
        info = await hass.async_add_executor_job(coord.client.send, "getMapInfo")
        if (info.get("result") or {}).get("current_map_id") != map_id:
            await hass.async_add_executor_job(coord.client.set_current_map, map_id)
            await asyncio.sleep(5)
        written: dict[str, int] = {}
        skipped = list(plan["skipped"])
        try:
            if plan["rooms"]:
                written["room"] = await hass.async_add_executor_job(
                    coord.client.set_areas, map_id, "room", plan["rooms"])
            for t, items in plan["zones"].items():
                written[t] = await hass.async_add_executor_job(coord.client.set_areas, map_id, t, items)
            if plan["furniture"]:
                written["furniture"] = await hass.async_add_executor_job(
                    coord.client.set_furniture, map_id, plan["furniture"])
            for body in plan["presets"]:
                written.setdefault("presets", 0)
                if await hass.async_add_executor_job(coord.client.add_preset, body) == 0:
                    written["presets"] += 1
            if plan["schedules"]:
                _, presets_now, _ = await hass.async_add_executor_job(_robot_state, coord, map_id)
                ready, why = mapsnapshot.resolve_schedules(plan["schedules"], presets_now, map_id)
                skipped += why
                for rule in ready:
                    await hass.async_add_executor_job(coord.client.add_schedule, rule)
                written["schedules"] = len(ready)
        except Exception as exc:
            raise HomeAssistantError(f"{call.service}: {exc} (written so far: {written})") from exc
        await coord.async_settings_changed()
        await coord.async_request_map_refresh()
        result.update(written=written, skipped=skipped)
        return result

    async def handle_restore_map_backup(call: ServiceCall) -> ServiceResponse:
        """Restore a map backup to the robot. By default HA serves the backup it already holds
        on a short-lived LAN URL and the robot fetches and applies it - a fully local restore,
        no cloud. use_cloud_url hands the robot the backup's own TP-Link URL instead, for when
        the robot cannot reach HA on the LAN."""
        import asyncio
        import hashlib
        import os
        import secrets

        from homeassistant.components.network import async_get_source_ip

        from .map_restore import async_setup_map_restore
        coord = _one(hass, call)
        if not call.data.get("confirm"):
            raise ServiceValidationError(f"{call.service}: this overwrites a map on the robot; set confirm: true")
        if coord.busy:
            raise ServiceValidationError(f"{call.service}: {coord.device_name} must be docked and idle")
        import re

        from . import mapsnapshot
        from .mapdata import fold
        folder = hass.config.path(DOMAIN, "map_backups")
        names = await hass.async_add_executor_job(coord.map_names)
        ref, fname = call.data.get("map"), call.data.get("file")
        # Which map the backup belongs to. It may no longer exist on the robot (the lost-map
        # case), so beyond the robot's own maps, accept a bare map id, a saved setup's map
        # name, or the id in the backup file's name.
        backup_id = None
        snap_name = None
        if ref not in (None, ""):
            want = fold(str(ref).strip())
            hits = [mid for mid, n in names.items() if str(mid) == want or fold(n) == want]
            if len(hits) > 1:
                raise ServiceValidationError(f"{call.service}: '{ref}' matches several maps: {sorted(names.values())}")
            if hits:
                backup_id = hits[0]
            elif want.isdigit():
                backup_id = int(want)
            else:
                snap = await hass.async_add_executor_job(_find_snapshot, None, ref)
                if snap:
                    backup_id, snap_name = snap.get("map_id"), snap.get("map_name")
        if backup_id is None and fname:
            m = re.match(r"^(?:cloud|local)_(\d+)_\d+\.(?:bin|bkmap)$", os.path.basename(str(fname)))
            if m:
                backup_id = int(m.group(1))
        if backup_id is None and ref in (None, ""):
            backup_id = coord.map_id
        if backup_id is None:
            raise ServiceValidationError(
                f"{call.service}: no map matching '{ref}' on the robot or in the saved map setups; "
                f"pass the map id or file: (robot maps: {sorted(names.values())})")
        try:
            map_id, carrier = mapsnapshot.restore_target(names, coord.map_id, backup_id)
        except ValueError as exc:
            raise ServiceValidationError(f"{call.service}: {exc}") from exc

        def _pick() -> str | None:
            if fname:
                p = os.path.join(folder, os.path.basename(str(fname)))
                return p if os.path.isfile(p) else None
            # cloud_<map_id>_<timestamp>.bin only - never the _snapshot preview image.
            pat = re.compile(rf"^cloud_{backup_id}_\d+\.bin$")
            cands = sorted(f for f in os.listdir(folder) if pat.match(f))
            return os.path.join(folder, cands[-1]) if cands else None

        # Default: serve the backup from HA on the LAN and let the robot fetch it directly - a
        # fully local restore, no cloud. The robot's HTTP client needs a clean Content-Length
        # response, so the URL must be HA's direct LAN address: a reverse proxy in front of HA
        # that serves the body chunked makes the robot's download stall near the end and fail.
        # base_url overrides the auto-derived address; use_cloud_url hands the robot the backup's
        # own TP-Link URL instead, for when it cannot reach HA on the LAN.
        store = None
        token = None
        src = "local"
        if call.data.get("use_cloud_url"):
            import uuid as _uuid

            from homeassistant.const import CONF_PASSWORD, CONF_USERNAME

            from .cloud import _connect
            terminal = str(_uuid.uuid5(_uuid.NAMESPACE_URL, f"{DOMAIN}:{coord.entry.entry_id}"))

            def _cloud_backup() -> dict | None:
                cloud, thing = _connect(coord.client, coord.entry.data[CONF_USERNAME],
                                        coord.entry.data[CONF_PASSWORD], terminal,
                                        call.data.get("verification_code"))
                best = None
                for b in cloud.map_backups(thing):
                    if b.get("mapId") == backup_id and (best is None
                            or (b.get("timestamp") or 0) > (best.get("timestamp") or 0)):
                        best = b
                return best

            best = await hass.async_add_executor_job(_cloud_backup)
            if not best or not best.get("mapUrl"):
                raise ServiceValidationError(f"{call.service}: no cloud backup for map {backup_id}")
            url = best["mapUrl"]
            md5 = best.get("mapMd5")
            src = "cloud"
        else:
            path = await hass.async_add_executor_job(_pick)
            if path is None:
                raise ServiceValidationError(
                    f"{call.service}: no backup file for map {backup_id} in {folder}; "
                    "run fetch_cloud_map_backups first, or pass file:")
            md5 = await hass.async_add_executor_job(
                lambda: hashlib.md5(open(path, "rb").read()).hexdigest())  # noqa: SIM115
            base = call.data.get("base_url")
            if base:
                base = str(base).rstrip("/")
            else:
                ip = await async_get_source_ip(hass, coord.client.host)
                scheme = "https" if hass.http.ssl_certificate else "http"
                base = f"{scheme}://{ip}:{hass.http.server_port}"
            store = async_setup_map_restore(hass)
            token = secrets.token_urlsafe(24)
            store[token] = path
            url = f"{base}/api/tapo_rv30/bkmap/{token}"
        try:
            try:
                code = await hass.async_add_executor_job(coord.client.recover_map, map_id, md5, url)
            except RuntimeError as exc:
                raise HomeAssistantError(f"{call.service}: {exc}") from exc
            process = {}
            for _ in range(30):
                await asyncio.sleep(2)
                process = await hass.async_add_executor_job(coord.client.get_map_br_process)
                if process.get("process") in (100, "100") or process.get("status") not in (None, 0, 1):
                    break
        finally:
            if store is not None and token is not None:
                await asyncio.sleep(3)  # let a slow fetch finish before the URL stops serving
                store.pop(token, None)
        await coord.async_request_map_refresh()
        status = process.get("status")
        # Where did it land? The robot restores under the backup's own map id; if that id was
        # gone it comes back as a new, unsaved map that must be saved in the Tapo app.
        landed = None
        if status == 3:
            try:
                _, map_list = await hass.async_add_executor_job(coord.client.get_map_info)
                landed = next((m for m in map_list if m.get("map_id") == backup_id), None)
            except Exception:  # the restore itself already succeeded
                landed = None
        saved = bool(landed) and landed.get("is_saved", True) is not False
        # The robot reports status 3 when the map is applied, 13 on failure, 2 while still working.
        note = ("restore failed on the robot (status 13); if the backup is served through a reverse "
                "proxy, set base_url to HA's direct LAN address" if status == 13
                else "still applying when polling ended" if status == 2 else None)
        next_steps = None
        if status == 3 and landed and not saved:
            next_steps = (f"The map came back as a new, unsaved map (id {backup_id}). Save it in the Tapo app "
                          "(keep the name), then run apply_map_setup on it to put back room names, no-go zones, "
                          "furniture, presets and schedules. Delete any throwaway map afterwards.")
        elif status == 3:
            next_steps = ("Run apply_map_setup on this map (dry_run: true first to preview) to put back anything "
                          "the backup does not carry: room names, zones, furniture, presets, schedules.")
        return {"map_id": map_id, "map_name": names.get(map_id), "backup_map_id": backup_id,
                "backup_map_name": names.get(backup_id) or snap_name, "carrier": carrier,
                "restored_map_saved": saved if status == 3 else None, "source": src, "md5": md5,
                "url": url, "error_code": code, "process": process, "applied": status == 3,
                "note": note, "next_steps": next_steps}

    hass.services.async_register(DOMAIN, "restore_map_backup", handle_restore_map_backup,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN, "save_map_setup", handle_save_map_setup,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN, "apply_map_setup", handle_apply_map_setup,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN, "fetch_cloud_map_backups", handle_fetch_cloud_map_backups,
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
