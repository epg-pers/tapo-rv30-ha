"""Custom services. Registered once per Home Assistant instance and routed to
the right vacuum from the call's target, so several vacuums can coexist."""
from __future__ import annotations

import json
import logging
import re

from homeassistant.core import HomeAssistant, ServiceCall, ServiceResponse, SupportsResponse
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError, Unauthorized
from homeassistant.helpers import entity_registry as er

from . import backupstore
from .const import DOMAIN, FAN_NAME_TO_INT, REMOTE_CONTROL_CODE, REMOTE_DIRECTIONS, WATER_NAME_TO_INT
from .coordinator import TapoCoordinator
from .mapdata import b64name, build_schedule_rule, decode_clean_record, dnd_active, dnd_window, encode_weekdays, parse_hhmm
from .targets import INDIRECT_TARGET_KEYS, TargetError, as_list, has_indirect_target, resolve
from .tpap import RobotBusy, _opt_int

_LOGGER = logging.getLogger(__name__)
SERVICES = ("clean_rooms", "set_room_settings", "clean_zone", "run_schedule", "send_raw",
            "get_clean_records", "run_preset", "set_map", "go_to",
            "add_schedule", "set_schedule", "remove_schedule", "remove_matter_fabric", "get_matter_setup_code",
            "rename_map", "set_map_rotation", "set_map_lock",
            "fetch_cloud_map_backups", "save_map_setup", "apply_map_setup", "restore_map_backup", "copy_map", "delete_map",
            "backup_map", "create_preset", "update_preset", "delete_preset", "remote_drive")


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
    # quick-setup twins and other onboarding / factory / map-deleting calls
    "set_qs_info", "set_qs_extra_info", "qs_component_nego", "getQsComponentList", "component_nego",
    "get_factory_mode", "set_button_detect_status", "clear_button_detect_status", "sync_env", "deleteMap",
})
_BLOCKED_NORM = frozenset(m.replace("_", "").lower() for m in BLOCKED_METHODS)


def _raw_methods(method: str, params: dict) -> list[str]:
    """Every method a send_raw call would run: multipleRequest carries its own list (which
    may nest), and each of those must pass the same checks as a plain call."""
    out = [method]
    if method.replace("_", "").lower() == "multiplerequest":
        for req in (params.get("requests") or []) if isinstance(params, dict) else []:
            if isinstance(req, dict):
                out += _raw_methods(str(req.get("method", "")), req.get("params") or {})
    return out


def _known(value, default):
    """The polled value, or default when the robot did not report it (None)."""
    return default if value is None else value


def _is_blocked(method: str) -> bool:
    """Blocked, or not a plain method name at all: a name with hidden characters ("\\x00", a
    zero-width space) could read as a blocked one on the robot while passing this check."""
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", method):
        return True
    return method.replace("_", "").lower() in _BLOCKED_NORM


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
        raise ServiceValidationError(f"{call.service}: 'rooms' (or 'room_ids') is required")
    return rooms


def _flag(value) -> bool:
    """A yes/no field: true, 1, "true", "yes", "on" (no schema coerces it)."""
    if isinstance(value, str):
        return value.strip().lower() in ("true", "yes", "on", "1")
    return bool(value)


def _levels(call: ServiceCall) -> dict:
    out = {}
    try:
        if "suction" in call.data:
            out["suction"] = FAN_NAME_TO_INT[str(call.data["suction"]).strip().lower()]
        if "water" in call.data:
            water = call.data["water"]
            # Unquoted `water: off` in YAML arrives as False.
            out["cistern"] = WATER_NAME_TO_INT["off" if water is False else str(water).strip().lower()]
        if "passes" in call.data:
            out["clean_number"] = int(call.data["passes"])
            if not 1 <= out["clean_number"] <= 3:
                raise ValueError(f"passes {out['clean_number']}")
    except (KeyError, ValueError) as exc:
        raise ServiceValidationError(
            f"{call.service}: invalid value {exc}. suction: {list(FAN_NAME_TO_INT)}, "
            f"water: {list(WATER_NAME_TO_INT)}, passes: 1-3"
        ) from exc
    return out


async def _resolve(hass: HomeAssistant, call: ServiceCall, coord: TapoCoordinator,
                   map_id: int | None = None) -> tuple[list[int], int]:
    """Resolve rooms/map from the call, raising a user-facing error on failure. room_ids
    (from the card and panel) name rooms exactly, including unnamed and same-named ones."""
    ids = call.data.get("room_ids")
    if ids not in (None, "", []):
        try:
            ids = [int(i) for i in ([ids] if isinstance(ids, (int, str)) else ids)]
        except (TypeError, ValueError):
            raise ServiceValidationError(f"{call.service}: 'room_ids' must be a list of room numbers") from None
        rooms = []
    else:
        ids = None
        rooms = _rooms_list(call)
    try:
        return await hass.async_add_executor_job(
            coord.resolve_rooms_live, rooms, None if map_id is not None else call.data.get("map"), map_id, ids
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
    if why := coord.start_refused():
        raise ServiceValidationError(f"{call.service}: {coord.device_name} {why}")
    busy = coord.busy
    if busy == "cleaning":
        raise ServiceValidationError(
            f"{call.service}: {coord.device_name} is already cleaning; stop or pause it first")
    if busy == "paused":
        raise ServiceValidationError(
            f"{call.service}: {coord.device_name} is paused; resume (vacuum.start) or stop it first")
    if busy:
        raise ServiceValidationError(f"{call.service}: {coord.device_name} is {busy}")


async def _send(hass: HomeAssistant, call: ServiceCall, fn, *args) -> None:
    """Run a client write, surfacing device errors to the caller."""
    try:
        await hass.async_add_executor_job(fn, *args)
    except RobotBusy as exc:
        raise ServiceValidationError(f"{call.service}: the vacuum {exc}") from exc
    except Exception as exc:
        raise HomeAssistantError(f"{call.service}: vacuum rejected the command: {exc}") from exc


MAP_NAME_MAX = 32     # the Tapo app's map name limit


def _match_map(call: ServiceCall, names: dict[int, str], ref, exact: bool = False) -> int:
    """One map from a name or id: an id or exact name first, then (unless exact) a unique
    partial name. Writes use exact, so a short name cannot land on the wrong map."""
    if ref in (None, ""):
        raise ServiceValidationError(f"{call.service}: 'map' (name or id) is required")
    from .mapdata import fold
    wanted = fold(str(ref).strip())
    hits = [mid for mid, n in names.items() if str(mid) == wanted or fold(n) == wanted]
    if not exact:
        hits = hits or [mid for mid, n in names.items() if wanted and wanted in fold(n)]
    if len(hits) != 1:
        raise ServiceValidationError(
            f"{call.service}: no unique map matching '{ref}'. Available: {sorted(names.values())}")
    return hits[0]


def _map_name(call: ServiceCall, value) -> str:
    """A new map name as the app would store it: NFC, runs of spaces collapsed, no control or
    invisible characters, 1 to MAP_NAME_MAX UTF-16 units (how the app counts)."""
    import unicodedata
    name = " ".join(unicodedata.normalize("NFC", str(value or "")).split())
    if any(unicodedata.category(ch).startswith("C") for ch in name):
        raise ServiceValidationError(f"{call.service}: 'name' contains control or invisible characters")
    if not name or len(name.encode("utf-16-le")) // 2 > MAP_NAME_MAX:
        raise ServiceValidationError(f"{call.service}: 'name' must be 1 to {MAP_NAME_MAX} characters")
    return name


async def _read(hass: HomeAssistant, call: ServiceCall, fn, *args):
    """Run a blocking robot read, surfacing failures as a readable error."""
    try:
        return await hass.async_add_executor_job(fn, *args)
    except Exception as exc:
        raise HomeAssistantError(f"{call.service}: could not read from the vacuum: {exc}") from exc


# Services that can wipe or rewrite what is on the robot (or send it anything at all): only
# admins may call them, like the write websocket commands. Automations run without a user and
# are allowed; a script runs as whoever started it, as with Home Assistant's own admin services.
ADMIN_SERVICES = frozenset({"send_raw", "restore_map_backup", "apply_map_setup", "save_map_setup",
                            "fetch_cloud_map_backups", "delete_preset", "remove_schedule",
                            "remove_matter_fabric", "rename_map", "copy_map", "delete_map", "set_map_lock",
                            "backup_map"})


def _admin_only(hass: HomeAssistant, handler):
    async def wrapped(call: ServiceCall):
        if call.context.user_id:
            user = await hass.auth.async_get_user(call.context.user_id)
            if user is None or not user.is_admin:
                raise Unauthorized(context=call.context)
        return await handler(call)
    return wrapped


def async_setup_services(hass: HomeAssistant) -> None:
    """Register the services once (safe to call per config entry)."""
    if hass.services.has_service(DOMAIN, SERVICES[0]):
        return

    async def handle_clean_rooms(call: ServiceCall) -> None:
        want = call.data.get("map_id")
        if want not in (None, ""):
            try:
                want = int(want)
            except (TypeError, ValueError):
                raise ServiceValidationError(f"{call.service}: 'map_id' must be a map number") from None
        else:
            want = None
        levels = _levels(call) or None
        # Every robot is checked before any is started, so a call for two robots does not
        # start one and then fail on the other.
        plans = []
        for coord in _coordinators(hass, call):
            _require_idle(call, coord)
            # map_id (sent by the card and panel with room_ids): the rooms were picked on that
            # map. The robot cleans its current map, so refuse if it has moved to another.
            if want is not None and coord.map_id != want:
                raise ServiceValidationError(
                    f"{call.service}: {coord.device_name} is now on another map (the rooms were picked on "
                    f"map {want}); refresh and pick the rooms again")
            plans.append((coord, *await _resolve(hass, call, coord, map_id=want)))
        for coord, room_ids, map_id in plans:
            await _send(hass, call, coord.client.clean_rooms, room_ids, map_id, True, levels)
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
                        "tapo_rv30.clean_rooms for a single run, or make a preset with per-room levels "
                        "(tapo_rv30.create_preset) and run it with tapo_rv30.run_preset.") from exc
                raise HomeAssistantError(f"{call.service}: vacuum rejected the command: {exc}") from exc
            await coord.async_request_refresh()

    async def handle_clean_zone(call: ServiceCall) -> None:
        coord = _one(hass, call)        # zones are in one map's coordinate frame
        _require_idle(call, coord)
        g = coord.data or {}
        lv = {"suction": _known(g.get("suction"), 3), "cistern": _known(g.get("cistern"), 0),
              "clean_number": 1, **_levels(call)}
        zones = call.data.get("zones")
        try:
            zones = [[int(v) for v in z] for z in zones]
            if not zones or any(len(z) != 4 for z in zones):
                raise ValueError
        except (TypeError, ValueError):
            raise ServiceValidationError(
                f"{call.service}: 'zones' must be a list of [x1, y1, x2, y2] rectangles in map mm, "
                "for example [[-500, -500, 500, 500]]") from None
        try:
            map_id, _ = await hass.async_add_executor_job(coord.client.get_map_info)
        except Exception as exc:
            raise HomeAssistantError(f"{call.service}: could not read maps from the vacuum: {exc}") from exc
        await _send(hass, call, coord.client.clean_zones, map_id, zones,
                    lv["suction"], lv["cistern"], lv["clean_number"])
        await coord.async_refresh_soon()

    async def handle_go_to(call: ServiceCall) -> None:
        """Drive to a point given in map mm (same frame as position_mm / clean_zone)."""
        coord = _one(hass, call)
        if coord.map_lock.locked():
            raise ServiceValidationError(f"{call.service}: {coord.device_name} is having its map written; try again shortly")
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
        # room_ids (the sidebar page sends them) name rooms exactly, unnamed or same-named ones too.
        if "rooms" in call.data or "room_ids" in call.data or "preset" in call.data:
            attr.pop("room_list", None); attr.pop("custom_rule_id", None)
            if call.data.get("preset") not in (None, ""):
                preset = coord.find_preset(call.data["preset"], await _preset_map(call, coord))
                if preset is None:
                    raise ServiceValidationError(f"{call.service}: no unique preset matching {call.data['preset']!r}"
                                                 "; name its map with map: if more than one map has it")
                attr.update({"clean_mode": 5, "custom_rule_id": preset["id"], "map_id": preset.get("map_id") or coord.map_id})
            elif call.data.get("rooms") or call.data.get("room_ids"):
                room_ids, map_id = await _resolve(hass, call, coord)
                attr.update({"clean_mode": 3, "room_list": room_ids, "map_id": map_id})
            else:
                attr.update({"clean_mode": 0, "map_id": coord.map_id})
        elif "clean_mode" not in attr:
            attr.update({"clean_mode": 0, "map_id": coord.map_id})
        attr.setdefault("suction", _known(g.get("suction"), 2))
        attr.setdefault("cistern", _known(g.get("cistern"), 0))
        attr.setdefault("clean_number", _known(g.get("clean_number"), 1))
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

    def _find_rule(call: ServiceCall, coord: TapoCoordinator, rules: list | None = None) -> dict:
        sid = str(call.data.get("schedule_id", "")).strip()
        if not sid:
            raise ServiceValidationError(f"{call.service}: 'schedule_id' is required (e.g. S1)")
        if rules is None:
            rules = (coord.settings.get("schedules") or {}).get("rule_list") or []
        rule = next((r for r in rules if str(r.get("id")) == sid), None)
        if rule is None:
            raise ServiceValidationError(f"{call.service}: no schedule {sid!r}; known: {[r.get('id') for r in rules]}")
        return rule

    async def handle_set_schedule(call: ServiceCall) -> None:
        coord = _one(hass, call)
        # editScheduleRule replaces the whole rule, built from a read of it: two edits at
        # once (or one against a stale poll) would each put back what the other changed.
        async with coord.schedule_lock:
            await _set_schedule(call, coord)

    async def _set_schedule(call: ServiceCall, coord: TapoCoordinator) -> None:
        fresh = await _read(hass, call, coord.client.get_schedules)
        rule = dict(_find_rule(call, coord, fresh))
        try:
            minutes = parse_hhmm(call.data["time"]) if "time" in call.data else rule.get("s_min", 0)
            mask = encode_weekdays(call.data["days"]) if "days" in call.data else rule.get("week_day", 0)
        except ValueError as exc:
            raise ServiceValidationError(f"{call.service}: {exc}") from exc
        once = rule.get("mode") == "once" and "days" not in call.data
        if not mask and not once:
            raise ServiceValidationError(f"{call.service}: 'days' must leave at least one day")
        enabled = call.data.get("enabled", rule.get("enable", True))
        if "time" in call.data or call.data.get("enabled"):
            _check_dnd(call, coord, minutes, enabled)
        attr = await _schedule_clean_attr(call, coord, rule.get("clean_attr") or {})
        once_date = None
        if once and rule.get("year"):
            import datetime as _dt
            once_date = _dt.date(int(rule["year"]), int(rule["month"]), int(rule["day"]))
        body = build_schedule_rule(minutes, 0 if once else mask, attr, enabled=enabled,
                                   once_date=once_date, rule_id=rule["id"])
        # editScheduleRule replaces the whole rule: keep what the app set that this call does
        # not change (the pre-start reminder and its lead time).
        for key in ("start_remind", "alarm_min"):
            if key in rule:
                body[key] = rule[key]
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

    async def handle_get_matter_setup_code(call: ServiceCall) -> ServiceResponse:
        """The robot's Matter pairing code and QR payload, for admins only: never in entity
        state, where every user and the recorder would see it."""
        coord = _one(hass, call)
        if not coord.has("matter"):
            raise ServiceValidationError(f"{call.service}: {coord.device_name} has no Matter support")
        info = coord.settings.get("matter_setup")
        if not isinstance(info, dict) or not info.get("setup_code"):
            try:
                info = await hass.async_add_executor_job(coord.client.send, "getMatterSetupInfo")
                info = (info or {}).get("result") or {}
            except Exception as exc:
                raise HomeAssistantError(f"{call.service}: could not read the setup code: {exc}") from exc
        return {"setup_code": info.get("setup_code"), "setup_payload": info.get("setup_payload")}

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
            await hass.async_add_executor_job(coord.client.run_schedule, str(sid))
        except ValueError as exc:
            raise ServiceValidationError(f"{call.service}: {exc}") from exc
        except RobotBusy as exc:
            raise ServiceValidationError(f"{call.service}: the vacuum {exc}") from exc
        except Exception as exc:
            raise HomeAssistantError(f"{call.service}: vacuum rejected the command: {exc}") from exc
        await coord.async_refresh_soon()

    async def handle_send_raw(call: ServiceCall) -> ServiceResponse:
        coord = _one(hass, call)
        method = str(call.data.get("method", "")).strip()
        if not method:
            raise ServiceValidationError(f"{call.service}: 'method' is required")
        params = call.data.get("params") or {}
        if isinstance(params, str):     # typed as JSON text, as in the action form's example
            try:
                params = json.loads(params)
            except ValueError:
                pass
        if not isinstance(params, dict):
            raise ServiceValidationError(f"{call.service}: 'params' must be a mapping")
        methods = _raw_methods(method, params)
        blocked = [m for m in methods if _is_blocked(m)]
        if blocked:
            if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", blocked[0]):
                raise ServiceValidationError(
                    f"{call.service}: {blocked[0]!r} is not a plain method name (letters, digits and _ only)")
            raise ServiceValidationError(
                f"{call.service}: '{blocked[0]}' is an onboarding, system or factory call and is blocked. "
                "Calls like this have wiped this robot's maps; use the Tapo app for them.")
        # Probing a robot mid-run is how the author lost a map set and the robot's
        # clean history (see README, "Protocol notes"). Known-safe status reads are
        # allowed; anything else waits for the robot to be idle unless forced.
        unsafe = [m for m in methods if m not in SAFE_WHILE_BUSY and m != "multipleRequest"]
        if coord.map_busy and unsafe and not call.data.get("force"):
            raise ServiceValidationError(
                f"{call.service}: {coord.device_name} is {coord.map_busy}; '{unsafe[0]}' is not on the "
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
        preset = coord.find_preset(ref, await _preset_map(call, coord))
        if preset is None:
            names = [p["name"] for p in coord.presets]
            raise ServiceValidationError(
                f"{call.service}: no unique preset matching '{ref}'. Available: {names}")
        await _send(hass, call, coord.client.run_preset, preset["id"], preset["map_id"],
                    preset.get("clean_order", True))
        await coord.async_refresh_soon()

    # ---- presets (the robot's own "customisation rules", as the Tapo app edits them) ----
    def _preset_rooms(coord: TapoCoordinator, map_id: int, room_ids: list[int], lv: dict,
                      keep: dict[int, dict] | None = None) -> list[dict]:
        """Preset room items in cleaning order. Levels: the call's, else the room's existing
        ones in this preset, else the robot's current settings. Carpet handling is copied from
        the map's room, as the app does. Blocking."""
        g = coord.data or {}
        data = coord.client.get_map_data(map_id)
        carpet = {a["id"]: a.get("carpet_strategy") for a in data.get("area_list", []) if a.get("type") == "room"}
        out = []
        for rid in room_ids:
            old = (keep or {}).get(rid, {})
            out.append({"id": rid,
                        "suction": lv.get("suction", old.get("suction", _known(g.get("suction"), 2))),
                        "cistern": lv.get("cistern", old.get("cistern", _known(g.get("cistern"), 1))),
                        "clean_number": lv.get("clean_number", old.get("clean_number", 1)),
                        "carpet_strategy": old.get("carpet_strategy", carpet.get(rid))})
        return out

    async def _preset_map(call: ServiceCall, coord: TapoCoordinator) -> int | None:
        """The map a preset call names (map: name or id), else None for any map."""
        ref = call.data.get("map")
        if ref in (None, ""):
            return None
        return _match_map(call, await _read(hass, call, coord.map_names), ref, exact=True)

    async def _preset_for(call: ServiceCall, coord: TapoCoordinator) -> dict:
        ref = call.data.get("preset")
        if ref in (None, ""):
            raise ServiceValidationError(f"{call.service}: 'preset' (name or id) is required")
        preset = coord.find_preset(ref, await _preset_map(call, coord))
        if preset is None:
            raise ServiceValidationError(
                f"{call.service}: no unique preset matching '{ref}'. Available: {[p['name'] for p in coord.presets]}")
        return preset

    async def _write_preset(call: ServiceCall, coord: TapoCoordinator, body: dict) -> None:
        try:
            code = await hass.async_add_executor_job(coord.client.add_preset, body)
        except Exception as exc:
            raise HomeAssistantError(f"{call.service}: vacuum rejected the preset: {exc}") from exc
        if code:
            raise HomeAssistantError(f"{call.service}: vacuum rejected the preset (error {code})")

    async def handle_create_preset(call: ServiceCall) -> ServiceResponse:
        from .mapdata import fold, preset_body
        coord = _one(hass, call)
        name = str(call.data.get("name", "")).strip()
        if not name:
            raise ServiceValidationError(f"{call.service}: 'name' is required")
        room_ids, map_id = await _resolve(hass, call, coord)
        if any(fold(p["name"]) == fold(name) and p["map_id"] == map_id for p in coord.presets):
            raise ServiceValidationError(f"{call.service}: a preset called '{name}' already exists on that map")
        rooms = await _read(hass, call, _preset_rooms, coord, map_id, room_ids, _levels(call))
        await _write_preset(call, coord, preset_body(name, map_id, rooms, call.data.get("clean_order", True)))
        await coord.async_settings_changed()
        made = next((p for p in coord.presets if fold(p["name"]) == fold(name) and p["map_id"] == map_id), None)
        return {"preset_id": made and made["id"], "name": name, "map_id": map_id, "rooms": made and made["rooms"]}

    async def handle_update_preset(call: ServiceCall) -> ServiceResponse:
        from .mapdata import b64name, preset_body
        coord = _one(hass, call)
        preset = await _preset_for(call, coord)
        map_id, rule_id = preset["map_id"], preset["id"]
        try:
            detail = await hass.async_add_executor_job(coord.client.get_preset_detail, map_id, rule_id)
        except Exception as exc:
            raise HomeAssistantError(f"{call.service}: could not read the preset: {exc}") from exc
        keep = {a["id"]: a for a in detail.get("area_list") or [] if a.get("type") == "room"}
        if "rooms" in call.data or "room_ids" in call.data:
            # Rooms are matched on the preset's own map (by id: it may be unnamed or share a
            # name), which need not be the active one.
            room_ids, rmap = await _resolve(hass, call, coord, map_id=map_id)
            if rmap != map_id:
                raise ServiceValidationError(f"{call.service}: the rooms must be on the preset's own map")
        else:
            room_ids = list(keep)
        rooms = await _read(hass, call, _preset_rooms, coord, map_id, room_ids, _levels(call), keep)
        name = str(call.data.get("name") or b64name(detail.get("rule_name", ""))).strip()
        order = call.data.get("clean_order", detail.get("clean_order", True))
        await _write_preset(call, coord, preset_body(name, map_id, rooms, order, rule_id=rule_id))
        await coord.async_settings_changed()
        now = coord.find_preset(rule_id, map_id)
        return {"preset_id": rule_id, "name": now and now["name"], "rooms": now and now["room_settings"]}

    async def handle_delete_preset(call: ServiceCall) -> ServiceResponse:
        coord = _one(hass, call)
        if not call.data.get("confirm"):
            raise ServiceValidationError(f"{call.service}: this deletes the preset; set confirm: true")
        preset = await _preset_for(call, coord)
        try:
            code = await hass.async_add_executor_job(coord.client.delete_preset, preset["map_id"], preset["id"])
        except Exception as exc:
            raise HomeAssistantError(f"{call.service}: vacuum rejected the delete: {exc}") from exc
        if code:
            raise HomeAssistantError(f"{call.service}: vacuum rejected the delete (error {code})")
        await coord.async_settings_changed()
        return {"deleted": preset["name"], "preset_id": preset["id"],
                "remaining": [p["name"] for p in coord.presets]}

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
        await _send(hass, call, coord.client.set_current_map, _match_map(call, names, ref))
        await coord.async_request_map_refresh()

    async def handle_set_map_rotation(call: ServiceCall) -> ServiceResponse:
        """Turn a map's display (clockwise), stored on the robot as in the app. Display only."""
        coord = _one(hass, call)
        value = call.data.get("rotation")
        # Exactly one of the four (90.7 or "90 " are not quietly taken as 90).
        if isinstance(value, bool) or str(value) not in ("0", "90", "180", "270"):
            raise ServiceValidationError(f"{call.service}: 'rotation' must be 0, 90, 180 or 270")
        rotation = int(str(value))
        names = await _read(hass, call, coord.map_names)
        map_id = _match_map(call, names, call.data.get("map", coord.map_id), exact=True)
        try:
            await coord.async_set_map_rotation(map_id, rotation)
        except ValueError as exc:
            raise ServiceValidationError(f"{call.service}: {coord.device_name}: {exc}") from exc
        except Exception as exc:
            raise HomeAssistantError(f"{call.service}: the robot refused the rotation: {exc}") from exc
        return {"map_id": map_id, "name": names.get(map_id), "rotation": rotation}

    async def handle_set_map_lock(call: ServiceCall) -> ServiceResponse:
        """Lock or unlock a map, as in the app: locked, later cleans no longer update it."""
        coord = _one(hass, call)
        locked = call.data.get("locked")
        if not isinstance(locked, bool):
            raise ServiceValidationError(f"{call.service}: 'locked' must be true or false")
        names = await _read(hass, call, coord.map_names)
        map_id = _match_map(call, names, call.data.get("map", coord.map_id), exact=True)
        try:
            await coord.async_set_map_locked(map_id, locked)
        except ValueError as exc:
            raise ServiceValidationError(f"{call.service}: {coord.device_name}: {exc}") from exc
        except Exception as exc:
            raise HomeAssistantError(f"{call.service}: the robot refused the change: {exc}") from exc
        return {"map_id": map_id, "name": names.get(map_id), "locked": locked}

    async def handle_rename_map(call: ServiceCall) -> ServiceResponse:
        """Rename a saved map. Everything in this integration (schedules, presets, room freshness,
        the planner, area mappings, setups, history) follows maps by id, so only references by
        the old name (automations passing map: <name>) need updating."""
        coord = _one(hass, call)
        _require_idle(call, coord)
        new = _map_name(call, call.data.get("name"))
        if coord.map_lock.locked():
            raise ServiceValidationError(f"{call.service}: {coord.device_name} is having its map written; "
                                         "try again shortly")
        async with coord.map_lock:
            # Names and saved state from one fresh read: the cached map list can lag a new map.
            _, map_list = await _read(hass, call, coord.client.get_map_info)
            names = {m["map_id"]: b64name(m.get("map_name", "")) for m in map_list}
            map_id = _match_map(call, names, call.data.get("map"), exact=True)
            old = names.get(map_id) or ""
            if next(m for m in map_list if m["map_id"] == map_id).get("is_saved") is not True:
                raise ServiceValidationError(f"{call.service}: that map is not saved yet; save it in the "
                                             "Tapo app first")
            if new == old:
                raise ServiceValidationError(f"{call.service}: the map is already called '{old}'")
            from .mapdata import fold
            # Another map's name may not equal, contain or sit inside the new one: references by
            # name match exactly first, then by part, so either would retarget them silently.
            clash = [n for mid, n in names.items() if mid != map_id and n
                     and (fold(n) in fold(new) or fold(new) in fold(n))]
            if clash:
                raise ServiceValidationError(f"{call.service}: '{new}' is too close to another map's name "
                                             f"'{clash[0]}'; references by name could pick the wrong map")
            await _send(hass, call, coord.client.rename_map, map_id, new)
            try:
                after = await _read(hass, call, coord.map_names)
            finally:
                await coord.async_request_map_refresh()
        if after.get(map_id) != new:
            raise HomeAssistantError(f"{call.service}: the robot accepted the rename but still reports "
                                     f"'{after.get(map_id)}'")
        return {"map_id": map_id, "old_name": old, "name": new}

    async def handle_fetch_cloud_map_backups(call: ServiceCall) -> ServiceResponse:
        import uuid

        from homeassistant.const import CONF_PASSWORD, CONF_USERNAME

        from .cloud import CloudError, fetch_backups
        coord = _one(hass, call)
        if coord.entry is None:
            raise ServiceValidationError(f"{call.service}: no config entry")
        folder = setup_apply.backups_folder(hass, coord)
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
        names = await _read(hass, call, coord.map_names)
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

    from . import setup_apply

    def _robot_state(coord: TapoCoordinator, map_id: int) -> tuple[dict, list, list]:
        return setup_apply.robot_state(coord.client, map_id)

    def _find_snapshot(coord: TapoCoordinator, map_id: int | None, ref) -> dict | None:
        return setup_apply.find_snapshot(setup_apply.snapshot_folders(hass, coord), map_id, ref)

    async def handle_save_map_setup(call: ServiceCall) -> ServiceResponse:
        import json
        import os
        import time

        from . import mapsnapshot
        coord = _one(hass, call)
        map_id, names = await _setup_map_id(call, coord)
        data, presets, schedules = await _read(hass, call, _robot_state, coord, map_id)
        snap = mapsnapshot.build(map_id, names.get(map_id), data.get("area_list", []),
                                 data.get("furniture_list", []), presets, schedules,
                                 time.strftime("%Y-%m-%dT%H:%M:%S"))
        folder = setup_apply.snapshots_folder(hass, coord)

        def _write() -> bool:
            """Write the snapshot; the latest copy is only replaced by a degraded one
            (rooms missing or unnamed, as after a lost map) when forced."""
            os.makedirs(os.path.join(folder, "history"), exist_ok=True)
            stamp = time.strftime("%Y%m%d-%H%M%S")
            latest = os.path.join(folder, f"{map_id}.json")
            old = None
            for path in (latest, os.path.join(os.path.dirname(folder), f"{map_id}.json")):
                if old is None:
                    try:
                        with open(path) as fh:
                            old = json.load(fh)
                    except (OSError, ValueError):
                        pass
            keep_old = mapsnapshot.is_degraded(old, snap) and not call.data.get("force")
            paths = [os.path.join(folder, "history", f"{map_id}_{stamp}.json")]
            if not keep_old:
                paths.append(latest)
            for path in paths:
                setup_apply.write_json(path, snap)
            return keep_old

        kept = await hass.async_add_executor_job(_write)
        if kept:
            raise ServiceValidationError(
                f"{call.service}: map {names.get(map_id) or map_id} looks degraded (rooms missing or "
                "unnamed), so the saved setup was kept and this one only went to history. "
                "Pass force: true to replace it anyway.")
        return {"map_id": map_id, "map_name": names.get(map_id), "saved": snap["counts"],
                "furniture": len(snap["furniture"]), "presets": len(snap["presets"]),
                "schedules": len(snap["schedules"]), "file": os.path.relpath(os.path.join(folder, f"{map_id}.json"), hass.config.path(DOMAIN))}

    async def handle_apply_map_setup(call: ServiceCall) -> ServiceResponse:
        coord = _one(hass, call)
        dry_run = bool(call.data.get("dry_run"))
        if not dry_run and not call.data.get("confirm"):
            raise ServiceValidationError(
                f"{call.service}: this writes rooms, zones, furniture, presets and schedules; "
                "set confirm: true (or dry_run: true to see what it would do)")
        if coord.map_busy and not dry_run:
            raise ServiceValidationError(f"{call.service}: {coord.device_name} must be docked and idle")
        map_id, names = await _setup_map_id(call, coord)
        src = call.data.get("source_map")
        snap = await hass.async_add_executor_job(_find_snapshot, coord, map_id, src)
        if snap is None:
            where = f"matching source_map '{src}'" if src else f"for map {map_id}"
            raise ServiceValidationError(f"{call.service}: no saved setup {where}; run save_map_setup first")
        try:
            result = await setup_apply.apply_setup(hass, coord, map_id, snap, dry_run)
        except setup_apply.MapBusy as exc:
            raise ServiceValidationError(f"{call.service}: {exc}") from exc
        except setup_apply.ApplyError as exc:
            raise HomeAssistantError(f"{call.service}: {exc}") from exc
        except Exception as exc:
            raise HomeAssistantError(f"{call.service}: could not read the map from the vacuum: {exc}") from exc
        result["map_name"] = names.get(map_id)
        return result

    async def _with_progress(call: ServiceCall, job: str, run) -> ServiceResponse:
        """Run a long map job, telling the page when it ends (done, or failed with the reason)."""
        coord = _one(hass, call)
        try:
            result = await run(call)
        except ServiceValidationError:
            raise       # refused before any work: another job's progress bar must not end
        except Exception as exc:
            coord.map_job(job, "Failed", 100, done=True, error=str(exc))
            raise
        if result.get("finishing"):
            coord.map_job(job, "On the robot; finishing in the background", 100, done=True)
            return result
        ok = (bool(result.get("applied")) and not result.get("note")
              and result.get("restored_map_saved") is not False)
        coord.map_job(job, "Done" if ok else "Finished with a problem", 100, done=True,
                      error=None if ok else (result.get("note") or "the robot did not confirm it"))
        return result

    async def handle_restore_map_backup(call: ServiceCall) -> ServiceResponse:
        return await _with_progress(call, "restore", _restore_map_backup)

    async def handle_copy_map(call: ServiceCall) -> ServiceResponse:
        return await _with_progress(call, "copy", _copy_map)

    async def handle_backup_map(call: ServiceCall) -> ServiceResponse:
        return await _with_progress(call, "backup", _backup_map)

    async def _restore_map_backup(call: ServiceCall) -> ServiceResponse:
        """Restore a map backup to the robot. By default HA serves the backup it already holds
        on a short-lived LAN URL and the robot fetches and applies it - a fully local restore,
        no cloud. use_cloud_url hands the robot the backup's own TP-Link URL instead, for when
        the robot cannot reach HA on the LAN. new_name restores it as a new map beside the
        original (a copy) instead of over it."""
        import os

        from .mapdata import fold
        coord = _one(hass, call)
        if not call.data.get("confirm"):
            raise ServiceValidationError(f"{call.service}: this overwrites a map on the robot; set confirm: true")
        names = await _read(hass, call, coord.map_names)
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
                snap = await hass.async_add_executor_job(_find_snapshot, coord, None, ref)
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
        new_name = call.data.get("new_name")
        if new_name not in (None, "") and call.data.get("use_cloud_url"):
            raise ServiceValidationError(f"{call.service}: new_name restores from the copy Home Assistant "
                                         "holds; it cannot be combined with use_cloud_url")
        return await _restore(call, coord, names, backup_id, snap_name, fname,
                              _new_map_name(call, names, new_name) if new_name not in (None, "") else None)

    def _new_map_name(call: ServiceCall, names: dict[int, str], value) -> str:
        """The name for a map restored or copied as new: valid, unused, and room for it."""
        from .mapcopy import MAX_MAPS
        from .mapdata import fold
        name = _map_name(call, value)
        if any(fold(n) == fold(name) for n in names.values()):
            raise ServiceValidationError(f"{call.service}: the robot already has a map called '{name}'")
        if len(names) >= MAX_MAPS:
            raise ServiceValidationError(f"{call.service}: the robot holds at most {MAX_MAPS} maps and has "
                                         f"{len(names)}; delete one first (delete_map, or the Tapo app)")
        return name

    async def _restore(call: ServiceCall, coord: TapoCoordinator, names: dict[int, str], backup_id: int,
                       snap_name: str | None, fname, new_name: str | None, job: str = "restore",
                       span: tuple[float, float] = (0, 100)) -> dict:
        """mapRecovery with everything around it. Over the backup's own map when the robot has
        it; otherwise onto a carrier (the current map), whose rooms and furniture the robot
        overwrites with the backup's and which are put back here. With new_name the backup is
        given a fresh map id first, so it lands as a new map, a copy, which is saved under
        new_name and given the backup's room names and furniture."""
        import asyncio
        import hashlib
        import os
        import secrets
        import time

        from homeassistant.components.network import async_get_source_ip

        from . import mapbackup, mapcopy
        from .map_restore import async_setup_map_restore
        if coord.map_busy:
            raise ServiceValidationError(f"{call.service}: {coord.device_name} must be docked and idle")
        if coord.map_lock.locked():
            raise ServiceValidationError(f"{call.service}: a map write is running; try again shortly")
        folders = setup_apply.backup_folders(hass, coord)
        label = names.get(backup_id) or snap_name
        src_id = backup_id      # the map the backup is of (a copy gives it a fresh id below)

        def _pick() -> str | None:
            # This robot's own backups first, then the shared folder older versions used.
            if fname:
                return backupstore.locate(folders, os.path.basename(str(fname)))
            # cloud_<map_id>_<timestamp>.bin only - never the _snapshot preview image.
            pat = re.compile(rf"^cloud_{backup_id}_\d+\.bin$")
            for folder in folders:
                try:
                    cands = sorted(f for f in os.listdir(folder) if pat.match(f))
                except OSError:      # no backups fetched yet
                    continue
                if cands:
                    return os.path.join(folder, cands[-1])
            return None

        # Default: serve the backup from HA on the LAN and let the robot fetch it directly - a
        # fully local restore, no cloud. The robot's HTTP client needs a clean Content-Length
        # response, so the URL must be HA's direct LAN address: a reverse proxy in front of HA
        # that serves the body chunked makes the robot's download stall near the end and fail.
        # base_url overrides the auto-derived address; use_cloud_url hands the robot the backup's
        # own TP-Link URL instead, for when it cannot reach HA on the LAN.
        store = None
        token = None
        src = "local"
        tail = None
        tmp = None
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
                    f"{call.service}: no backup file for map {backup_id} in {folders[0]}; "
                    "run fetch_cloud_map_backups first, or pass file:")
            data = await hass.async_add_executor_job(lambda: open(path, "rb").read())  # noqa: SIM115
            try:
                # The tail (room names, furniture) goes onto the restored map when it lands beside a
                # carrier; the robot checks the file itself, so only a copy needs it readable here.
                tail = mapbackup.parse_bkmap(data)["tail"] if new_name or backup_id not in names else None
            except ValueError:
                tail = None
            try:
                if new_name:
                    # A copy: the same backup under a fresh id, so it lands beside the original.
                    backup_id = mapcopy.new_map_id(names, time.time())
                    data = mapbackup.reid_bkmap(data, backup_id)
            except ValueError as exc:
                raise ServiceValidationError(f"{call.service}: {os.path.basename(path)}: {exc}") from exc
            if new_name:
                tmp = os.path.join(os.path.dirname(path), f".copy_{backup_id}.bkmap")   # written below
            md5 = hashlib.md5(data).hexdigest()
            base = call.data.get("base_url")
            if base:
                base = str(base).rstrip("/")
            else:
                ip = await async_get_source_ip(hass, coord.client.host)
                scheme = "https" if hass.http.ssl_certificate else "http"
                base = f"{scheme}://{ip}:{hass.http.server_port}"
            store = async_setup_map_restore(hass)
            token = secrets.token_urlsafe(24)
            store[token] = tmp or path
            url = f"{base}/api/tapo_rv30/bkmap/{token}"
        process: dict = {}
        code = None
        tidy: dict | None = None
        carry_why = None
        landed = None
        carrier = False
        map_id = backup_id
        keep_url = False
        try:
            if tmp:
                await hass.async_add_executor_job(setup_apply.write_bytes, tmp, data)
            async with coord.map_lock:
                if (old := coord.restore_unfinished()) is not None:
                    raise ServiceValidationError(
                        f"{call.service}: an earlier restore onto map {old['carrier']} is still being finished; "
                        "try again in a few minutes")
                # Which map takes the restore, from a fresh read: the backup's own map, or else a
                # saved map to carry it (the current one if it is saved; never a map still unsaved,
                # which the restored one could replace).
                current, map_list = await _read(hass, call, coord.client.get_map_info)
                saved = [m.get("map_id") for m in map_list if m.get("is_saved") is not False]
                if not new_name and backup_id in {m.get("map_id") for m in map_list}:
                    map_id = backup_id
                elif current is not None and current not in saved and any(m.get("map_id") == current for m in map_list):
                    raise ServiceValidationError(
                        f"{call.service}: the current map is not saved yet, and the restored map could replace it; "
                        "save it in the Tapo app or switch to a saved map first")
                elif saved:
                    map_id, carrier = (current if current in saved else saved[0]), True
                else:
                    raise ServiceValidationError(
                        f"{call.service}: the robot has no saved map to take the restore. Make any map in the "
                        "Tapo app (a quick mapping run is enough), then run this again: the backup comes back "
                        "under its own map id and that throwaway map can be deleted")
                try:
                    baseline = await hass.async_add_executor_job(coord.client.get_map_br_process)
                except Exception as exc:
                    raise HomeAssistantError(f"{call.service}: could not read the robot's restore progress: {exc}") from exc
                # A new map takes the source map's presets (and its schedules, switched off, if asked).
                carry, carry_why = ((await _carry_from(coord, src_id, any(m.get("map_id") == src_id for m in map_list),
                                                       _flag(call.data.get("copy_schedules"))))
                                    if new_name else (None, None))
                if carrier:
                    # The robot writes the backup's room names, colours and furniture onto the carrier:
                    # keep the carrier's own, recorded before the robot is asked so that a Home
                    # Assistant restart or a slow restore still puts them back (on a later poll).
                    before = mapcopy.layers(await _read(hass, call, coord.client.get_map_data, map_id))
                    coord.expect_restore(backup_id, new_name or label, map_id, before,
                                         mapcopy.tail_subset(tail), copy=bool(new_name), carry=carry)
                pend = coord.pending_restore if carrier else None
                lo, hi = span
                applying = "Restoring the map on the robot"
                coord.map_job(job, applying, lo)
                try:
                    code = await hass.async_add_executor_job(coord.client.recover_map, map_id, md5, url)
                except RuntimeError as exc:
                    if not str(exc).startswith("Device error"):
                        # No answer: the robot may still have taken it. Keep the pending restore,
                        # so the carrier is put back once the map lands (or after a while anyway).
                        keep_url = True
                        raise HomeAssistantError(
                            f"{call.service}: {exc}. If the robot took the restore, Home Assistant puts "
                            f"\"{names.get(map_id)}\" back as it was once it lands") from exc
                    if pend is not None:
                        coord._drop_restore(pend)
                    raise HomeAssistantError(f"{call.service}: {exc}") from exc
                if code != 0:
                    if pend is not None:
                        coord._drop_restore(pend)
                else:
                    process = await _wait_br(coord, 2, baseline, progress=lambda pc: coord.map_job(
                        job, applying, lo + (hi - lo) * 0.85 * pc / 100))
                    coord.map_job(job, "Saving it and putting the maps back as they were", lo + (hi - lo) * 0.9)
                    if carrier and _opt_int(process.get("status")) not in (3, 13):
                        # The map id was not on the robot before, so seeing it now means it landed
                        # (the job status can look unchanged when an earlier restore left the same).
                        try:
                            _, now_list = await hass.async_add_executor_job(coord.client.get_map_info)
                            if any(m.get("map_id") == backup_id for m in now_list):
                                process = {**process, "type": 2, "status": 3}
                        except Exception:
                            pass
                status = _opt_int(process.get("status"))
                keep_url = code == 0 and status in (None, 2)
                # The restore can take minutes; if the entry was reloaded meanwhile, carry on with
                # its new coordinator (the old one's client is closed).
                live = hass.data.get(DOMAIN, {}).get(coord.entry.entry_id, coord) if coord.entry else coord
                if carrier and code == 0 and status in (3, 13) and live is coord:
                    # Done (or failed, when the carrier may still have been written to): tidy up now.
                    # (After a reload the new coordinator's own poll does it, under its own lock.)
                    lp = live.pending_restore
                    if lp and lp.get("map_id") == backup_id and not lp.get("tidied", True):
                        if status == 13:
                            lp["failed"] = True     # the map will not land: just put the carrier back
                        # The robot can still be busy with it for a little while (it then refuses):
                        # give it a minute before leaving the rest to the next polls.
                        for _ in range(20):
                            tidy = await live.async_tidy_restore(lp)
                            if tidy is not None or live.pending_restore is not lp:
                                break
                            await asyncio.sleep(3)
                if status == 3:
                    try:
                        _, map_list = await hass.async_add_executor_job(live.client.get_map_info)
                        landed = next((m for m in map_list if m.get("map_id") == backup_id), None)
                    except Exception:  # the restore itself already succeeded
                        landed = None
                coord = live
        finally:
            # Whatever happened, read the maps again soon: a restore that landed (or may yet) is
            # finished by the poll that sees it.
            await coord.async_request_map_refresh()
            if store is not None and token is not None:
                if keep_url:
                    # Still applying (or unknown): keep serving the backup for a while longer.
                    hass.loop.call_later(600, store.pop, token, None)
                else:
                    await asyncio.sleep(3)  # let a slow fetch finish before the URL stops serving
                    store.pop(token, None)
            if tmp:
                def _rm() -> None:
                    try:
                        os.remove(tmp)
                    except OSError:
                        pass
                hass.loop.call_later(600 if keep_url else 5, lambda: hass.async_add_executor_job(_rm))
        status = _opt_int(process.get("status"))
        if tidy is None and new_name and code == 0 and (coord.pending_restore or {}).get("map_id") != backup_id:
            # Letting go of the map lock above lets a poll's background tidy finish the copy (save it,
            # its presets, the switch back) before this answers: report what that did, not the
            # earlier read of a map not saved yet.
            tidy = coord.last_tidy(backup_id)
        saved = bool(tidy and tidy["saved"]) or (bool(landed) and landed.get("is_saved", True) is not False)
        carrier_name = names.get(map_id)
        # The robot reports status 3 when the map is applied, 13 on failure, 2 while still working.
        note = (f"the robot refused the restore (error {code})" if code not in (0, None)
                else "restore failed on the robot (status 13); if the backup is served through a reverse "
                "proxy, set base_url to HA's direct LAN address" if status == 13
                else "still applying when polling ended" if status in (2, None) else None)
        if tidy and tidy["errors"]:
            note = ((note + "; ") if note else "") + "after the restore: " + "; ".join(tidy["errors"])
        if carry_why:
            note = ((note + "; ") if note else "") + carry_why
        put_back = bool(tidy and tidy["carrier_ok"])
        next_steps = None
        finishing = False
        if code not in (0, None):
            pass
        elif status in (2, None) and carrier:
            # Polling ended before the robot finished; it will most likely land, and the next polls
            # put the carrier back (and save a named map) once it does.
            next_steps = (f"The robot is still applying the backup. Once it lands, Home Assistant puts \"{carrier_name}\" "
                          "back as it was" + (f" and saves the new map as \"{new_name}\"." if new_name else
                                              (f" and saves it as \"{label}\"." if label else
                                               "; then save the restored map in the Tapo app.")))
        elif status == 3 and carrier and coord.restore_unfinished():
            finishing = True
            next_steps = ("The map is on the robot; Home Assistant is finishing it in the background"
                          + (f" (saving it as \"{new_name or label}\" and" if (new_name or label) else " (")
                          + f" putting \"{carrier_name}\" back as it was) and lets you know when it is done.")
        elif status == 3 and new_name:
            if saved:
                next_steps = (f"Restored as a new map, \"{new_name}\", with the backup's room names and furniture"
                              + mapcopy.carried_text((tidy or {}).get("carried")) + "."
                              + (f" \"{carrier_name}\" was put back as it was" if put_back else "")
                              + (" and is the current map again." if put_back and tidy and tidy["switched"]
                                 else "." if put_back else ""))
            else:
                next_steps = (f"The copy came back as an unsaved map (id {backup_id}) but saving it failed; save it "
                              "in the Tapo app.")
        elif status == 3 and landed and carrier:
            # The map had been deleted: finished automatically once it is saved.
            next_steps = (("The map came back as a new, unsaved map. Save it in the Tapo app"
                           + (f" as \"{label}\"" if label else "") + ". Home Assistant then puts back its room "
                           "names, no-go zones, furniture, presets and schedules by itself and lets you know.")
                          if not saved else
                          "Home Assistant is putting back its room names, zones, furniture, presets and schedules.")
        elif status == 3 and landed and not saved:
            next_steps = (f"The map came back as a new, unsaved map (id {backup_id}). Save it in the Tapo app "
                          "(keep the name), then run apply_map_setup on it to put back room names, no-go zones, "
                          "furniture, presets and schedules.")
        elif status == 3:
            next_steps = ("Run apply_map_setup on this map (dry_run: true first to preview) to put back anything "
                          "the backup does not carry: room names, zones, furniture, presets, schedules.")
        return {"map_id": map_id, "map_name": carrier_name, "backup_map_id": backup_id,
                "backup_map_name": new_name or label, "carrier": carrier, "as_new": bool(new_name),
                "restored_map_saved": saved if status == 3 else None,
                "carrier_repaired": tidy["carrier"] if put_back else None,
                "carried": tidy.get("carried") if tidy else None,
                "source": src, "md5": md5, "url": url, "error_code": code, "process": process,
                "applied": status == 3, "finishing": finishing, "note": note, "next_steps": next_steps}

    async def _carry_from(coord: TapoCoordinator, src_id: int, on_robot: bool,
                          with_schedules: bool) -> tuple[dict | None, str | None]:
        """What a new map made from map src_id takes with it (mapsnapshot.carry_setup): read from the
        robot while it has that map, else from the map's saved setup. With None, why not."""
        from . import mapsnapshot
        try:
            if on_robot:
                _, presets, schedules = await hass.async_add_executor_job(setup_apply.robot_state, coord.client, src_id)
            else:
                snap = await hass.async_add_executor_job(
                    setup_apply.find_snapshot, setup_apply.snapshot_folders(hass, coord), src_id, None)
                if snap is None:
                    return None, "no saved setup for that map, so no presets came with it"
                presets, schedules = snap.get("presets"), snap.get("schedules")
        except Exception as exc:     # the copy itself can still go ahead without them
            _LOGGER.warning("%s: could not read the presets of map %s to copy them: %s", coord.device_name, src_id, exc)
            return None, f"could not read the map's presets to copy them ({exc})"
        return mapsnapshot.carry_setup(presets, schedules, src_id, with_schedules), None

    async def _wait_br(coord: TapoCoordinator, kind: int, baseline: dict, src: int | None = None,
                       tries: int = 90, progress=None) -> dict:
        """Poll getMapBRProcess until a job of this kind (1 backup, 2 recovery) has finished
        (status 3) or failed (13). A finished job of the same kind still shown from before the
        request (baseline) does not count until something else has been read; a backup that has
        run and been cleared back to all zeros counts as finished. {} if it never got there."""
        import asyncio
        stale = dict(baseline or {})
        seen = misses = 0
        last: dict = {}
        for _ in range(tries):
            await asyncio.sleep(2)
            try:
                p = await hass.async_add_executor_job(coord.client.get_map_br_process)
                misses = 0
            except Exception as exc:
                # The robot often stops answering while it unpacks a backup: missed reads are
                # not a failed job, so keep asking (within tries).
                misses += 1
                _LOGGER.debug("getMapBRProcess failed (%s), %d in a row", exc, misses)
                continue
            t, st = _opt_int(p.get("type")), _opt_int(p.get("status"))
            if p == stale:
                continue
            stale = {}
            if t == kind and (src is None or _opt_int(p.get("map_id")) == src):
                seen += 1
                last = p
                if progress is not None:
                    progress(max(0, min(100, _opt_int(p.get("process")) or 0)))
                if st in (3, 13):
                    return p
            elif seen and t == 0 and st == 0 and kind == 1:
                return {**last, "status": 3}
        return last


    async def _copy_map(call: ServiceCall) -> ServiceResponse:
        """Copy a map to a new map: back it up to the TP-Link cloud, download that backup and
        restore it under a fresh map id with the given name. The original is not written to."""
        coord = _one(hass, call)
        if coord.entry is None:
            raise ServiceValidationError(f"{call.service}: no config entry")
        names = await _read(hass, call, coord.map_names)
        ref = call.data.get("map")
        src = _match_map(call, names, ref, exact=True) if ref not in (None, "") else coord.map_id
        name = _new_map_name(call, names, call.data.get("name"))
        newest = await _backup_fetch(call, coord, names, src, "copy", 40)
        # 3. Restore it as a new map.
        result = await _restore(call, coord, names, src, None, newest["file"], name, job="copy", span=(50, 100))
        result["copied_from"] = {"map_id": src, "map_name": names[src], "backup": newest["file"]}
        return result

    async def _backup_map(call: ServiceCall) -> ServiceResponse:
        """Back a map up now and keep the backup in Home Assistant: the robot writes it to the
        TP-Link cloud (the only place it sends one), and it is downloaded straight away."""
        coord = _one(hass, call)
        if coord.entry is None:
            raise ServiceValidationError(f"{call.service}: no config entry")
        names = await _read(hass, call, coord.map_names)
        ref = call.data.get("map")
        src = _match_map(call, names, ref, exact=True) if ref not in (None, "") else coord.map_id
        newest = await _backup_fetch(call, coord, names, src, "backup", 85)
        return {"applied": True, "map_id": src, "map_name": names.get(src), "file": newest["file"],
                "timestamp": newest.get("timestamp"),
                "next_steps": f"Backed up \"{names.get(src)}\" and kept a copy in Home Assistant "
                              "(the Backups tab, config/tapo_rv30/map_backups)."}

    async def _backup_fetch(call: ServiceCall, coord: TapoCoordinator, names: dict[int, str], src: int,
                            job: str, upto: float) -> dict:
        """A fresh backup of map src: mapBackup (the robot uploads it to the TP-Link cloud), then
        download it into this robot's backups folder. Progress goes to job, 0..upto percent.
        Returns the downloaded backup's entry (file, timestamp, ...)."""
        import time
        import uuid

        from homeassistant.const import CONF_PASSWORD, CONF_USERNAME

        from .cloud import CloudError, fetch_backups
        if coord.map_busy:
            raise ServiceValidationError(f"{call.service}: {coord.device_name} must be docked and idle")
        if coord.map_lock.locked():
            raise ServiceValidationError(f"{call.service}: a map write is running; try again shortly")
        started = time.time()
        async with coord.map_lock:
            if coord.restore_unfinished() is not None:
                raise ServiceValidationError(f"{call.service}: a restore is still being finished; try again in a "
                                             "few minutes")
            _, map_list = await _read(hass, call, coord.client.get_map_info)
            if not any(m.get("map_id") == src and m.get("is_saved") is not False for m in map_list):
                raise ServiceValidationError(f"{call.service}: only a saved map can be backed up or copied")
            # 1. A fresh backup of the source map, to the cloud (the only place the robot puts one).
            try:
                baseline = await hass.async_add_executor_job(coord.client.get_map_br_process)
            except Exception:
                baseline = {}
            code = await _read(hass, call, coord.client.backup_map, src)
            if code != 0:
                raise HomeAssistantError(f"{call.service}: the robot refused to back up '{names[src]}' (error {code})")
            coord.map_job(job, "Backing the map up to your TP-Link cloud", 0)
            process = await _wait_br(coord, 1, baseline, src, tries=60, progress=lambda pc: coord.map_job(
                job, "Backing the map up to your TP-Link cloud", upto * pc / 100))
        if _opt_int(process.get("status")) != 3:
            raise HomeAssistantError(f"{call.service}: the robot did not finish backing up '{names[src]}'"
                                     + (" (it reported a failure)" if _opt_int(process.get("status")) == 13 else ""))
        # 2. Download it.
        coord.map_job(job, "Downloading the backup", upto + 2)
        terminal = str(uuid.uuid5(uuid.NAMESPACE_URL, f"{DOMAIN}:{coord.entry.entry_id}"))
        try:
            got = await hass.async_add_executor_job(
                fetch_backups, coord.client, coord.entry.data[CONF_USERNAME], coord.entry.data[CONF_PASSWORD],
                terminal, setup_apply.backups_folder(hass, coord), False, call.data.get("verification_code"))
        except CloudError as exc:
            raise HomeAssistantError(f"{call.service}: {exc}") from exc
        if got.get("status") == "code_sent":
            # The robot has already made the backup: only the download waits for the code.
            msg = ("TP-Link emailed a verification code. The backup is in your TP-Link cloud: run "
                   "fetch_cloud_map_backups with verification_code set to that code to download it"
                   + ("" if call.service == "backup_map" else f", then run {call.service} again"))
            coord.map_job(job, "Waiting for a verification code", 100, done=True, error=msg)
            raise HomeAssistantError(f"{call.service}: {msg}")
        # Only the backup just made (cloud timestamps are seconds; a few minutes' slack for clocks).
        mine = [b for b in got.get("backups", []) if b.get("map_id") == src and b.get("file") and not b.get("error")
                and (_opt_int(b.get("timestamp")) or 0) >= started - 300]
        if not mine:
            raise HomeAssistantError(f"{call.service}: the cloud does not have the new backup of '{names[src]}' "
                                     "yet; try again in a minute")
        return max(mine, key=lambda b: b.get("timestamp") or 0)

    async def handle_delete_map(call: ServiceCall) -> ServiceResponse:
        """Delete a map from the robot, as the Tapo app does. Never the current map (switch first)
        and never the last saved one; named in full or by id; docked and idle."""
        import os
        coord = _one(hass, call)
        if not call.data.get("confirm"):
            raise ServiceValidationError(f"{call.service}: this deletes a map from the robot; set confirm: true")
        names = await _read(hass, call, coord.map_names)
        map_id = _match_map(call, names, call.data.get("map"), exact=True)
        if coord.map_busy:
            raise ServiceValidationError(f"{call.service}: {coord.device_name} must be docked and idle")
        if coord.map_lock.locked():
            raise ServiceValidationError(f"{call.service}: a map write is running; try again shortly")
        async with coord.map_lock:
            current, map_list = await _read(hass, call, coord.client.get_map_info)
            ids = [m.get("map_id") for m in map_list]
            if map_id not in ids:
                raise ServiceValidationError(f"{call.service}: '{names.get(map_id)}' is not on the robot any more")
            if map_id == current:
                raise ServiceValidationError(f"{call.service}: '{names.get(map_id)}' is the current map; switch to "
                                             "another map first")
            if not any(m.get("is_saved") is not False and m.get("map_id") != map_id for m in map_list):
                raise ServiceValidationError(f"{call.service}: '{names.get(map_id)}' is the only saved map; the robot "
                                             "needs one to restore a backup onto")
            if coord.restore_unfinished() is not None:
                raise ServiceValidationError(f"{call.service}: a restore is still being finished; try again in a "
                                             "few minutes")

            def _held() -> list[str]:
                out = []
                for folder in setup_apply.backup_folders(hass, coord):
                    try:
                        out += [f for f in os.listdir(folder) if re.match(rf"^cloud_{map_id}_\d+\.bin$", f)]
                    except OSError:
                        continue
                return sorted(out)

            held = await hass.async_add_executor_job(_held)
            try:
                code = await _read(hass, call, coord.client.delete_map, map_id)
                _, after = await _read(hass, call, coord.client.get_map_info)
            finally:
                await coord.async_request_map_refresh()
        if code != 0 or any(m.get("map_id") == map_id for m in after):
            raise HomeAssistantError(f"{call.service}: the robot did not delete '{names.get(map_id)}' (error {code})")
        if (coord.pending_restore or {}).get("map_id") == map_id:
            coord._drop_restore(coord.pending_restore)
        return {"map_id": map_id, "map_name": names.get(map_id), "deleted": True, "backups_held": held}

    hass.services.async_register(DOMAIN, "restore_map_backup", _admin_only(hass, handle_restore_map_backup),
                                 supports_response=SupportsResponse.OPTIONAL)
    hass.services.async_register(DOMAIN, "copy_map", _admin_only(hass, handle_copy_map),
                                 supports_response=SupportsResponse.OPTIONAL)
    hass.services.async_register(DOMAIN, "backup_map", _admin_only(hass, handle_backup_map),
                                 supports_response=SupportsResponse.OPTIONAL)
    hass.services.async_register(DOMAIN, "delete_map", _admin_only(hass, handle_delete_map),
                                 supports_response=SupportsResponse.OPTIONAL)
    hass.services.async_register(DOMAIN, "save_map_setup", _admin_only(hass, handle_save_map_setup),
                                 supports_response=SupportsResponse.OPTIONAL)
    hass.services.async_register(DOMAIN, "apply_map_setup", _admin_only(hass, handle_apply_map_setup),
                                 supports_response=SupportsResponse.OPTIONAL)
    hass.services.async_register(DOMAIN, "fetch_cloud_map_backups", _admin_only(hass, handle_fetch_cloud_map_backups),
                                 supports_response=SupportsResponse.OPTIONAL)
    hass.services.async_register(DOMAIN, "clean_rooms", handle_clean_rooms)
    hass.services.async_register(DOMAIN, "run_preset", handle_run_preset)
    for name, fn in (("create_preset", handle_create_preset), ("update_preset", handle_update_preset),
                     ("delete_preset", handle_delete_preset)):
        if name in ADMIN_SERVICES:
            fn = _admin_only(hass, fn)
        hass.services.async_register(DOMAIN, name, fn, supports_response=SupportsResponse.OPTIONAL)
    hass.services.async_register(DOMAIN, "set_map", handle_set_map)
    # Renaming rewrites the robot and can break automations that name the map: admins only.
    hass.services.async_register(DOMAIN, "rename_map", _admin_only(hass, handle_rename_map),
                                 supports_response=SupportsResponse.OPTIONAL)
    hass.services.async_register(DOMAIN, "set_map_rotation", handle_set_map_rotation,
                                 supports_response=SupportsResponse.OPTIONAL)
    hass.services.async_register(DOMAIN, "set_map_lock", _admin_only(hass, handle_set_map_lock),
                                 supports_response=SupportsResponse.OPTIONAL)
    hass.services.async_register(DOMAIN, "go_to", handle_go_to)
    hass.services.async_register(DOMAIN, "remote_drive", handle_remote_drive,
                                 supports_response=SupportsResponse.OPTIONAL)
    hass.services.async_register(DOMAIN, "add_schedule", handle_add_schedule,
                                 supports_response=SupportsResponse.OPTIONAL)
    hass.services.async_register(DOMAIN, "set_schedule", handle_set_schedule)
    hass.services.async_register(DOMAIN, "remove_schedule", _admin_only(hass, handle_remove_schedule))
    hass.services.async_register(DOMAIN, "remove_matter_fabric", _admin_only(hass, handle_remove_matter_fabric))
    hass.services.async_register(DOMAIN, "get_matter_setup_code", _admin_only(hass, handle_get_matter_setup_code),
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN, "get_clean_records", handle_get_clean_records,
                                 supports_response=SupportsResponse.ONLY)
    hass.services.async_register(DOMAIN, "set_room_settings", handle_set_room_settings)
    hass.services.async_register(DOMAIN, "clean_zone", handle_clean_zone)
    hass.services.async_register(DOMAIN, "run_schedule", handle_run_schedule)
    hass.services.async_register(DOMAIN, "send_raw", _admin_only(hass, handle_send_raw),
                                 supports_response=SupportsResponse.ONLY)


def async_unload_services(hass: HomeAssistant) -> None:
    """Remove the services once the last config entry is gone."""
    for svc in SERVICES:
        hass.services.async_remove(DOMAIN, svc)
