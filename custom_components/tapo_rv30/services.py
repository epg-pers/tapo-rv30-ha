"""Custom services. Registered once per Home Assistant instance and routed to
the right vacuum from the call's target, so several vacuums can coexist."""
from __future__ import annotations

import logging

from homeassistant.core import HomeAssistant, ServiceCall, ServiceResponse, SupportsResponse
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError
from homeassistant.helpers import entity_registry as er

from .const import DOMAIN, FAN_NAME_TO_INT, WATER_NAME_TO_INT
from .coordinator import TapoCoordinator

_LOGGER = logging.getLogger(__name__)
SERVICES = ("clean_rooms", "set_room_settings", "clean_zone", "run_schedule", "send_raw")


def _coordinators(hass: HomeAssistant, call: ServiceCall) -> list[TapoCoordinator]:
    """The coordinator(s) a call targets. With no target, the only vacuum set up."""
    loaded: dict[str, TapoCoordinator] = hass.data.get(DOMAIN, {})
    raw = call.data.get("entity_id") or []
    entity_ids = [raw] if isinstance(raw, str) else list(raw)
    if not entity_ids:
        if len(loaded) == 1:
            return list(loaded.values())
        raise ServiceValidationError(
            f"{call.service}: pick a target vacuum entity "
            f"({len(loaded)} Tapo vacuums are set up)"
        )
    registry = er.async_get(hass)
    found: dict[str, TapoCoordinator] = {}
    for eid in entity_ids:
        entry = registry.async_get(eid)
        coord = loaded.get(entry.config_entry_id) if entry and entry.config_entry_id else None
        if coord is None:
            raise ServiceValidationError(f"{call.service}: {eid} is not a Tapo RV30 entity")
        found[entry.config_entry_id] = coord
    return list(found.values())


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
            room_ids, map_id = await _resolve(hass, call, coord)
            await _send(hass, call, coord.client.clean_rooms, room_ids, map_id)
            await coord.async_refresh_soon()

    async def handle_set_room_settings(call: ServiceCall) -> None:
        for coord in _coordinators(hass, call):
            room_ids, map_id = await _resolve(hass, call, coord)
            lv = _levels(call)
            await _send(hass, call, coord.client.set_room_settings, map_id, {rid: lv for rid in room_ids})
            await coord.async_request_refresh()

    async def handle_clean_zone(call: ServiceCall) -> None:
        coord = _one(hass, call)        # zones are in one map's coordinate frame
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

    async def handle_run_schedule(call: ServiceCall) -> None:
        """Replays a saved schedule's settings; see services.yaml."""
        coord = _one(hass, call)
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
        try:
            resp = await hass.async_add_executor_job(coord.client.send, method, params)
        except Exception as exc:
            raise HomeAssistantError(f"{call.service}: {method} failed: {exc}") from exc
        return {"result": resp.get("result"), "error_code": resp.get("error_code", 0)}

    hass.services.async_register(DOMAIN, "clean_rooms", handle_clean_rooms)
    hass.services.async_register(DOMAIN, "set_room_settings", handle_set_room_settings)
    hass.services.async_register(DOMAIN, "clean_zone", handle_clean_zone)
    hass.services.async_register(DOMAIN, "run_schedule", handle_run_schedule)
    hass.services.async_register(DOMAIN, "send_raw", handle_send_raw,
                                 supports_response=SupportsResponse.ONLY)


def async_unload_services(hass: HomeAssistant) -> None:
    """Remove the services once the last config entry is gone."""
    for svc in SERVICES:
        hass.services.async_remove(DOMAIN, svc)
