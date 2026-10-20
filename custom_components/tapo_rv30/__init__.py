"""Tapo RV30 Robot Vacuum integration."""
from __future__ import annotations

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME, Platform
from homeassistant.core import HomeAssistant, ServiceCall, ServiceResponse, SupportsResponse
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError

from .const import DEFAULT_PORT, DOMAIN, FAN_NAME_TO_INT, WATER_NAME_TO_INT
from .coordinator import TapoCoordinator
from .tpap import TapoVacuumClient

_LOGGER = logging.getLogger(__name__)
PLATFORMS = [Platform.VACUUM, Platform.SENSOR, Platform.CAMERA, Platform.SELECT,
             Platform.BUTTON, Platform.SWITCH, Platform.TIME, Platform.NUMBER]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    client = TapoVacuumClient(
        host=entry.data[CONF_HOST],
        username=entry.data[CONF_USERNAME],
        password=entry.data[CONF_PASSWORD],
        port=DEFAULT_PORT,
    )
    coordinator = TapoCoordinator(hass, client)
    await coordinator.async_config_entry_first_refresh()

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    def _rooms_list(call: ServiceCall) -> list[str]:
        """'rooms' as a list. Templates give a bare string when one room is picked,
        and iterating a string would yield single characters."""
        raw = call.data.get("rooms", [])
        rooms = [raw] if isinstance(raw, str) else list(raw)
        if not rooms:
            raise ServiceValidationError(f"{call.service}: 'rooms' is required")
        return rooms

    async def _resolve(call: ServiceCall) -> tuple[list[int], int]:
        """Resolve rooms/map from the call, raising a user-facing error on failure."""
        rooms = _rooms_list(call)
        try:
            return await hass.async_add_executor_job(
                coordinator.resolve_rooms_live, rooms, call.data.get("map")
            )
        except ValueError as exc:          # MapNotFound / RoomNotFound
            raise ServiceValidationError(f"{call.service}: {exc}") from exc
        except Exception as exc:
            raise HomeAssistantError(
                f"{call.service}: could not read maps from the vacuum: {exc}"
            ) from exc

    async def _send(call: ServiceCall, fn, *args) -> None:
        """Run a client write, surfacing device errors to the caller."""
        try:
            await hass.async_add_executor_job(fn, *args)
        except Exception as exc:
            raise HomeAssistantError(f"{call.service}: vacuum rejected the command: {exc}") from exc

    async def handle_clean_rooms(call: ServiceCall) -> None:
        """Service: tapo_rv30.clean_rooms."""
        room_ids, map_id = await _resolve(call)
        await _send(call, coordinator.client.clean_rooms, room_ids, map_id)
        await coordinator.async_refresh_soon()

    hass.services.async_register(DOMAIN, "clean_rooms", handle_clean_rooms)

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

    async def handle_set_room_settings(call: ServiceCall) -> None:
        """Service: tapo_rv30.set_room_settings."""
        room_ids, map_id = await _resolve(call)
        lv = _levels(call)
        await _send(call, coordinator.client.set_room_settings, map_id, {rid: lv for rid in room_ids})
        await coordinator.async_request_refresh()

    async def handle_clean_zone(call: ServiceCall) -> None:
        """Service: tapo_rv30.clean_zone."""
        g = coordinator.data or {}
        lv = {"suction": g.get("suction", 3), "cistern": g.get("cistern", 0),
              "clean_number": 1, **_levels(call)}
        try:
            map_id, _ = await hass.async_add_executor_job(coordinator.client.get_map_info)
        except Exception as exc:
            raise HomeAssistantError(f"{call.service}: could not read maps from the vacuum: {exc}") from exc
        await _send(call, coordinator.client.clean_zones, map_id, call.data["zones"],
                    lv["suction"], lv["cistern"], lv["clean_number"])
        await coordinator.async_refresh_soon()

    async def handle_run_schedule(call: ServiceCall) -> None:
        """Service: tapo_rv30.run_schedule (replays a saved schedule's settings)."""
        sid = call.data.get("schedule_id")
        if sid is None:
            raise ServiceValidationError(f"{call.service}: 'schedule_id' is required")
        try:
            sid = int(sid)
        except (TypeError, ValueError):
            pass
        try:
            await hass.async_add_executor_job(coordinator.client.run_schedule, sid)
        except ValueError as exc:
            raise ServiceValidationError(f"{call.service}: {exc}") from exc
        except Exception as exc:
            raise HomeAssistantError(f"{call.service}: vacuum rejected the command: {exc}") from exc
        await coordinator.async_refresh_soon()

    async def handle_send_raw(call: ServiceCall) -> ServiceResponse:
        """Service: tapo_rv30.send_raw -- any device method, returns the response."""
        method = str(call.data.get("method", "")).strip()
        if not method:
            raise ServiceValidationError(f"{call.service}: 'method' is required")
        params = call.data.get("params") or {}
        if not isinstance(params, dict):
            raise ServiceValidationError(f"{call.service}: 'params' must be a mapping")
        try:
            resp = await hass.async_add_executor_job(coordinator.client.send, method, params)
        except Exception as exc:
            raise HomeAssistantError(f"{call.service}: {method} failed: {exc}") from exc
        return {"result": resp.get("result"), "error_code": resp.get("error_code", 0)}

    hass.services.async_register(DOMAIN, "set_room_settings", handle_set_room_settings)
    hass.services.async_register(DOMAIN, "clean_zone", handle_clean_zone)
    hass.services.async_register(DOMAIN, "run_schedule", handle_run_schedule)
    hass.services.async_register(DOMAIN, "send_raw", handle_send_raw,
                                 supports_response=SupportsResponse.ONLY)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if ok:
        hass.data[DOMAIN].pop(entry.entry_id, None)
        for svc in ("clean_rooms", "set_room_settings", "clean_zone", "run_schedule", "send_raw"):
            hass.services.async_remove(DOMAIN, svc)
    return ok
