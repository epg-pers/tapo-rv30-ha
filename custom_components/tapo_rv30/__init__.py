"""Tapo RV30 Robot Vacuum integration."""
from __future__ import annotations

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME, Platform
from homeassistant.core import HomeAssistant, ServiceCall

from .const import DEFAULT_PORT, DOMAIN
from .coordinator import TapoCoordinator
from .tpap import TapoVacuumClient

_LOGGER = logging.getLogger(__name__)
PLATFORMS = [Platform.VACUUM, Platform.SENSOR, Platform.CAMERA]


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

    async def handle_clean_rooms(call: ServiceCall) -> None:
        """Service: tapo_rv30.clean_rooms."""
        entity_ids: list[str] = call.data.get("entity_id", [])
        rooms:      list[str] = call.data.get("rooms", [])
        if not rooms:
            _LOGGER.error("clean_rooms: 'rooms' field is required")
            return

        # Find the coordinator for the target entity
        coord: TapoCoordinator | None = None
        for eid in entity_ids:
            state = hass.states.get(eid)
            if state and state.attributes.get("integration") == DOMAIN:
                coord = coordinator
                break
        if coord is None:
            coord = coordinator   # fallback to first/only

        try:
            room_ids = coord.resolve_room_ids(rooms)
            map_id   = coord.map_id
            if map_id is None:
                _LOGGER.error("clean_rooms: map not loaded yet, try again in a moment")
                return
            await hass.async_add_executor_job(coord.client.clean_rooms, room_ids, map_id)
            # Trigger a map refresh after a short delay so the in-progress path shows
            await coordinator.async_request_refresh()
        except ValueError as exc:
            _LOGGER.error("clean_rooms: %s", exc)

    hass.services.async_register(DOMAIN, "clean_rooms", handle_clean_rooms)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if ok:
        hass.data[DOMAIN].pop(entry.entry_id, None)
        hass.services.async_remove(DOMAIN, "clean_rooms")
    return ok
