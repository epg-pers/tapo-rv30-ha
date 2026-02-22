"""Camera entity serving the rendered map image for Tapo RV30."""
from __future__ import annotations

import logging
from homeassistant.components.camera import Camera
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import TapoCoordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: TapoCoordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([TapoMapCamera(coordinator, entry)])


class TapoMapCamera(CoordinatorEntity[TapoCoordinator], Camera):
    _attr_has_entity_name = True
    _attr_name            = "Map"
    _attr_is_streaming    = False
    _attr_is_recording    = False
    _attr_brand           = "TP-Link"
    _attr_model           = "Tapo RV30 Map"

    def __init__(self, coordinator: TapoCoordinator, entry: ConfigEntry) -> None:
        CoordinatorEntity.__init__(self, coordinator)
        Camera.__init__(self)
        self._attr_unique_id  = f"{entry.entry_id}_map"
        self._attr_device_info = {
            "identifiers": {(DOMAIN, entry.entry_id)},
            "name": "Jarvis",
            "manufacturer": "TP-Link",
            "model": "Tapo RV30 Max Plus",
        }

    async def async_camera_image(
        self, width: int | None = None, height: int | None = None
    ) -> bytes | None:
        return self.coordinator.map_image_bytes
