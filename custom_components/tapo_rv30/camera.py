"""Camera entity serving the rendered map image for Tapo RV30."""
from __future__ import annotations

from typing import Any

from homeassistant.components.camera import Camera
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import TapoCoordinator


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry,
                            async_add_entities: AddEntitiesCallback) -> None:
    async_add_entities([TapoMapCamera(hass.data[DOMAIN][entry.entry_id], entry)])


class TapoMapCamera(CoordinatorEntity[TapoCoordinator], Camera):
    """The current map: rooms, no-go zones, walls, carpets, dock and the robot.

    The robot marker is refreshed on every poll; the rest every 5 minutes.
    `room_geometry` / `map_geometry` attributes let a card map clicks and
    millimetre coordinates to image pixels.
    """
    _attr_has_entity_name = True
    _attr_name = "Map"
    _attr_is_streaming = False
    _attr_is_recording = False
    _attr_brand = "TP-Link"

    def __init__(self, coordinator: TapoCoordinator, entry: ConfigEntry) -> None:
        CoordinatorEntity.__init__(self, coordinator)
        Camera.__init__(self)
        self._attr_unique_id = f"{entry.entry_id}_map"

    @property
    def device_info(self) -> DeviceInfo:
        return self.coordinator.device_info

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        return {
            "map_id": self.coordinator.map_id,
            "map_name": self.coordinator.map_name,
            "rooms": [r["name"] for r in self.coordinator.room_geometry],
            "room_geometry": self.coordinator.room_geometry,
            "map_geometry": self.coordinator.map_geometry,
        }

    async def async_camera_image(self, width: int | None = None, height: int | None = None) -> bytes | None:
        return self.coordinator.map_image_bytes
