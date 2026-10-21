"""Image entity for the map: pushes updates to the frontend the moment the
rendered map changes, unlike the camera which the frontend polls."""
from __future__ import annotations

import hashlib

from homeassistant.components.image import ImageEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.util import dt as dt_util

from .const import DOMAIN
from .entity import TapoEntity


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry,
                            async_add_entities: AddEntitiesCallback) -> None:
    async_add_entities([TapoMapImage(hass, hass.data[DOMAIN][entry.entry_id], entry)])


class TapoMapImage(TapoEntity, ImageEntity):
    _attr_content_type = "image/png"
    _attr_icon = "mdi:map"

    def __init__(self, hass: HomeAssistant, coordinator, entry: ConfigEntry) -> None:
        TapoEntity.__init__(self, coordinator, entry, "map_image", "Map Image")
        ImageEntity.__init__(self, hass)
        self._digest: str | None = None
        self._bump()

    def _bump(self) -> None:
        data = self.coordinator.map_image_bytes
        digest = hashlib.sha1(data).hexdigest() if data else None
        if digest != self._digest:
            self._digest = digest
            self._attr_image_last_updated = dt_util.utcnow()

    @callback
    def _handle_coordinator_update(self) -> None:
        self._bump()
        super()._handle_coordinator_update()

    async def async_image(self) -> bytes | None:
        return self.coordinator.map_image_bytes
