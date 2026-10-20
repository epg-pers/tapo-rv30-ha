"""Number entities for Tapo RV30 — voice volume."""
from __future__ import annotations

from homeassistant.components.number import NumberEntity, NumberMode
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .entity import TapoEntity


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry,
                            async_add_entities: AddEntitiesCallback) -> None:
    c = hass.data[DOMAIN][entry.entry_id]
    if "volume" in c.settings:
        async_add_entities([TapoVolume(c, entry, "volume", "Volume")])


class TapoVolume(TapoEntity, NumberEntity):
    # Range 0-100 assumed (robot reported 15); the robot rejects anything out of range.
    _attr_icon = "mdi:volume-high"
    _attr_entity_category = EntityCategory.CONFIG
    _attr_native_min_value = 0
    _attr_native_max_value = 100
    _attr_native_step = 1
    _attr_mode = NumberMode.SLIDER

    @property
    def native_value(self) -> float | None:
        return self.settings.get("volume", {}).get("volume")

    async def async_set_native_value(self, value: float) -> None:
        await self._write(lambda: self.coordinator.client.set_volume(int(value)))
