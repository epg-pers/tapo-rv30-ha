"""Number entities for Tapo RV30: voice volume, poll interval."""
from __future__ import annotations

from homeassistant.components.number import NumberEntity, NumberMode
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory, UnitOfTime
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN, MAX_POLL_INTERVAL, MIN_POLL_INTERVAL
from .entity import TapoEntity


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry,
                            async_add_entities: AddEntitiesCallback) -> None:
    c = hass.data[DOMAIN][entry.entry_id]
    entities = [TapoPollInterval(c, entry, "poll_interval", "Poll Interval")]
    if "volume" in c.settings:
        entities.append(TapoVolume(c, entry, "volume", "Volume"))
    async_add_entities(entities)


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


class TapoPollInterval(TapoEntity, NumberEntity):
    """How often the vacuum is polled. Lower is snappier, higher is kinder to the
    robot's wifi; the map image is still only re-rendered every 5 minutes."""
    _attr_icon = "mdi:timer-sync-outline"
    _attr_entity_category = EntityCategory.CONFIG
    _attr_native_min_value = MIN_POLL_INTERVAL
    _attr_native_max_value = MAX_POLL_INTERVAL
    _attr_native_step = 5
    _attr_native_unit_of_measurement = UnitOfTime.SECONDS
    _attr_mode = NumberMode.BOX

    @property
    def native_value(self) -> float:
        return self.coordinator.poll_interval

    async def async_set_native_value(self, value: float) -> None:
        await self.coordinator.async_set_poll_interval(int(value))
