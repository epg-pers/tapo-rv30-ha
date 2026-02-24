"""Select entities for Tapo RV30 — water level and clean passes."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.select import SelectEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, WATER_INT_TO_NAME, WATER_NAME_TO_INT
from .coordinator import TapoCoordinator

_LOGGER = logging.getLogger(__name__)

PASSES_OPTIONS = ["1", "2", "3"]
WATER_OPTIONS  = ["off", "low", "medium", "high"]


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: TapoCoordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([
        TapoCleanPassesSelect(coordinator, entry),
        TapoWaterLevelSelect(coordinator, entry),
    ])


class _TapoSelectBase(CoordinatorEntity[TapoCoordinator], SelectEntity):
    _attr_has_entity_name = True

    def __init__(self, coordinator: TapoCoordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator)
        self._entry = entry

    @property
    def device_info(self) -> dict[str, Any]:
        return {
            "identifiers": {(DOMAIN, self._entry.entry_id)},
            "name":        self.coordinator.device_name,
            "manufacturer":"TP-Link",
            "model":       "Tapo RV30 Max Plus",
        }


class TapoCleanPassesSelect(_TapoSelectBase):
    _attr_name    = "Clean Passes"
    _attr_icon    = "mdi:repeat"
    _attr_options = PASSES_OPTIONS

    def __init__(self, coordinator: TapoCoordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator, entry)
        self._attr_unique_id = f"{entry.entry_id}_clean_passes"

    @property
    def current_option(self) -> str | None:
        d = self.coordinator.data
        if d is None:
            return None
        return str(d.get("clean_number", 1))

    async def async_select_option(self, option: str) -> None:
        await self.hass.async_add_executor_job(
            self.coordinator.client.set_passes, int(option)
        )
        await self.coordinator.async_request_refresh()


class TapoWaterLevelSelect(_TapoSelectBase):
    _attr_name    = "Water Level"
    _attr_icon    = "mdi:water"
    _attr_options = WATER_OPTIONS

    def __init__(self, coordinator: TapoCoordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator, entry)
        self._attr_unique_id = f"{entry.entry_id}_water_level"

    @property
    def current_option(self) -> str | None:
        d = self.coordinator.data
        if d is None:
            return None
        return WATER_INT_TO_NAME.get(d.get("cistern", 0), "off")

    async def async_select_option(self, option: str) -> None:
        value = WATER_NAME_TO_INT.get(option)
        if value is None:
            _LOGGER.error("Unknown water level: %s", option)
            return
        await self.hass.async_add_executor_job(
            self.coordinator.client.set_water, value
        )
        await self.coordinator.async_request_refresh()
