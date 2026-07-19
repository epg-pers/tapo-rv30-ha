"""Number entities for Tapo RV30 — generic bridge for any python-kasa
Feature of type Number. (clean_count is excluded here since it's already
exposed as the "Clean Passes" select entity — this platform picks up any
other numeric config values the device negotiates.)
"""
from __future__ import annotations

import logging

from homeassistant.components.number import NumberEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, EXCLUDE_FEATURE_IDS
from .coordinator import TapoCoordinator

_LOGGER = logging.getLogger(__name__)

_CATEGORY_MAP = {
    "Config": EntityCategory.CONFIG,
    "Debug":  EntityCategory.DIAGNOSTIC,
    "Info":   EntityCategory.DIAGNOSTIC,
}


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: TapoCoordinator = hass.data[DOMAIN][entry.entry_id]
    entities = [
        TapoFeatureNumber(coordinator, entry, desc)
        for desc in coordinator.feature_descriptors
        if desc["type"] == "Number" and desc["id"] not in EXCLUDE_FEATURE_IDS
    ]
    async_add_entities(entities)


class TapoFeatureNumber(CoordinatorEntity[TapoCoordinator], NumberEntity):
    _attr_has_entity_name = True

    def __init__(self, coordinator, entry, desc: dict) -> None:
        super().__init__(coordinator)
        self._fid            = desc["id"]
        self._attr_name      = desc["name"]
        self._attr_unique_id = f"{entry.entry_id}_feat_{desc['id']}"
        if desc.get("icon"):
            self._attr_icon = desc["icon"]
        if desc.get("unit"):
            self._attr_native_unit_of_measurement = desc["unit"]
        self._attr_native_min_value = desc.get("min") if desc.get("min") is not None else 0
        self._attr_native_max_value = desc.get("max") if desc.get("max") is not None else 100
        self._attr_entity_category = _CATEGORY_MAP.get(desc.get("category"))
        self._entry = entry

    @property
    def device_info(self):
        return {
            "identifiers": {(DOMAIN, self._entry.entry_id)},
            "name":        self.coordinator.device_name,
            "manufacturer":"TP-Link",
            "model":       self.coordinator.device_model,
        }

    @property
    def native_value(self) -> float | None:
        return self.coordinator.features.get(self._fid)

    async def async_set_native_value(self, value: float) -> None:
        await self.hass.async_add_executor_job(
            self.coordinator.client.set_feature_value, self._fid, int(round(value))
        )
        await self.coordinator.async_request_refresh()
