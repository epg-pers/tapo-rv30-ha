"""Select entities for Tapo RV30 — water level, clean passes, auto empty, clean map history and map rotation."""
from __future__ import annotations

import logging

from homeassistant.components.select import SelectEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .cleanhistory import RETENTION_DAYS
from .const import AUTO_EMPTY_MODES, DOMAIN, WATER_INT_TO_NAME, WATER_NAME_TO_INT
from .coordinator import TapoCoordinator
from .entity import TapoEntity, remove_missing_parts

_LOGGER = logging.getLogger(__name__)

PASSES_OPTIONS = ["1", "2", "3"]
WATER_OPTIONS  = ["off", "low", "medium", "high"]


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: TapoCoordinator = hass.data[DOMAIN][entry.entry_id]
    entities: list[SelectEntity] = [TapoCleanPassesSelect(coordinator, entry)]
    # Robots without a mop have no water level: no mop component and no water level reported.
    if (coordinator.components and coordinator.has("mop")) or (coordinator.data or {}).get("cistern") is not None:
        entities.append(TapoWaterLevelSelect(coordinator, entry))
    else:
        remove_missing_parts(hass, coordinator, entry, "select", ["water_level"])
    if "dust_collection_mode" in (coordinator.settings.get("dust") or {}):
        entities.append(TapoAutoEmptyModeSelect(coordinator, entry))
    entities.append(TapoHistoryRetentionSelect(coordinator, entry))
    entities.append(TapoMapRotationSelect(coordinator, entry))
    async_add_entities(entities)


class _TapoSelectBase(CoordinatorEntity[TapoCoordinator], SelectEntity):
    _attr_has_entity_name = True

    async def _call(self, fn, *args) -> None:
        """Device or network errors become a readable error instead of a traceback."""
        try:
            await self.hass.async_add_executor_job(fn, *args)
        except Exception as exc:
            raise HomeAssistantError(f"{self.coordinator.device_name} rejected the change: {exc}") from exc

    def __init__(self, coordinator: TapoCoordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator)
        self._entry = entry

    @property
    def device_info(self):
        return self.coordinator.device_info


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
        return None if d.get("clean_number") is None else str(d["clean_number"])

    async def async_select_option(self, option: str) -> None:
        await self._call(self.coordinator.client.set_passes, int(option))
        await self.coordinator.async_request_refresh()


class TapoWaterLevelSelect(_TapoSelectBase):
    _attr_name    = "Water Level"
    _attr_translation_key = "water_level"     # for the state names
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
        return None if d.get("cistern") is None else WATER_INT_TO_NAME.get(d["cistern"], "off")

    async def async_select_option(self, option: str) -> None:
        value = WATER_NAME_TO_INT.get(option)
        if value is None:
            _LOGGER.error("Unknown water level: %s", option)
            return
        await self._call(self.coordinator.client.set_water, value)
        await self.coordinator.async_request_refresh()


class TapoAutoEmptyModeSelect(TapoEntity, SelectEntity):
    """How often the self-empty dock empties the bin (Smart / Light / Balanced / Max)."""
    _attr_entity_category = EntityCategory.CONFIG
    _attr_icon = "mdi:delete-sweep"
    _attr_translation_key = "auto_empty_mode"
    _attr_options = list(AUTO_EMPTY_MODES.values())

    def __init__(self, coordinator: TapoCoordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator, entry, "auto_empty_mode", "Auto Empty Mode")

    @property
    def current_option(self) -> str | None:
        return AUTO_EMPTY_MODES.get((self.settings.get("dust") or {}).get("dust_collection_mode"))

    async def async_select_option(self, option: str) -> None:
        mode = next(k for k, v in AUTO_EMPTY_MODES.items() if v == option)
        await self._write(lambda: self.coordinator.client.set_auto_empty_mode(mode))


class TapoHistoryRetentionSelect(TapoEntity, SelectEntity):
    """How long the maps of finished cleans are kept in Home Assistant (Off clears them)."""
    _attr_entity_category = EntityCategory.CONFIG
    _attr_icon = "mdi:map-clock-outline"
    _attr_options = list(RETENTION_DAYS)

    def __init__(self, coordinator: TapoCoordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator, entry, "clean_map_history", "Clean Map History")

    @property
    def current_option(self) -> str:
        return self.coordinator.history_retention

    async def async_select_option(self, option: str) -> None:
        await self.coordinator.async_set_history(retention=option)


class TapoMapRotationSelect(TapoEntity, SelectEntity):
    """How the current map is turned (clockwise degrees), stored on the robot like the app's
    own setting, so the Tapo app shows it the same way. Display only."""
    _attr_entity_category = EntityCategory.CONFIG
    _attr_icon = "mdi:rotate-right"
    _attr_options = ["0", "90", "180", "270"]

    def __init__(self, coordinator: TapoCoordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator, entry, "map_rotation", "Map Rotation")

    @property
    def available(self) -> bool:
        return super().available and self.coordinator.map_id is not None

    @property
    def current_option(self) -> str:
        return str(self.coordinator.map_rotation)

    async def async_select_option(self, option: str) -> None:
        try:
            await self.coordinator.async_set_map_rotation(self.coordinator.map_id, int(option))
        except Exception as exc:
            raise HomeAssistantError(f"{self.coordinator.device_name}: could not turn the map: {exc}") from exc
