"""Shared base for the integration's entities."""
from __future__ import annotations

from typing import Callable

from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .coordinator import TapoCoordinator


class TapoEntity(CoordinatorEntity[TapoCoordinator]):
    _attr_has_entity_name = True

    def __init__(self, coordinator: TapoCoordinator, entry: ConfigEntry, key: str, name: str | None) -> None:
        super().__init__(coordinator)
        self._entry = entry
        self._attr_unique_id = f"{entry.entry_id}_{key}"
        self._attr_name = name

    @property
    def device_info(self) -> DeviceInfo:
        return self.coordinator.device_info

    @property
    def settings(self) -> dict:
        return (self.coordinator.data or {}).get("settings", {})

    async def _write(self, fn: Callable[[], None]) -> None:
        """Run a client write, then re-read settings so the UI updates immediately."""
        await self.hass.async_add_executor_job(fn)
        await self.coordinator.async_settings_changed()
