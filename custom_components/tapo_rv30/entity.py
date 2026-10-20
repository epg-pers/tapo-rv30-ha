"""Shared base for the settings entities (button / switch / time / number)."""
from __future__ import annotations

from typing import Any, Callable

from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import TapoCoordinator


class TapoEntity(CoordinatorEntity[TapoCoordinator]):
    _attr_has_entity_name = True

    def __init__(self, coordinator: TapoCoordinator, entry: ConfigEntry, key: str, name: str) -> None:
        super().__init__(coordinator)
        self._entry = entry
        self._attr_unique_id = f"{entry.entry_id}_{key}"
        self._attr_name = name

    @property
    def device_info(self) -> dict[str, Any]:
        return {
            "identifiers": {(DOMAIN, self._entry.entry_id)},
            "name":        self.coordinator.device_name,
            "manufacturer":"TP-Link",
            "model":       "Tapo RV30 Max Plus",
        }

    @property
    def settings(self) -> dict:
        return (self.coordinator.data or {}).get("settings", {})

    async def _write(self, fn: Callable[[], None]) -> None:
        """Run a client write, then re-read settings so the UI updates immediately."""
        await self.hass.async_add_executor_job(fn)
        await self.coordinator.async_settings_changed()
