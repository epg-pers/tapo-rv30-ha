"""Shared base for the integration's entities."""
from __future__ import annotations

from typing import Any, Callable

from homeassistant.config_entries import ConfigEntry
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import TapoCoordinator
from .tpap import AuthError, RobotBusy


def remove_missing_parts(hass, coordinator: TapoCoordinator, entry: ConfigEntry, domain: str,
                         keys: list[str]) -> None:
    """Drop registry entries for part entities no longer created because the robot does not
    report the part (0.28 made them for every robot). Only on a definite answer: a parts list
    that was read, so a failed read never removes anything."""
    from homeassistant.helpers import entity_registry as er

    if not keys or not (coordinator.data or {}).get("consumables"):
        return
    reg = er.async_get(hass)
    for key in keys:
        if eid := reg.async_get_entity_id(domain, DOMAIN, f"{entry.entry_id}_{key}"):
            reg.async_remove(eid)


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

    async def _call(self, fn: Callable[..., Any], *args: Any) -> Any:
        """Run a blocking client call; device/network errors become a readable
        HomeAssistantError instead of "Unexpected exception" in the UI."""
        try:
            return await self.hass.async_add_executor_job(fn, *args)
        except AuthError as exc:
            raise HomeAssistantError(f"{self.coordinator.device_name}: authentication failed ({exc})") from exc
        except RobotBusy as exc:
            raise ServiceValidationError(f"{self.coordinator.device_name} {exc}") from exc
        except Exception as exc:
            raise HomeAssistantError(f"{self.coordinator.device_name} rejected the command: {exc}") from exc

    async def _write(self, fn: Callable[[], None]) -> None:
        """Run a client write, then re-read settings so the UI updates immediately."""
        await self._call(fn)
        await self.coordinator.async_settings_changed()
        # The robot can still answer with the old value for a second or two.
        await self.coordinator.async_settings_changed_later(2.5)
