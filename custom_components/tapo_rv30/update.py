"""Firmware update entity (read-only): shows the robot's own update check.
Installing is deliberately not offered here: some firmware builds have broken
local access (see README), so update from the Tapo app on purpose."""
from __future__ import annotations

from homeassistant.components.update import UpdateDeviceClass, UpdateEntity, UpdateEntityFeature
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .entity import TapoEntity


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry,
                            async_add_entities: AddEntitiesCallback) -> None:
    c = hass.data[DOMAIN][entry.entry_id]
    if c.has("firmware"):
        async_add_entities([TapoFirmware(c, entry, "firmware", "Firmware")])


class TapoFirmware(TapoEntity, UpdateEntity):
    _attr_device_class = UpdateDeviceClass.FIRMWARE
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_supported_features = UpdateEntityFeature(0)   # no install from HA, on purpose

    @property
    def installed_version(self) -> str | None:
        return self.coordinator.fw_version

    @property
    def latest_version(self) -> str | None:
        fw = (self.coordinator.data or {}).get("firmware") or {}
        if fw.get("need_to_upgrade") and fw.get("fw_ver"):
            return fw["fw_ver"]
        return self.coordinator.fw_version

    @property
    def release_summary(self) -> str | None:
        fw = (self.coordinator.data or {}).get("firmware") or {}
        return fw.get("release_note") or None
