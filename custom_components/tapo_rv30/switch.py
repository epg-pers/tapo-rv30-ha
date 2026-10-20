"""Switches for Tapo RV30 — auto-empty, do-not-disturb, child lock, carpet boost."""
from __future__ import annotations

from typing import Any

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .entity import TapoEntity

# key, name, icon, settings group, field, client setter(client, value)
SWITCHES = [
    ("auto_empty", "Auto Empty", "mdi:delete-restore", "dust", "auto_dust_collection",
     lambda c, v: c.set_auto_empty(v)),
    ("dnd", "Do Not Disturb", "mdi:bell-sleep", "dnd", "do_not_disturb",
     lambda c, v: c.set_dnd(do_not_disturb=v)),
    ("child_lock", "Child Lock", "mdi:lock", "child_lock", "child_lock_status",
     lambda c, v: c.set_child_lock(v)),
    ("carpet_boost", "Carpet Boost", "mdi:rug", "carpet_boost", "auto_boost",
     lambda c, v: c.set_carpet_boost(v)),
]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry,
                            async_add_entities: AddEntitiesCallback) -> None:
    c = hass.data[DOMAIN][entry.entry_id]
    # Only what this model answered (unsupported getters are left out of settings).
    async_add_entities(TapoSettingSwitch(c, entry, *s) for s in SWITCHES if s[3] in c.settings)


class TapoSettingSwitch(TapoEntity, SwitchEntity):
    _attr_entity_category = EntityCategory.CONFIG

    def __init__(self, coordinator, entry, key, name, icon, group, field, setter) -> None:
        super().__init__(coordinator, entry, key, name)
        self._attr_icon = icon
        self._group, self._field, self._setter = group, field, setter

    @property
    def is_on(self) -> bool | None:
        return self.settings.get(self._group, {}).get(self._field)

    async def async_turn_on(self, **kwargs: Any) -> None:
        await self._write(lambda: self._setter(self.coordinator.client, True))

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self._write(lambda: self._setter(self.coordinator.client, False))
