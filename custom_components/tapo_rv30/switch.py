"""Switches for Tapo RV30: auto-empty, do-not-disturb, and every on/off
setting the robot answers (child lock, carpet boost, and the RV50-era ones)."""
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
SETTING_GROUP_SWITCHES = [
    ("auto_empty", "Auto Empty", "mdi:delete-restore", "dust", "auto_dust_collection",
     lambda c, v: c.set_auto_empty(v)),
    ("dnd", "Do Not Disturb", "mdi:bell-sleep", "dnd", "do_not_disturb",
     lambda c, v: c.set_dnd(do_not_disturb=v)),
]

# Labels/icons for TapoVacuumClient.BOOL_SETTINGS; only the ones the robot answered get an entity.
BOOL_SETTING_LABELS = {
    "child_lock":          ("Child Lock", "mdi:lock"),
    "carpet_boost":        ("Carpet Boost", "mdi:rug"),
    "ai_avoid":            ("AI Obstacle Avoidance", "mdi:radar"),
    "automatic_remopping": ("Automatic Re-mopping", "mdi:autorenew"),
    "clean_along_floor":   ("Clean Along Floor", "mdi:floor-plan"),
    "extended_mopping":    ("Extended Mopping", "mdi:water-plus"),
    "pet_area_deep_clean": ("Pet Area Deep Clean", "mdi:paw"),
    "sweep_walk":          ("Sweep Walk", "mdi:motion-sensor"),
}


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry,
                            async_add_entities: AddEntitiesCallback) -> None:
    c = hass.data[DOMAIN][entry.entry_id]
    entities: list[SwitchEntity] = [
        TapoSettingSwitch(c, entry, *s) for s in SETTING_GROUP_SWITCHES if s[3] in c.settings]
    entities += [TapoBoolSettingSwitch(c, entry, key) for key in c.bool_settings_supported
                 if key in BOOL_SETTING_LABELS]
    async_add_entities(entities)


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


class TapoBoolSettingSwitch(TapoEntity, SwitchEntity):
    _attr_entity_category = EntityCategory.CONFIG

    def __init__(self, coordinator, entry, key: str) -> None:
        name, icon = BOOL_SETTING_LABELS[key]
        super().__init__(coordinator, entry, key, name)
        self._attr_icon = icon
        self._key = key

    @property
    def is_on(self) -> bool | None:
        return (self.coordinator.data or {}).get("bool_settings", {}).get(self._key)

    async def async_turn_on(self, **kwargs: Any) -> None:
        await self._write(lambda: self.coordinator.client.set_bool_setting(self._key, True))

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self._write(lambda: self.coordinator.client.set_bool_setting(self._key, False))
