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
    ("auto_update", "Auto Firmware Update", "mdi:update", "auto_update", "enable",
     lambda c, v: c.set_auto_update(v)),
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
    if getattr(c, "planner", None) is not None:
        entities.append(TapoPlannerSwitch(c, entry))
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

    async def _set(self, value: bool) -> None:
        await self._call(self.coordinator.client.set_bool_setting, self._key, value)
        # Some settings read back the old value for a moment after a write.
        self.coordinator.set_bool_setting_local(self._key, value)
        await self.coordinator.async_settings_changed_later()

    async def async_turn_on(self, **kwargs: Any) -> None:
        await self._set(True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self._set(False)


class TapoPlannerSwitch(TapoEntity, SwitchEntity):
    """The smart cleaning planner on or off (its settings are on the Tapo Vacuum page)."""
    _attr_icon = "mdi:calendar-check"

    def __init__(self, coordinator, entry) -> None:
        super().__init__(coordinator, entry, "planner", "Planner")
        self._planner = coordinator.planner

    async def async_added_to_hass(self) -> None:
        await super().async_added_to_hass()
        self.async_on_remove(self._planner.add_listener(self.async_write_ha_state))

    @property
    def is_on(self) -> bool:
        return bool(self._planner.config.get("enabled"))

    @property
    def extra_state_attributes(self) -> dict:
        return {"preview": bool(self._planner.config.get("preview"))}

    async def async_turn_on(self, **kwargs: Any) -> None:
        await self._planner.async_set_config({"enabled": True})

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self._planner.async_set_config({"enabled": False})
