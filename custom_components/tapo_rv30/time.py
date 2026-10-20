"""Time entities for Tapo RV30 — do-not-disturb start / end."""
from __future__ import annotations

from datetime import time

from homeassistant.components.time import TimeEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .entity import TapoEntity


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry,
                            async_add_entities: AddEntitiesCallback) -> None:
    c = hass.data[DOMAIN][entry.entry_id]
    if "dnd" in c.settings:
        async_add_entities([TapoDndTime(c, entry, "s_min", "Do Not Disturb Start"),
                            TapoDndTime(c, entry, "e_min", "Do Not Disturb End")])


class TapoDndTime(TapoEntity, TimeEntity):
    """The robot stores DND bounds as minutes after midnight."""
    _attr_icon = "mdi:clock-outline"
    _attr_entity_category = EntityCategory.CONFIG

    def __init__(self, coordinator, entry, field: str, name: str) -> None:
        super().__init__(coordinator, entry, f"dnd_{field}", name)
        self._field = field

    @property
    def native_value(self) -> time | None:
        m = self.settings.get("dnd", {}).get(self._field)
        return None if m is None else time(m // 60 % 24, m % 60)

    async def async_set_value(self, value: time) -> None:
        minutes = value.hour * 60 + value.minute
        await self._write(lambda: self.coordinator.client.set_dnd(**{self._field: minutes}))
