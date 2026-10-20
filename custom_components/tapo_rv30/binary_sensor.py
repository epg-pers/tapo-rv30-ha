"""Binary sensors for Tapo RV30: mop attached, do-not-disturb active."""
from __future__ import annotations

from homeassistant.components.binary_sensor import BinarySensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.util import dt as dt_util

from .const import DOMAIN
from .entity import TapoEntity
from .mapdata import dnd_active


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry,
                            async_add_entities: AddEntitiesCallback) -> None:
    c = hass.data[DOMAIN][entry.entry_id]
    entities = [TapoMopAttached(c, entry, "mop_attached", "Mop Attached")]
    if "dnd" in c.settings:
        entities.append(TapoDndActive(c, entry, "dnd_active", "Do Not Disturb Active"))
    async_add_entities(entities)


class TapoMopAttached(TapoEntity, BinarySensorEntity):
    _attr_icon = "mdi:water"

    @property
    def is_on(self) -> bool | None:
        d = self.coordinator.data
        return None if d is None else bool(d.get("mop_attached"))


class TapoDndActive(TapoEntity, BinarySensorEntity):
    """On while the robot's do-not-disturb window is in effect (it then won't
    auto-empty or run schedules). Uses HA's local time, like the app."""
    _attr_icon = "mdi:bell-sleep"

    @property
    def is_on(self) -> bool | None:
        dnd = self.settings.get("dnd")
        if dnd is None:
            return None
        now = dt_util.now()
        return dnd_active(dnd, now.hour * 60 + now.minute)
