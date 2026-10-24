"""Binary sensors for Tapo RV30: mop attached, do-not-disturb active."""
from __future__ import annotations

from homeassistant.components.binary_sensor import BinarySensorDeviceClass, BinarySensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import CONSUMABLE_LABELS, CONSUMABLE_LIMITS_H, CONSUMABLE_WARN_FRACTION, DOMAIN, ERROR_CODES
from .entity import TapoEntity
from .mapdata import dnd_active


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry,
                            async_add_entities: AddEntitiesCallback) -> None:
    c = hass.data[DOMAIN][entry.entry_id]
    entities = [TapoCharging(c, entry, "charging", "Charging"),
                TapoProblem(c, entry, "problem", "Problem")]
    entities += [TapoConsumableWarn(c, entry, key, label) for key, label in CONSUMABLE_LABELS.items()
                 if c.has_part(key)]
    if c.has("mop"):
        entities.append(TapoMopAttached(c, entry, "mop_attached", "Mop Attached"))
    if "dnd" in c.settings:
        entities.append(TapoDndActive(c, entry, "dnd_active", "Do Not Disturb Active"))
    async_add_entities(entities)


class TapoCharging(TapoEntity, BinarySensorEntity):
    _attr_device_class = BinarySensorDeviceClass.BATTERY_CHARGING
    _attr_translation_key = "charging"

    @property
    def is_on(self) -> bool | None:
        d = self.coordinator.data
        return None if d is None else bool(d.get("charging"))


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
        now = self.coordinator.robot_now()     # DND times are in the robot's own region
        return dnd_active(dnd, now.hour * 60 + now.minute)


class TapoProblem(TapoEntity, BinarySensorEntity):
    """On while the robot reports an error (dust bin removed, trapped, ...)."""
    _attr_device_class = BinarySensorDeviceClass.PROBLEM
    _attr_translation_key = "problem"

    def _code(self) -> int:
        d = self.coordinator.data or {}
        return (d.get("error_codes") or [0])[0]

    @property
    def is_on(self) -> bool | None:
        return None if self.coordinator.data is None else self._code() != 0

    @property
    def extra_state_attributes(self) -> dict:
        code = self._code()
        return {"code": code, "error": ERROR_CODES.get(code, f"Code({code})") if code else None}


class TapoConsumableWarn(TapoEntity, BinarySensorEntity):
    """On when a consumable has less than 10% of its service life left."""
    _attr_device_class = BinarySensorDeviceClass.PROBLEM
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_icon = "mdi:wrench-clock"

    def __init__(self, coordinator, entry, ckey: str, label: str) -> None:
        super().__init__(coordinator, entry, f"replace_{ckey}", f"Replace {label}")
        self._ckey = ckey
        self._limit = CONSUMABLE_LIMITS_H[ckey]

    @property
    def is_on(self) -> bool | None:
        raw = ((self.coordinator.data or {}).get("consumables") or {}).get(self._ckey)
        if raw is None:
            return None
        return (self._limit - raw / 60) <= self._limit * CONSUMABLE_WARN_FRACTION
