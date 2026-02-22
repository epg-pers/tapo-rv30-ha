"""Sensor entities for Tapo RV30."""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Callable

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import PERCENTAGE, UnitOfTime
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import (
    CONSUMABLE_LABELS,
    CONSUMABLE_LIMITS_H,
    DOMAIN,
    VACUUM_STATES,
    WATER_INT_TO_NAME,
    FAN_INT_TO_NAME,
)
from .coordinator import TapoCoordinator

_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class TapoSensorDescription(SensorEntityDescription):
    value_fn: Callable[[dict], Any] = lambda d: None


_STATUS_SENSOR = TapoSensorDescription(
    key="status",
    name="Status",
    icon="mdi:robot-vacuum",
    value_fn=lambda d: VACUUM_STATES.get(d.get("status_code", 0), "idle").replace("_", " ").title(),
)

_BATTERY_SENSOR = TapoSensorDescription(
    key="battery",
    name="Battery",
    native_unit_of_measurement=PERCENTAGE,
    device_class=SensorDeviceClass.BATTERY,
    state_class=SensorStateClass.MEASUREMENT,
    value_fn=lambda d: d.get("battery"),
)

_AREA_SENSOR = TapoSensorDescription(
    key="clean_area",
    name="Last Clean Area",
    icon="mdi:texture-box",
    native_unit_of_measurement="m²",
    state_class=SensorStateClass.MEASUREMENT,
    value_fn=lambda d: d.get("clean_area"),
)


def _consumable_descriptions() -> list[TapoSensorDescription]:
    descs = []
    icons = {
        "roll_brush_time":     "mdi:brush",
        "edge_brush_time":     "mdi:rotate-right",
        "filter_time":         "mdi:air-filter",
        "sensor_time":         "mdi:eye",
        "charge_contact_time": "mdi:lightning-bolt",
    }
    for key, label in CONSUMABLE_LABELS.items():
        descs.append(TapoSensorDescription(
            key=f"consumable_{key}",
            name=f"{label} Remaining",
            icon=icons.get(key, "mdi:wrench"),
            native_unit_of_measurement=UnitOfTime.HOURS,
            state_class=SensorStateClass.MEASUREMENT,
            # value_fn filled in below via closure
        ))
    return descs


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: TapoCoordinator = hass.data[DOMAIN][entry.entry_id]
    device_info = {
        "identifiers": {(DOMAIN, entry.entry_id)},
        "name": "Jarvis",
        "manufacturer": "TP-Link",
        "model": "Tapo RV30 Max Plus",
    }

    entities: list[SensorEntity] = [
        TapoStatusSensor(coordinator, entry, _STATUS_SENSOR, device_info),
        TapoStatusSensor(coordinator, entry, _BATTERY_SENSOR, device_info),
        TapoStatusSensor(coordinator, entry, _AREA_SENSOR, device_info),
    ]

    for ckey, clabel in CONSUMABLE_LABELS.items():
        entities.append(
            TapoConsumableSensor(coordinator, entry, ckey, clabel, device_info)
        )

    async_add_entities(entities)


class TapoStatusSensor(CoordinatorEntity[TapoCoordinator], SensorEntity):
    _attr_has_entity_name = True

    def __init__(self, coordinator, entry, desc: TapoSensorDescription, device_info) -> None:
        super().__init__(coordinator)
        self.entity_description  = desc
        self._attr_unique_id     = f"{entry.entry_id}_{desc.key}"
        self._attr_device_info   = device_info

    @property
    def native_value(self) -> Any:
        d = self.coordinator.data
        if d is None:
            return None
        return self.entity_description.value_fn(d)


class TapoConsumableSensor(CoordinatorEntity[TapoCoordinator], SensorEntity):
    """Sensor showing hours remaining on a consumable part."""
    _attr_has_entity_name            = True
    _attr_native_unit_of_measurement = UnitOfTime.HOURS
    _attr_state_class                = SensorStateClass.MEASUREMENT

    def __init__(self, coordinator, entry, ckey: str, label: str, device_info) -> None:
        super().__init__(coordinator)
        self._ckey                = ckey
        self._limit_h             = CONSUMABLE_LIMITS_H[ckey]
        self._attr_name           = f"{label} Remaining"
        self._attr_unique_id      = f"{entry.entry_id}_consumable_{ckey}"
        self._attr_device_info    = device_info
        self._attr_icon           = "mdi:wrench"

    @property
    def native_value(self) -> float | None:
        d = self.coordinator.data
        if not d:
            return None
        raw = d.get("consumables", {}).get(self._ckey)
        if raw is None:
            return None
        return round(max(0.0, self._limit_h - raw / 60), 1)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        d = self.coordinator.data
        if not d:
            return {}
        raw = d.get("consumables", {}).get(self._ckey)
        if raw is None:
            return {}
        used_h = raw / 60
        return {
            "used_hours":   round(used_h, 1),
            "limit_hours":  self._limit_h,
            "percent_used": min(100, round(used_h / self._limit_h * 100, 1)),
        }
