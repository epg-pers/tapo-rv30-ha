"""Sensor entities for Tapo RV30."""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Callable

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import PERCENTAGE, EntityCategory, UnitOfTime
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import (
    CONSUMABLE_LABELS,
    CONSUMABLE_LIMITS_H,
    DOMAIN,
    ERROR_CODES,
    STATUS_LABELS,
)
from .coordinator import TapoCoordinator
from .mapdata import matter_state

_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class TapoSensorDescription(SensorEntityDescription):
    value_fn: Callable[[dict], Any] = lambda d: None
    attrs_fn: Callable[[dict], dict] | None = None
    unit_fn: Callable[[dict], str | None] | None = None


def _area_unit(d: dict) -> str:
    return {0: "m²", 1: "ft²", 2: "坪"}.get(d.get("area_unit", 0), "m²")


_PROGRESS_SENSOR = TapoSensorDescription(
    key="clean_progress", name="Clean Progress", icon="mdi:progress-check",
    native_unit_of_measurement=PERCENTAGE, state_class=SensorStateClass.MEASUREMENT,
    value_fn=lambda d: d.get("clean_percent"),
)


def _used_h(field: str) -> TapoSensorDescription:
    # App doesn't expose these parts' service intervals to us, so report hours used.
    label = {"main_brush_lid_time": "Main Brush Lid", "rag_time": "Mop Cloth"}[field]
    return TapoSensorDescription(
        key=f"consumable_{field}_used", name=f"{label} Used", icon="mdi:wrench-clock",
        native_unit_of_measurement=UnitOfTime.HOURS, state_class=SensorStateClass.MEASUREMENT,
        value_fn=lambda d: (None if d.get("consumables", {}).get(field) is None
                            else round(d["consumables"][field] / 60, 1)),
    )


def _records(d: dict) -> dict:
    return d.get("settings", {}).get("records") or {}


def _last_record(d: dict) -> dict:
    return max(_records(d).get("record_list") or [{}], key=lambda r: r.get("timestamp", 0))


_LAST_CLEAN_SENSOR = TapoSensorDescription(
    key="last_clean", name="Last Clean", icon="mdi:history",
    device_class=SensorDeviceClass.TIMESTAMP,
    value_fn=lambda d: (datetime.fromtimestamp(_last_record(d)["timestamp"], tz=UTC)
                        if _last_record(d).get("timestamp") else None),
    attrs_fn=lambda d: {
        "area_m2": _last_record(d).get("clean_area"),
        "minutes": _last_record(d).get("clean_time"),
        "emptied_bin": _last_record(d).get("dust_collection"),
        "ended_with_error": bool(_last_record(d).get("error")),
        "total_runs": _records(d).get("total_number"),
        "total_area_m2": _records(d).get("total_area"),
        "total_hours": round((_records(d).get("total_time") or 0) / 60, 1),
    },
)


_CURRENT_ROOM_SENSOR = TapoSensorDescription(
    key="current_room", translation_key="current_room", name="Current Room",
    # Inferred from the vacuum's map position; refreshed every poll.
    value_fn=lambda d: d.get("current_room"),
)

_SCHEDULES_SENSOR = TapoSensorDescription(
    key="schedules", translation_key="schedules", name="Schedules",
    # Count of schedules saved in the Tapo app; the decoded list is in the attributes.
    value_fn=lambda d: len(d.get("schedules") or []),
    attrs_fn=lambda d: {"schedules": d.get("schedules") or []},
)


_TOTAL_RUNS = TapoSensorDescription(
    key="total_runs", name="Total Cleans", icon="mdi:counter",
    state_class=SensorStateClass.TOTAL_INCREASING,
    value_fn=lambda d: _records(d).get("total_number"),
)
_TOTAL_AREA = TapoSensorDescription(
    key="total_area", name="Total Area Cleaned", icon="mdi:texture-box",
    state_class=SensorStateClass.TOTAL_INCREASING, value_fn=lambda d: _records(d).get("total_area"),
    unit_fn=_area_unit,
)
_TOTAL_TIME = TapoSensorDescription(
    key="total_time", name="Total Cleaning Time", icon="mdi:timer-outline",
    native_unit_of_measurement=UnitOfTime.HOURS, device_class=SensorDeviceClass.DURATION,
    state_class=SensorStateClass.TOTAL_INCREASING,
    value_fn=lambda d: (None if _records(d).get("total_time") is None else round(_records(d)["total_time"] / 60, 2)),
)


def _matter(d: dict) -> dict:
    return matter_state((d.get("settings") or {}).get("matter_status"), d.get("settings_read_at"), time.time())


_MATTER_SENSOR = TapoSensorDescription(
    key="matter", translation_key="matter", name="Matter",
    entity_category=EntityCategory.DIAGNOSTIC, entity_registry_enabled_default=False,
    # Not paired / Pairing window open / Paired. The setup code and QR payload are the
    # robot's fixed ones (printed on it); they are attributes here so you can pair from
    # another ecosystem, which is also why the sensor is off by default.
    value_fn=lambda d: _matter(d)["state"],
    attrs_fn=lambda d: {**_matter(d), **{k: v for k, v in ((d.get("settings") or {}).get("matter_setup") or {}).items()
                                        if k in ("setup_code", "setup_payload")}},
)


_MATTER_CODE_SENSOR = TapoSensorDescription(
    key="matter_setup_code", translation_key="matter_setup_code", name="Matter Setup Code",
    entity_category=EntityCategory.DIAGNOSTIC, entity_registry_enabled_default=False,
    # The robot's fixed manual pairing code as the state, the QR payload as an attribute.
    value_fn=lambda d: ((d.get("settings") or {}).get("matter_setup") or {}).get("setup_code"),
    attrs_fn=lambda d: {"setup_payload": ((d.get("settings") or {}).get("matter_setup") or {}).get("setup_payload")},
)


_WIFI_SENSOR = TapoSensorDescription(
    key="wifi_signal", name="Wi-Fi Signal", icon="mdi:wifi",
    native_unit_of_measurement="dBm", device_class=SensorDeviceClass.SIGNAL_STRENGTH,
    state_class=SensorStateClass.MEASUREMENT, entity_category=EntityCategory.DIAGNOSTIC,
    entity_registry_enabled_default=False,
    value_fn=lambda d: d.get("rssi"),
)


_STATUS_SENSOR = TapoSensorDescription(
    key="status", translation_key="status",
    name="Status",
    value_fn=lambda d: STATUS_LABELS.get(d.get("status_code", 0), f"Code({d.get('status_code')})"),
)

_BATTERY_SENSOR = TapoSensorDescription(
    key="battery",
    name="Battery",
    native_unit_of_measurement=PERCENTAGE,
    device_class=SensorDeviceClass.BATTERY,
    state_class=SensorStateClass.MEASUREMENT,
    value_fn=lambda d: d.get("battery"),
)

_ERROR_SENSOR = TapoSensorDescription(
    key="error", translation_key="error",
    name="Error",
    value_fn=lambda d: ERROR_CODES.get(
        (d.get("error_codes") or [0])[0], f"Code({(d.get('error_codes') or [0])[0]})"
    ),
)

_AREA_SENSOR = TapoSensorDescription(
    key="clean_area",
    name="Last Clean Area",
    icon="mdi:texture-box",
    state_class=SensorStateClass.MEASUREMENT,
    value_fn=lambda d: d.get("clean_area"),
    unit_fn=_area_unit,
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

    entities: list[SensorEntity] = [
        TapoStatusSensor(coordinator, entry, _STATUS_SENSOR),
        TapoStatusSensor(coordinator, entry, _BATTERY_SENSOR),
        TapoStatusSensor(coordinator, entry, _ERROR_SENSOR),
        TapoStatusSensor(coordinator, entry, _AREA_SENSOR),
        TapoStatusSensor(coordinator, entry, _PROGRESS_SENSOR),
        TapoStatusSensor(coordinator, entry, _LAST_CLEAN_SENSOR),
        TapoStatusSensor(coordinator, entry, _TOTAL_RUNS),
        TapoStatusSensor(coordinator, entry, _TOTAL_AREA),
        TapoStatusSensor(coordinator, entry, _TOTAL_TIME),
        TapoStatusSensor(coordinator, entry, _WIFI_SENSOR),
        TapoStatusSensor(coordinator, entry, _CURRENT_ROOM_SENSOR),
        TapoStatusSensor(coordinator, entry, _SCHEDULES_SENSOR),
        TapoStatusSensor(coordinator, entry, _used_h("main_brush_lid_time")),
        TapoStatusSensor(coordinator, entry, _used_h("rag_time")),
    ]
    if coordinator.has("matter") and "matter_status" in coordinator.settings:
        entities.append(TapoStatusSensor(coordinator, entry, _MATTER_SENSOR))
    if coordinator.has("matter") and "matter_setup" in coordinator.settings:
        entities.append(TapoStatusSensor(coordinator, entry, _MATTER_CODE_SENSOR))

    for ckey, clabel in CONSUMABLE_LABELS.items():
        entities.append(
            TapoConsumableSensor(coordinator, entry, ckey, clabel)
        )

    async_add_entities(entities)


class TapoStatusSensor(CoordinatorEntity[TapoCoordinator], SensorEntity):
    _attr_has_entity_name = True

    def __init__(self, coordinator, entry, desc: TapoSensorDescription) -> None:
        super().__init__(coordinator)
        self.entity_description = desc
        self._attr_unique_id    = f"{entry.entry_id}_{desc.key}"
        self._entry             = entry

    @property
    def device_info(self):
        return self.coordinator.device_info

    @property
    def native_value(self) -> Any:
        d = self.coordinator.data
        if d is None:
            return None
        return self.entity_description.value_fn(d)

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        fn = self.entity_description.attrs_fn
        return fn(self.coordinator.data) if fn and self.coordinator.data else None

    @property
    def native_unit_of_measurement(self) -> str | None:
        fn = self.entity_description.unit_fn
        if fn and self.coordinator.data:
            return fn(self.coordinator.data)
        return self.entity_description.native_unit_of_measurement


class TapoConsumableSensor(CoordinatorEntity[TapoCoordinator], SensorEntity):
    """Sensor showing hours remaining on a consumable part."""
    _attr_has_entity_name            = True
    _attr_native_unit_of_measurement = UnitOfTime.HOURS
    _attr_state_class                = SensorStateClass.MEASUREMENT

    def __init__(self, coordinator, entry, ckey: str, label: str) -> None:
        super().__init__(coordinator)
        self._ckey             = ckey
        self._limit_h          = CONSUMABLE_LIMITS_H[ckey]
        self._attr_name        = f"{label} Remaining"
        self._attr_unique_id   = f"{entry.entry_id}_consumable_{ckey}"
        self._attr_icon        = "mdi:wrench"
        self._entry            = entry

    @property
    def device_info(self):
        return self.coordinator.device_info

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
