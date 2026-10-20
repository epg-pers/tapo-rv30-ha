"""Vacuum entity for Tapo RV30."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.components.vacuum import (
    Segment,
    StateVacuumEntity,
    VacuumActivity,
    VacuumEntityFeature,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import (
    DOMAIN,
    FAN_INT_TO_NAME,
    FAN_NAME_TO_INT,
    FAN_SPEED_LIST,
    VACUUM_STATES,
    WATER_INT_TO_NAME,
)
from .coordinator import TapoCoordinator, _b64name

_LOGGER = logging.getLogger(__name__)

_FEATURES = (
    VacuumEntityFeature.START
    | VacuumEntityFeature.PAUSE
    | VacuumEntityFeature.STOP
    | VacuumEntityFeature.RETURN_HOME
    | VacuumEntityFeature.FAN_SPEED
    | VacuumEntityFeature.STATE
    | VacuumEntityFeature.MAP
    | VacuumEntityFeature.LOCATE
    | VacuumEntityFeature.CLEAN_SPOT
    | VacuumEntityFeature.CLEAN_AREA
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator: TapoCoordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([TapoVacuumEntity(coordinator, entry)])


class TapoVacuumEntity(CoordinatorEntity[TapoCoordinator], StateVacuumEntity):
    _attr_has_entity_name = True
    _attr_name            = None   # use device name as entity name
    _attr_supported_features = _FEATURES
    _attr_fan_speed_list     = FAN_SPEED_LIST

    def __init__(self, coordinator: TapoCoordinator, entry: ConfigEntry) -> None:
        super().__init__(coordinator)
        self._entry          = entry
        self._attr_unique_id = f"{entry.entry_id}_vacuum"

    @property
    def device_info(self):
        return {
            "identifiers": {(DOMAIN, self._entry.entry_id)},
            "name":        self.coordinator.device_name,
            "manufacturer":"TP-Link",
            "model":       "Tapo RV30 Max Plus",
        }

    @property
    def activity(self) -> VacuumActivity | None:
        d = self.coordinator.data
        if d is None:
            return None
        return VacuumActivity(VACUUM_STATES.get(d.get("status_code", 0), "idle"))

    @property
    def fan_speed(self) -> str | None:
        d = self.coordinator.data
        if d is None:
            return None
        return FAN_INT_TO_NAME.get(d.get("suction", 4), "Max").capitalize()

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        d = self.coordinator.data or {}
        rooms = [_b64name(r.get("name", "")) for r in self.coordinator.rooms]
        return {
            "water_level":   WATER_INT_TO_NAME.get(d.get("cistern", 0), "off"),
            "clean_passes":  d.get("clean_number", 1),
            "mop_attached":  d.get("mop_attached", False),
            "clean_area":    d.get("clean_area", 0),
            "clean_time_min":d.get("clean_time", 0),
            "clean_percent": d.get("clean_percent", 0),
            "rooms":         rooms,
            "position_mm":   (self.coordinator.vac_pos or [None, None])[:2],
            "integration":   DOMAIN,
        }

    async def async_start(self) -> None:
        await self.hass.async_add_executor_job(self.coordinator.client.start)
        await self.coordinator.async_refresh_soon()

    async def async_pause(self) -> None:
        await self.hass.async_add_executor_job(self.coordinator.client.pause)
        await self.coordinator.async_refresh_soon()

    async def async_stop(self, **kwargs: Any) -> None:
        await self.hass.async_add_executor_job(self.coordinator.client.stop)
        await self.coordinator.async_refresh_soon()

    async def async_clean_spot(self, **kwargs: Any) -> None:
        await self.hass.async_add_executor_job(self.coordinator.client.clean_spot)
        await self.coordinator.async_refresh_soon()

    async def async_locate(self, **kwargs: Any) -> None:
        await self.hass.async_add_executor_job(self.coordinator.client.locate)

    # ---- vacuum.clean_area (HA 2026.2+) --------------------------------------
    # Segment ids are "<map_id>:<room_id>" because room ids restart at 1 on every
    # map; the map name goes in Segment.group so the mapping UI can tell them apart.

    async def async_get_segments(self) -> list[Segment]:
        try:
            maps = await self.hass.async_add_executor_job(self.coordinator.list_rooms_all_maps)
        except Exception as exc:
            raise HomeAssistantError(f"Could not read maps from the vacuum: {exc}") from exc
        return [
            Segment(id=f"{map_id}:{room_id}", name=room_name, group=map_name)
            for map_id, map_name, rooms in maps
            for room_id, room_name in rooms
        ]

    async def async_clean_segments(self, segment_ids: list[str], **kwargs: Any) -> None:
        by_map: dict[int, list[int]] = {}
        for seg in segment_ids:
            try:
                map_id, room_id = (int(p) for p in seg.split(":", 1))
            except ValueError as exc:
                raise ServiceValidationError(f"Unknown segment id '{seg}'") from exc
            by_map.setdefault(map_id, []).append(room_id)
        if len(by_map) > 1:
            names = await self.hass.async_add_executor_job(self.coordinator.map_names)
            raise ServiceValidationError(
                "The selected areas are on different maps "
                f"({', '.join(names.get(m, str(m)) for m in by_map)}); "
                "the vacuum can only clean rooms on one map per run"
            )
        (map_id, room_ids), = by_map.items()
        try:
            await self.hass.async_add_executor_job(
                self.coordinator.client.clean_rooms, room_ids, map_id
            )
        except Exception as exc:
            raise HomeAssistantError(f"Vacuum rejected the command: {exc}") from exc
        await self.coordinator.async_refresh_soon()

    async def async_return_to_base(self, **kwargs: Any) -> None:
        await self.hass.async_add_executor_job(self.coordinator.client.dock)
        await self.coordinator.async_refresh_soon()

    async def async_set_fan_speed(self, fan_speed: str, **kwargs: Any) -> None:
        value = FAN_NAME_TO_INT.get(fan_speed.lower())
        if value is None:
            _LOGGER.error("Unknown fan speed: %s", fan_speed)
            return
        await self.hass.async_add_executor_job(self.coordinator.client.set_fan_speed, value)
        await self.coordinator.async_refresh_soon()
