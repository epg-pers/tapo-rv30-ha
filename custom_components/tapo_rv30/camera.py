"""Camera entity serving the rendered map image for Tapo RV30."""
from __future__ import annotations

from typing import Any

from homeassistant.components.camera import Camera
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import TapoCoordinator
from .maprender import rotate_px, rotation_of


def _calibration_points(g: dict) -> list[dict] | None:
    """Three mm<->px reference points derived from the map geometry."""
    try:
        res, (ox, oy) = g["resolution_mm"], g["real_origin_mm"]
        gw, gh, s = g["grid_size"][0], g["grid_size"][1], g["scale_px_per_cell"]
    except (KeyError, TypeError):
        return None

    rotation = rotation_of(g.get("rotation"))

    def pt(gx, gy):
        # the centre of cell (gx, gy) in mm and in image pixels (in the turned picture)
        x, y = rotate_px(gx * s + s / 2, (gh - 1 - gy) * s + s / 2, gw * s, gh * s, rotation)
        return {"vacuum": {"x": int(ox + (gx + 0.5) * res), "y": int(oy + (gy + 0.5) * res)},
                "map": {"x": int(x), "y": int(y)}}

    return [pt(0, 0), pt(gw - 1, 0), pt(0, gh - 1)]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry,
                            async_add_entities: AddEntitiesCallback) -> None:
    async_add_entities([TapoMapCamera(hass.data[DOMAIN][entry.entry_id], entry)])


class TapoMapCamera(CoordinatorEntity[TapoCoordinator], Camera):
    """The current map: rooms, no-go zones, walls, carpets, dock and the robot.

    The robot marker is refreshed on every poll; the rest every 5 minutes.
    `room_geometry` / `map_geometry` attributes let a card map clicks and
    millimetre coordinates to image pixels.
    """
    _attr_has_entity_name = True
    _attr_name = "Map"
    # Large, and path_points changes every poll while cleaning: kept out of the recorder (the
    # card reads them from the live state), so a cleaning hour does not add megabytes of history.
    _unrecorded_attributes = frozenset({"room_geometry", "map_geometry", "rooms_last_cleaned",
                                        "calibration_points", "maps", "path_points"})
    _attr_is_streaming = False
    _attr_is_recording = False
    _attr_brand = "TP-Link"
    _attr_content_type = "image/png"

    def __init__(self, coordinator: TapoCoordinator, entry: ConfigEntry) -> None:
        CoordinatorEntity.__init__(self, coordinator)
        Camera.__init__(self)
        self._attr_unique_id = f"{entry.entry_id}_map"

    @property
    def device_info(self) -> DeviceInfo:
        return self.coordinator.device_info

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        fresh = self.coordinator.room_freshness_by_id()
        return {
            "map_id": self.coordinator.map_id,
            "map_name": self.coordinator.map_name,
            "maps": self.coordinator.maps,
            "path_points": len(self.coordinator.shown_path()),
            "rooms": [r["name"] for r in self.coordinator.room_geometry],
            "room_geometry": [{**r, **fresh.get(r.get("id"), {})} for r in self.coordinator.room_geometry],
            "rooms_last_cleaned": self.coordinator.room_freshness(),
            "last_clean": self.coordinator.last_clean_info,
            "last_clean_url": (f"/api/{DOMAIN}/{self.coordinator.entry.entry_id}/last_clean.png?v={self.coordinator.last_clean_hash}"
                               if self.coordinator.entry and self.coordinator.last_clean_image_bytes else None),
            "map_geometry": self.coordinator.map_geometry,
            # Ready-made calibration for the Xiaomi Vacuum Map Card: vacuum coords
            # here are millimetres, the frame tapo_rv30.clean_zone expects.
            "calibration_points": _calibration_points(self.coordinator.map_geometry),
            # For the bundled card: lossless room-id mask, same orientation as the image.
            "rooms_mask_url": (f"/api/{DOMAIN}/{self.coordinator.entry.entry_id}/rooms.png?v={self.coordinator.map_hash}"
                               if self.coordinator.entry and self.coordinator.room_mask else None),
        }

    async def async_camera_image(self, width: int | None = None, height: int | None = None) -> bytes | None:
        return self.coordinator.map_image_bytes
