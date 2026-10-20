"""DataUpdateCoordinator for Tapo RV30."""
from __future__ import annotations

import asyncio
import base64
import logging
from datetime import timedelta
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from PIL import Image, ImageDraw, ImageFont

from .const import (
    DOMAIN,
    FAST_INTERVAL,
    MAP_INTERVAL,
    ROOM_PALETTE,
    WALL_COLOR,
    UNKNOWN_COLOR,
    FLOOR_COLOR,
)
from .mapdata import (
    MapNotFound, RoomNotFound, b64name, decode_schedule, lz4_block_decompress, resolve_rooms,
    room_at_vac,
)
from .tpap import TapoVacuumClient

_LOGGER = logging.getLogger(__name__)

MAP_SCALE = 4   # px per vacuum grid cell -> ~700x700 output image
FONT_SIZE = 14


def _render_map_image(map_data: dict) -> bytes:
    """Decode LZ4 pixel data and produce a JPEG image as bytes."""
    width   = map_data["width"]
    height  = map_data["height"]
    pix_len = map_data["pix_len"]

    raw     = base64.b64decode(map_data["map_data"])
    pixels  = lz4_block_decompress(raw, uncompressed_size=pix_len)

    rooms = [a for a in map_data.get("area_list", []) if a.get("type") == "room"]
    sorted_ids  = sorted(r["id"] for r in rooms)
    room_colors = {rid: ROOM_PALETTE[i % len(ROOM_PALETTE)]
                   for i, rid in enumerate(sorted_ids)}

    # Build colour lookup table (0-255)
    lut: list[tuple[int, int, int]] = [UNKNOWN_COLOR] * 256
    lut[0]   = WALL_COLOR
    lut[127] = UNKNOWN_COLOR
    lut[255] = FLOOR_COLOR
    for rid, color in room_colors.items():
        if 0 <= rid <= 255:
            lut[rid] = color

    img = Image.new("RGB", (width * MAP_SCALE, height * MAP_SCALE))
    draw = ImageDraw.Draw(img)

    # Draw pixels — rows bottom→top, cols left→right
    for row in range(height - 1, -1, -1):
        for col in range(width):
            pv    = pixels[row * width + col]
            color = lut[pv] if pv < 256 else UNKNOWN_COLOR
            screen_row = (height - 1 - row) * MAP_SCALE
            screen_col = col * MAP_SCALE
            draw.rectangle(
                [screen_col, screen_row,
                 screen_col + MAP_SCALE - 1, screen_row + MAP_SCALE - 1],
                fill=color,
            )

    # Room name labels centred in each room
    try:
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
                                  FONT_SIZE)
    except Exception:
        font = ImageFont.load_default()

    for room in rooms:
        rid = room["id"]
        if rid not in room_colors:
            continue
        name = b64name(room.get("name", ""))
        # Find centroid of all pixels belonging to this room
        xs, ys = [], []
        for row in range(height):
            for col in range(width):
                if pixels[row * width + col] == rid:
                    xs.append(col)
                    ys.append(row)
        if not xs:
            continue
        cx = int(sum(xs) / len(xs)) * MAP_SCALE + MAP_SCALE // 2
        cy = int((height - 1 - (sum(ys) / len(ys)))) * MAP_SCALE + MAP_SCALE // 2

        # Shadow + white label
        draw.text((cx + 1, cy + 1), name, fill=(0, 0, 0, 180), font=font, anchor="mm")
        draw.text((cx, cy),         name, fill=(255, 255, 255), font=font, anchor="mm")

    # Charger and vacuum markers
    charge = map_data.get("charge_coor")
    vac    = map_data.get("vac_coor")

    def _dot(gx, gy, color, radius=6):
        sx = gx * MAP_SCALE + MAP_SCALE // 2
        sy = (height - 1 - gy) * MAP_SCALE + MAP_SCALE // 2
        draw.ellipse([sx - radius, sy - radius, sx + radius, sy + radius],
                     fill=color, outline=(255, 255, 255), width=2)

    if charge:
        _dot(charge[0], charge[1], (255, 200, 0))   # amber = dock
    if vac:
        _dot(vac[0], vac[1], (0, 180, 255))          # cyan = vacuum

    import io
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=85)
    return buf.getvalue()


class TapoCoordinator(DataUpdateCoordinator):
    """Polls Jarvis for status + periodically re-renders map."""

    def __init__(self, hass: HomeAssistant, client: TapoVacuumClient) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=FAST_INTERVAL),
        )
        self.client          = client
        self._map_tick       = 0      # counts update cycles; refresh map every N
        self._map_cycles     = MAP_INTERVAL // FAST_INTERVAL
        self.map_image_bytes: bytes | None = None
        self.rooms:  list[dict] = []   # current rooms (area_list, type==room)
        self.map_id: int | None = None # current map_id
        self.device_name:  str = "Tapo RV30"
        self._name_fetched = False
        self.settings: dict = {}       # get_settings(), refreshed with the map
        self.schedules: list[dict] = []
        self.vac_pos: list | None = None
        self.current_room: str | None = None

    async def _async_update_data(self) -> dict[str, Any]:
        if not self._name_fetched:
            try:
                self.device_name = await self.hass.async_add_executor_job(
                    self.client.get_nickname
                )
                self._name_fetched = True
            except Exception:
                pass

        try:
            data = await self.hass.async_add_executor_job(self.client.get_status)
        except Exception as exc:
            raise UpdateFailed(f"Failed to fetch vacuum status: {exc}") from exc

        try:
            data["consumables"] = await self.hass.async_add_executor_job(
                self.client.get_consumables
            )
        except Exception as exc:
            _LOGGER.debug("Consumables fetch failed: %s", exc)
            data["consumables"] = {}

        # Refresh map on first load and every MAP_INTERVAL seconds; in between,
        # re-read the map data (no re-render) so position and current room track.
        self._map_tick += 1
        if self.map_image_bytes is None or self._map_tick >= self._map_cycles:
            self._map_tick = 0
            try:
                await self.hass.async_add_executor_job(self._refresh_map)
            except Exception as exc:
                # The robot refuses map data while manoeuvring (-3016); with a
                # map already rendered that is routine, so keep it out of the log.
                if self.map_image_bytes is None:
                    _LOGGER.warning("Map refresh failed: %s", exc)
                else:
                    _LOGGER.debug("Map refresh skipped: %s", exc)
                    self._map_tick = self._map_cycles - 1   # try again next poll
            self.settings = await self.hass.async_add_executor_job(self.client.get_settings)
            self._decode_schedules()
        elif self.map_id is not None:
            try:
                await self.hass.async_add_executor_job(self._refresh_position)
            except Exception as exc:
                _LOGGER.debug("Position refresh failed: %s", exc)

        data["settings"] = self.settings
        data["schedules"] = self.schedules
        data["current_room"] = self.current_room
        data["position_mm"] = self.vac_pos
        return data

    def _decode_schedules(self) -> None:
        names = {r["id"]: b64name(r.get("name", "")) for r in self.rooms}
        rules = (self.settings.get("schedules") or {}).get("rule_list") or []
        self.schedules = [decode_schedule(r, names) for r in rules]

    def _refresh_position(self) -> None:
        map_data = self.client.get_map_data(self.map_id)
        self.vac_pos = map_data.get("real_vac_coor")
        self.current_room = room_at_vac(map_data)

    async def async_settings_changed(self) -> None:
        """Re-read settings right after a write so switches don't wait for the slow cycle."""
        self.settings = await self.hass.async_add_executor_job(self.client.get_settings)
        self._decode_schedules()
        if self.data is not None:
            self.data["settings"] = self.settings
            self.data["schedules"] = self.schedules
        self.async_update_listeners()

    def _refresh_map(self) -> None:
        current_id, _ = self.client.get_map_info()
        map_data       = self.client.get_map_data(current_id)
        self.map_id    = current_id
        self.vac_pos   = map_data.get("real_vac_coor")
        self.current_room = room_at_vac(map_data)
        self.rooms     = [a for a in map_data.get("area_list", [])
                          if a.get("type") == "room"]
        self.map_image_bytes = _render_map_image(map_data)
        _LOGGER.debug("Map rendered: %d bytes, %d rooms",
                      len(self.map_image_bytes), len(self.rooms))

    async def async_refresh_soon(self) -> None:
        """Re-poll at 2, 5 and 10 s after a command.

        The robot takes a few seconds to report its new status and the normal poll
        is 30 s, so without this every UI shows the old state for up to 30 s.
        """
        async def _poll() -> None:
            for delay in (2, 3, 5):
                await asyncio.sleep(delay)
                await self.async_refresh()
        self.hass.async_create_task(_poll())

    def map_names(self) -> dict[int, str]:
        """{map_id: name} for every map stored on the vacuum."""
        _, map_list = self.client.get_map_info()
        return {m["map_id"]: b64name(m.get("map_name", "")) for m in map_list}

    def list_rooms_all_maps(self) -> list[tuple[int, str, list[tuple[int, str]]]]:
        """[(map_id, map_name, [(room_id, room_name), ...]), ...] read live."""
        out = []
        for map_id, map_name in self.map_names().items():
            map_data = self.client.get_map_data(map_id)
            rooms = [(a["id"], b64name(a.get("name", "")))
                     for a in map_data.get("area_list", []) if a.get("type") == "room"]
            out.append((map_id, map_name, rooms))
        return out

    def resolve_rooms_live(
        self, name_patterns: list[str], map_name: str | None = None
    ) -> tuple[list[int], int]:
        """Fetch rooms live from device, resolve names -> (room_ids, map_id).

        Uses map_name (partial match) if given, otherwise current map. Names are
        normalised with _norm() first. Raises MapNotFound / RoomNotFound (both
        ValueError) with the available names in the message.
        """
        current_map_id, map_list = self.client.get_map_info()
        map_names = {m["map_id"]: b64name(m.get("map_name", "")) for m in map_list}

        if map_name is not None:
            wanted = _norm(map_name)
            if not wanted:
                raise MapNotFound(
                    "'map' was given but is empty after trimming; omit it to use the "
                    f"current map. Available maps: {sorted(map_names.values())}"
                )
            exact = [mid for mid, n in map_names.items() if n.lower() == wanted.lower()]
            partial = [mid for mid, n in map_names.items() if wanted.lower() in n.lower()]
            hits = exact or partial
            if not hits:
                raise MapNotFound(
                    f"Map '{wanted}' not found on the vacuum. "
                    f"Available maps: {sorted(map_names.values())}"
                )
            if len(hits) > 1:
                raise MapNotFound(
                    f"Map '{wanted}' is ambiguous, matches: "
                    f"{sorted(map_names[m] for m in hits)}"
                )
            target_id = hits[0]
        else:
            target_id = current_map_id

        map_data = self.client.get_map_data(target_id)
        rooms = [a for a in map_data.get("area_list", []) if a.get("type") == "room"]
        decoded = [b64name(r.get("name", "")) for r in rooms]
        target_name = map_names.get(target_id, str(target_id))

        matched: list[int] = []
        seen: set[int] = set()
        for raw in name_patterns:
            pat = _norm(raw)
            if not pat:
                raise RoomNotFound(
                    f"Empty room name in 'rooms' on map '{target_name}'. "
                    f"Available rooms: {decoded}"
                )
            exact = [r for r, n in zip(rooms, decoded) if n.lower() == pat.lower()]
            hits = exact or [r for r, n in zip(rooms, decoded) if pat.lower() in n.lower()]
            if not hits:
                raise RoomNotFound(
                    f"No room matching '{pat}' on map '{target_name}'. "
                    f"Available rooms: {decoded}"
                )
            for r in hits:
                if r["id"] not in seen:
                    seen.add(r["id"]); matched.append(r["id"])

        return matched, target_id
