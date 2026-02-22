"""DataUpdateCoordinator for Tapo RV30."""
from __future__ import annotations

import base64
import logging
from datetime import timedelta
from typing import Any

import lz4.block
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
from .tpap import TapoVacuumClient

_LOGGER = logging.getLogger(__name__)

MAP_SCALE = 4   # px per vacuum grid cell → ~700×700 output image
FONT_SIZE  = 14


def _b64name(s: str) -> str:
    try:
        return base64.b64decode(s).decode(errors="replace").strip()
    except Exception:
        return s


def _render_map_image(map_data: dict) -> bytes:
    """Decode LZ4 pixel data and produce a JPEG image as bytes."""
    width   = map_data["width"]
    height  = map_data["height"]
    pix_len = map_data["pix_len"]

    raw     = base64.b64decode(map_data["map_data"])
    pixels  = lz4.block.decompress(raw, uncompressed_size=pix_len)

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
        name = _b64name(room.get("name", ""))
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

    async def _async_update_data(self) -> dict[str, Any]:
        try:
            data = await self.hass.async_add_executor_job(self.client.get_status)
        except Exception as exc:
            raise UpdateFailed(f"Failed to fetch Jarvis status: {exc}") from exc

        # Refresh map on first load and every MAP_INTERVAL seconds
        self._map_tick += 1
        if self.map_image_bytes is None or self._map_tick >= self._map_cycles:
            self._map_tick = 0
            try:
                await self.hass.async_add_executor_job(self._refresh_map)
            except Exception as exc:
                _LOGGER.warning("Map refresh failed: %s", exc)

        return data

    def _refresh_map(self) -> None:
        current_id, _ = self.client.get_map_info()
        map_data       = self.client.get_map_data(current_id)
        self.map_id    = current_id
        self.rooms     = [a for a in map_data.get("area_list", [])
                          if a.get("type") == "room"]
        self.map_image_bytes = _render_map_image(map_data)
        _LOGGER.debug("Map rendered: %d bytes, %d rooms",
                      len(self.map_image_bytes), len(self.rooms))

    def resolve_room_ids(self, name_patterns: list[str]) -> list[int]:
        """Match partial room names → list of room IDs. Raises ValueError on no match."""
        matched: list[int] = []
        seen: set[int] = set()
        for pat in name_patterns:
            hits = [r for r in self.rooms
                    if pat.lower() in _b64name(r.get("name", "")).lower()]
            if not hits:
                available = [_b64name(r.get("name", "")) for r in self.rooms]
                raise ValueError(f"No room matching '{pat}'. Available: {available}")
            for r in hits:
                if r["id"] not in seen:
                    seen.add(r["id"]); matched.append(r["id"])
        return matched
