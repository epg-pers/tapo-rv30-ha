"""Map rendering: LZ4 pixel grid -> annotated JPEG, plus the geometry a card
needs to place its own overlays. No Home Assistant imports."""
from __future__ import annotations

import base64
import io

from PIL import Image, ImageDraw, ImageFont

from .const import (
    CARPET_COLOR, FLOOR_COLOR, FORBID_COLOR, FORBID_OUTLINE, FURNITURE_OUTLINE, FURNITURE_TYPES, ROOM_PALETTE,
    UNKNOWN_COLOR, VIRTUAL_WALL_COLOR, WALL_COLOR, ZONE_OUTLINE,
)
from .mapdata import decode_path, b64name, lz4_block_decompress, mm_to_grid, validate_map

MAP_SCALE = 4   # px per vacuum grid cell -> ~700x700 output image
FONT_SIZE = 14


def _font():
    try:
        return ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", FONT_SIZE)
    except Exception:
        return ImageFont.load_default()


def _px_transform(map_data: dict):
    """Return mm -> image px function for this map (Y grows upwards in the grid,
    downwards in the image)."""
    height = map_data["height"]

    def to_px(x_mm: float, y_mm: float) -> tuple[float, float]:
        gx, gy = mm_to_grid(map_data, x_mm, y_mm)
        return gx * MAP_SCALE + MAP_SCALE / 2, (height - 1 - gy) * MAP_SCALE + MAP_SCALE / 2

    return to_px


def _grid_px(gx: float, gy: float, height: int) -> tuple[int, int]:
    return int(gx * MAP_SCALE + MAP_SCALE // 2), int((height - 1 - gy) * MAP_SCALE + MAP_SCALE // 2)


def render_map(map_data: dict) -> tuple[Image.Image, list[dict], dict]:
    """Decode the LZ4 pixel grid and draw rooms, no-go zones, virtual walls,
    carpets, saved zones, furniture, labels and the dock.

    Returns (base image without the vacuum marker, room_geometry, map_geometry).
    room_geometry: per room id/name, bbox and centre in image px.
    map_geometry: what a card needs to place its own overlays (mm -> px).
    """
    validate_map(map_data)
    width, height, pix_len = map_data["width"], map_data["height"], map_data["pix_len"]
    pixels = lz4_block_decompress(base64.b64decode(map_data["map_data"]), pix_len)

    areas = map_data.get("area_list", [])
    rooms = [a for a in areas if a.get("type") == "room"]
    sorted_ids = sorted(r["id"] for r in rooms)
    room_colors = {rid: ROOM_PALETTE[i % len(ROOM_PALETTE)] for i, rid in enumerate(sorted_ids)}

    lut: list[tuple[int, int, int]] = [UNKNOWN_COLOR] * 256
    lut[0] = WALL_COLOR
    lut[127] = UNKNOWN_COLOR
    lut[255] = FLOOR_COLOR
    for rid, color in room_colors.items():
        if 0 <= rid <= 255:
            lut[rid] = color

    # Paint the grid at 1 px per cell, then scale: far faster than per-cell rectangles.
    # Unknown area is transparent so the map sits on light and dark themes alike.
    small = Image.new("RGBA", (width, height))
    small.putdata([(*lut[p], 255) if (p < 256 and p != 127) else (0, 0, 0, 0) for p in pixels])
    small = small.transpose(Image.Transpose.FLIP_TOP_BOTTOM)
    img = small.resize((width * MAP_SCALE, height * MAP_SCALE), Image.Resampling.NEAREST)

    to_px = _px_transform(map_data)

    def poly(a: dict) -> list[tuple[float, float]]:
        return [to_px(x, y) for x, y in a.get("vertexs", [])]

    draw = ImageDraw.Draw(img)
    for a in areas:
        if a.get("type") == "carpet_rectangle" and len(a.get("vertexs", [])) >= 3:
            draw.polygon(poly(a), fill=CARPET_COLOR, outline=(170, 170, 170))
    for f in map_data.get("furniture_list", []):
        if len(f.get("vertexs", [])) >= 3:
            draw.polygon(poly(f), outline=FURNITURE_OUTLINE, width=2)
    for a in areas:
        if a.get("type") == "area" and len(a.get("vertexs", [])) >= 3:
            draw.polygon(poly(a), outline=ZONE_OUTLINE, width=2)

    # Translucent no-go zones need an RGBA pass.
    forbid = [a for a in areas if a.get("type") == "forbid" and len(a.get("vertexs", [])) >= 3]
    if forbid:
        overlay = Image.new("RGBA", img.size, (0, 0, 0, 0))
        od = ImageDraw.Draw(overlay)
        for a in forbid:
            od.polygon(poly(a), fill=FORBID_COLOR, outline=FORBID_OUTLINE + (255,), width=2)
        img = Image.alpha_composite(img, overlay)
        draw = ImageDraw.Draw(img)
    for a in areas:
        if a.get("type") == "virtual_wall" and len(a.get("vertexs", [])) >= 2:
            draw.line(poly(a), fill=VIRTUAL_WALL_COLOR, width=3)

    # Room geometry (bbox / centroid in image px) and labels.
    font = _font()
    geometry: list[dict] = []
    cells: dict[int, list[tuple[int, int]]] = {rid: [] for rid in room_colors}
    for row in range(height):
        base = row * width
        for col in range(width):
            pv = pixels[base + col]
            if pv in cells:
                cells[pv].append((col, row))
    for room in rooms:
        rid = room["id"]
        pts = cells.get(rid) or []
        if not pts:
            continue
        xs = [c for c, _ in pts]
        ys = [r for _, r in pts]
        cx, cy = _grid_px(sum(xs) / len(xs), sum(ys) / len(ys), height)
        x0, y0 = _grid_px(min(xs), max(ys), height)
        x1, y1 = _grid_px(max(xs), min(ys), height)
        name = b64name(room.get("name", ""))
        geometry.append({"id": rid, "name": name, "bbox": [x0, y0, x1, y1], "centre": [cx, cy],
                         "cells": len(pts), "suction": room.get("suction"), "water_level": room.get("cistern"),
                         "passes": room.get("clean_number")})
        draw.text((cx + 1, cy + 1), name, fill=(0, 0, 0), font=font, anchor="mm")
        draw.text((cx, cy), name, fill=(255, 255, 255), font=font, anchor="mm")

    charge = map_data.get("charge_coor")
    if charge:
        _dot(draw, *_grid_px(charge[0], charge[1], height), (255, 200, 0))

    zones = [{"id": a.get("id"), "px": [list(p) for p in poly(a)],
              "mm": [list(v) for v in a.get("vertexs", [])],
              "suction": a.get("suction"), "water_level": a.get("cistern"), "passes": a.get("clean_number")}
             for a in areas if a.get("type") == "area" and len(a.get("vertexs", [])) >= 3]
    furniture = [{"id": f.get("id"), "type": f.get("type"),
                  "type_name": FURNITURE_TYPES.get(f.get("type")), "angle": f.get("angle"),
                  "px": [list(p) for p in poly(f)], "mm": [list(v) for v in f.get("vertexs", [])]}
                 for f in map_data.get("furniture_list", []) if len(f.get("vertexs", [])) >= 3]
    map_geometry = {
        "map_id": map_data.get("map_id"),
        "saved_zones": zones,
        "furniture": furniture,
        "map_name": b64name(map_data.get("map_name", "")),
        "image_size": [img.width, img.height],
        "grid_size": [width, height],
        "scale_px_per_cell": MAP_SCALE,
        "resolution_mm": map_data.get("resolution"),
        "real_origin_mm": list(map_data.get("real_origin_coor", [0, 0])[:2]),
        # px_x = ((mm_x - ox) / res) * scale + scale / 2
        # px_y = (grid_h - 1 - (mm_y - oy) / res) * scale + scale / 2
        "dock_px": list(_grid_px(charge[0], charge[1], height)) if charge else None,
    }
    return img, geometry, map_geometry


CLEANED_COLOR = (88, 170, 255)
RECORD_FLOOR = (205, 205, 210)


def render_record(rec: dict) -> Image.Image:
    """A finished run from getCleanRecordExtraInfo: cells the robot cleaned (255)
    in blue over the rooms it skipped in grey, with the path it drove, where it
    started (green) and where it stopped (red). Same grid format as the live map."""
    validate_map(rec)
    width, height, pix_len = rec["width"], rec["height"], rec["pix_len"]
    pixels = lz4_block_decompress(base64.b64decode(rec["map_data"]), pix_len)
    lut: list[tuple[int, int, int]] = [RECORD_FLOOR] * 256
    lut[0] = WALL_COLOR
    lut[255] = CLEANED_COLOR
    small = Image.new("RGBA", (width, height))
    small.putdata([(*lut[p], 255) if (p < 256 and p != 127) else (0, 0, 0, 0) for p in pixels])
    small = small.transpose(Image.Transpose.FLIP_TOP_BOTTOM)
    img = small.resize((width * MAP_SCALE, height * MAP_SCALE), Image.Resampling.NEAREST)
    draw = ImageDraw.Draw(img)
    to_px = _px_transform(rec)
    for a in rec.get("area_list", []):
        if a.get("type") == "forbid" and len(a.get("vertexs", [])) >= 3:
            draw.polygon([to_px(x, y) for x, y in a["vertexs"]], outline=FORBID_OUTLINE, width=2)
    pts: list = []
    if rec.get("pos_array") and rec.get("pos_len"):
        try:
            pts = decode_path(rec["pos_array"], int(rec["pos_len"]))
        except Exception:
            pts = []
    if len(pts) > 1:
        draw.line([to_px(x, y) for x, y in pts], fill=(20, 60, 140, 220), width=2, joint="curve")
        _dot(draw, *map(int, to_px(*pts[0])), (40, 180, 90), 5)
        _dot(draw, *map(int, to_px(*pts[-1])), (220, 60, 60), 5)
    charge = rec.get("real_charge_coor")
    if charge:
        _dot(draw, *map(int, to_px(charge[0], charge[1])), (255, 200, 0), 5)
    return img


def _dot(draw: ImageDraw.ImageDraw, sx: int, sy: int, color, radius: int = 6) -> None:
    draw.ellipse([sx - radius, sy - radius, sx + radius, sy + radius],
                 fill=color, outline=(255, 255, 255), width=2)


def _png(img: Image.Image) -> bytes:
    buf = io.BytesIO()
    img.save(buf, format="PNG", optimize=True)
    return buf.getvalue()


_jpeg = _png   # kept for callers; the map is PNG with transparency since 0.11




def room_mask_png(map_data: dict) -> bytes:
    """Lossless 8-bit PNG of the room-id grid (same orientation as the map
    image, 1 px per cell). Pixel value = room id, 0 wall, 255 floor, 127 unknown."""
    validate_map(map_data)
    width, height, pix_len = map_data["width"], map_data["height"], map_data["pix_len"]
    pixels = lz4_block_decompress(base64.b64decode(map_data["map_data"]), pix_len)
    img = Image.frombytes("L", (width, height), bytes(min(p, 255) for p in pixels))
    img = img.transpose(Image.Transpose.FLIP_TOP_BOTTOM)
    buf = io.BytesIO()
    img.save(buf, format="PNG", optimize=True)
    return buf.getvalue()
