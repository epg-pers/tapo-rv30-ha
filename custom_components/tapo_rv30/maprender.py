"""Map rendering: LZ4 pixel grid -> annotated JPEG, plus the geometry a card
needs to place its own overlays. No Home Assistant imports."""
from __future__ import annotations

import base64
import math
import io

from PIL import Image, ImageDraw, ImageFont

from .const import (
    CARPET_COLOR, FLOOR_COLOR, FORBID_COLOR, FORBID_OUTLINE, FURNITURE_OUTLINE, FURNITURE_TYPES, ROOM_PALETTE,
    UNKNOWN_COLOR, VIRTUAL_WALL_COLOR, WALL_COLOR, ZONE_OUTLINE,
)
from .mapdata import decode_path, b64name, lz4_block_decompress, mm_to_grid, validate_map

MAP_SCALE = 4   # px per vacuum grid cell -> ~700x700 output image
FONT_SIZE = 14


def _font(size: int = FONT_SIZE):
    try:
        return ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", size)
    except Exception:
        return ImageFont.load_default()


# Furniture glyphs, our own drawing, in the unit square of each item's rectangle
# (a across its width, b down its height; the robot's rotation comes for free
# because the square is mapped onto the item's rotated outline). Each entry is a
# list of shapes: ("poly", [(a, b), ...]) closed outline, ("line", [...]) open
# polyline, ("circle", (ca, cb), r) with r in width units, ("dot", (ca, cb)).
def _rect(a0, b0, a1, b1):
    return ("poly", [(a0, b0), (a1, b0), (a1, b1), (a0, b1)])


_SOFA = [_rect(0.0, 0.0, 1.0, 0.28), _rect(0.0, 0.28, 0.13, 1.0), _rect(0.87, 0.28, 1.0, 1.0)]
FURNITURE_GLYPHS = {
    1:   [_rect(0.12, 0.06, 0.88, 0.24), ("line", [(0.0, 0.32), (1.0, 0.32)])],                    # single bed
    2:   [_rect(0.08, 0.06, 0.46, 0.24), _rect(0.54, 0.06, 0.92, 0.24), ("line", [(0.0, 0.32), (1.0, 0.32)])],
    101: _SOFA,
    102: _SOFA + [("line", [(0.5, 0.28), (0.5, 1.0)])],
    103: _SOFA + [("line", [(0.5, 0.28), (0.5, 1.0)]), _rect(0.0, 0.6, 0.45, 1.0)],
    201: [_rect(0.2, 0.25, 0.8, 0.75)] + [("dot", p) for p in ((0.1, 0.38), (0.1, 0.62), (0.9, 0.38), (0.9, 0.62),
                                                                 (0.35, 0.12), (0.65, 0.12), (0.35, 0.88), (0.65, 0.88))],
    202: [_rect(0.15, 0.15, 0.85, 0.85)],
    203: [_rect(0.2, 0.2, 0.8, 0.8), ("dot", (0.5, 0.5))],
    301: [("line", [(0.0, 0.5), (1.0, 0.5)]), _rect(0.3, 0.1, 0.7, 0.4)],                            # tv cabinet
    302: [("line", [(0.5, 0.0), (0.5, 1.0)]), ("dot", (0.42, 0.5)), ("dot", (0.58, 0.5))],          # wardrobe
    303: [_rect(0.2, 0.2, 0.8, 0.8), ("dot", (0.5, 0.5))],
    401: [("line", [(0.0, 0.35), (1.0, 0.35)]), ("dot", (0.85, 0.2)), ("dot", (0.85, 0.6))],       # fridge
    402: [("circle", (0.5, 0.55), 0.3), ("circle", (0.5, 0.55), 0.18)],                             # washer
    403: [("line", [(0.1, 0.3), (0.9, 0.3)]), ("line", [(0.1, 0.42), (0.9, 0.42)]), ("line", [(0.1, 0.54), (0.9, 0.54)])],
    503: [("circle", (0.5, 0.5), 0.42), ("circle", (0.5, 0.5), 0.22)],                              # plants
    601: [_rect(0.15, 0.0, 0.85, 0.3), ("circle", (0.5, 0.66), 0.3)],                              # toilet
    701: [("poly", [(0.0, 0.42), (0.5, 0.0), (1.0, 0.42)]), _rect(0.1, 0.42, 0.9, 1.0)],           # pet house
    702: [_rect(0.1, 0.1, 0.9, 0.9)] + [("dot", p) for p in ((0.3, 0.4), (0.6, 0.3), (0.5, 0.65), (0.7, 0.7))],
    703: [("circle", (0.3, 0.5), 0.2), ("circle", (0.7, 0.5), 0.2)],                                 # pet bowl
}
FURNITURE_FILL = (255, 255, 255, 90)


def _draw_furniture(img: Image.Image, furniture: list[dict], to_px) -> None:
    """Outline, a light fill, our own glyph and a small label per item. The glyph
    is drawn in the unit square of the item's four corners, so the item's own
    rotation applies without any trig here."""
    overlay = Image.new("RGBA", img.size, (0, 0, 0, 0))
    od = ImageDraw.Draw(overlay)
    draw = ImageDraw.Draw(img)
    small_font = _font(max(8, FONT_SIZE - 4))
    for f in furniture:
        verts = f.get("vertexs") or []
        if len(verts) < 4:
            continue
        p0, p1, p2, p3 = [to_px(x, y) for x, y in verts[:4]]
        poly = [p0, p1, p2, p3]

        def at(a: float, b: float):
            return (p0[0] + a * (p1[0] - p0[0]) + b * (p3[0] - p0[0]),
                    p0[1] + a * (p1[1] - p0[1]) + b * (p3[1] - p0[1]))

        od.polygon(poly, fill=FURNITURE_FILL)
        draw.polygon(poly, outline=FURNITURE_OUTLINE, width=2)
        width_px = max(1.0, ((p1[0] - p0[0]) ** 2 + (p1[1] - p0[1]) ** 2) ** 0.5)
        height_px = max(1.0, ((p3[0] - p0[0]) ** 2 + (p3[1] - p0[1]) ** 2) ** 0.5)
        for shape in FURNITURE_GLYPHS.get(f.get("type"), []):
            kind = shape[0]
            if kind == "poly":
                draw.polygon([at(a, b) for a, b in shape[1]], outline=FURNITURE_OUTLINE, width=1)
            elif kind == "line":
                draw.line([at(a, b) for a, b in shape[1]], fill=FURNITURE_OUTLINE, width=1)
            elif kind == "circle":
                (ca, cb), r = shape[1], shape[2]
                rb = r * width_px / height_px          # keep it round on the screen
                draw.polygon([at(ca + r * math.cos(t), cb + rb * math.sin(t))
                              for t in (i * math.pi / 12 for i in range(24))], outline=FURNITURE_OUTLINE, width=1)
            elif kind == "dot":
                cx, cy = at(*shape[1])
                draw.ellipse([cx - 2, cy - 2, cx + 2, cy + 2], fill=FURNITURE_OUTLINE)
        name = FURNITURE_TYPES.get(f.get("type"))
        if name and height_px >= 24 and draw.textlength(name, font=small_font) <= width_px - 8:
            cx, cy = at(0.5, 0.5)
            draw.text((cx + 1, cy + 1), name, fill=(255, 255, 255), font=small_font, anchor="mm")
            draw.text((cx, cy), name, fill=(60, 60, 60), font=small_font, anchor="mm")
    img.alpha_composite(overlay)


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
    _draw_furniture(img, map_data.get("furniture_list", []), to_px)
    draw = ImageDraw.Draw(img)
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
