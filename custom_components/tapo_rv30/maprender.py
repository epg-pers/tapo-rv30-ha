"""Map rendering: LZ4 pixel grid -> annotated JPEG, plus the geometry a card
needs to place its own overlays. No Home Assistant imports."""
from __future__ import annotations

import base64
import io
import math

import numpy as np
from PIL import Image, ImageDraw, ImageFont

from .const import (
    CARPET_COLOR,
    FLOOR_COLOR,
    FORBID_COLOR,
    FORBID_OUTLINE,
    FURNITURE_OUTLINE,
    FURNITURE_TYPES,
    MAP_BACKGROUND,
    MAP_CLEAN_MAX_CELLS,
    ROOM_PALETTE,
    SPACE_COLOR,
    VIRTUAL_WALL_COLOR,
    WALL_COLOR,
    ZONE_OUTLINE,
)
from .mapclean import NULL, clean_grid, grid_values, room_colours
from .mapdata import b64name, decode_path, lz4_block_decompress, mm_to_grid, texture_direction, validate_map

MAP_SCALE = 4   # px per vacuum grid cell -> ~700x700 output image
FONT_SIZE = 14


def _font(size: int = FONT_SIZE):
    try:
        return ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", size)
    except Exception:
        return ImageFont.load_default()


# Furniture: our own little illustrations, defined in the unit square of each item's
# rectangle (a across its width, b down its height) and mapped onto the item's rotated
# outline, so the robot's angle comes for free. Shapes are drawn on a 2x overlay and
# downsampled, which is what makes the curves smooth.
#   ("rrect", a0, b0, a1, b1, radius, fill, outline)   rounded rectangle
#   ("ellipse", ca, cb, ra, rb, fill, outline)          ra, rb in width / height units
#   ("poly", [(a, b), ...], fill, outline)
#   ("line", [(a, b), ...], colour, width)
WOOD, WOOD_D = (222, 196, 160), (160, 128, 90)
FABRIC, FABRIC_D = (214, 206, 198), (130, 120, 110)
LINEN, LINEN_D = (236, 232, 244), (150, 140, 170)
STEEL, STEEL_D = (222, 228, 236), (120, 130, 150)
LEAF, LEAF_D = (134, 196, 120), (60, 120, 60)
CERAMIC, CERAMIC_D = (246, 248, 252), (130, 140, 160)
PET, PET_D = (246, 214, 180), (170, 120, 70)
PILLOW = (252, 252, 255)


def _bed(double: bool):
    pillows = ([("rrect", 0.10, 0.06, 0.47, 0.24, 0.05, PILLOW, LINEN_D), ("rrect", 0.53, 0.06, 0.90, 0.24, 0.05, PILLOW, LINEN_D)]
               if double else [("rrect", 0.16, 0.06, 0.84, 0.24, 0.05, PILLOW, LINEN_D)])
    return [("rrect", 0, 0, 1, 1, 0.08, LINEN, LINEN_D), ("rrect", 0, 0, 1, 0.05, 0.02, LINEN_D, LINEN_D),
            *pillows, ("rrect", 0.04, 0.30, 0.96, 0.97, 0.06, (200, 190, 230), LINEN_D),
            ("line", [(0.04, 0.42), (0.96, 0.42)], LINEN_D, 1)]


def _sofa(seats: int, corner: bool = False):
    g = [("rrect", 0, 0, 1, 1, 0.12, FABRIC, FABRIC_D), ("rrect", 0.02, 0.02, 0.98, 0.30, 0.10, FABRIC_D, FABRIC_D),
         ("rrect", 0.0, 0.25, 0.13, 1.0, 0.08, FABRIC_D, FABRIC_D), ("rrect", 0.87, 0.25, 1.0, 1.0, 0.08, FABRIC_D, FABRIC_D)]
    w = (0.87 - 0.13) / seats
    for i in range(seats):
        g.append(("rrect", 0.13 + i * w + 0.015, 0.33, 0.13 + (i + 1) * w - 0.015, 0.96, 0.06, (228, 222, 214), FABRIC_D))
    if corner:
        g.append(("rrect", 0.13, 0.55, 0.50, 0.96, 0.06, (228, 222, 214), FABRIC_D))
    return g


def _chairs():
    pts = [(0.03, 0.30), (0.03, 0.56), (0.83, 0.30), (0.83, 0.56), (0.30, 0.02), (0.56, 0.02), (0.30, 0.82), (0.56, 0.82)]
    return [("rrect", a, b, a + 0.14, b + 0.16, 0.04, WOOD_D, WOOD_D) for a, b in pts]


FURNITURE_GLYPHS = {
    1:   _bed(False),
    2:   _bed(True),
    101: _sofa(1),
    102: _sofa(2),
    103: _sofa(3, corner=True),
    201: _chairs() + [("rrect", 0.17, 0.20, 0.83, 0.80, 0.08, WOOD, WOOD_D), ("line", [(0.22, 0.5), (0.78, 0.5)], WOOD_D, 1)],
    202: [("rrect", 0.08, 0.08, 0.92, 0.92, 0.10, WOOD, WOOD_D), ("line", [(0.14, 0.5), (0.86, 0.5)], WOOD_D, 1)],
    203: [("rrect", 0.08, 0.08, 0.92, 0.92, 0.12, WOOD, WOOD_D), ("ellipse", 0.5, 0.5, 0.16, 0.16, (255, 244, 200), WOOD_D)],
    301: [("rrect", 0, 0.30, 1, 1, 0.06, WOOD, WOOD_D), ("line", [(0.0, 0.65), (1.0, 0.65)], WOOD_D, 1),
          ("rrect", 0.22, 0.04, 0.78, 0.30, 0.03, (40, 44, 52), (20, 22, 28))],
    302: [("rrect", 0, 0, 1, 1, 0.05, WOOD, WOOD_D), ("line", [(0.5, 0.04), (0.5, 0.96)], WOOD_D, 1),
          ("ellipse", 0.44, 0.5, 0.03, 0.05, WOOD_D, WOOD_D), ("ellipse", 0.56, 0.5, 0.03, 0.05, WOOD_D, WOOD_D)],
    303: [("rrect", 0.06, 0.06, 0.94, 0.94, 0.10, WOOD, WOOD_D), ("ellipse", 0.5, 0.5, 0.18, 0.18, (255, 244, 200), WOOD_D)],
    401: [("rrect", 0, 0, 1, 1, 0.08, STEEL, STEEL_D), ("line", [(0.04, 0.36), (0.96, 0.36)], STEEL_D, 1),
          ("rrect", 0.82, 0.10, 0.88, 0.30, 0.02, STEEL_D, STEEL_D), ("rrect", 0.82, 0.42, 0.88, 0.80, 0.02, STEEL_D, STEEL_D)],
    402: [("rrect", 0, 0, 1, 1, 0.10, STEEL, STEEL_D), ("ellipse", 0.5, 0.56, 0.32, 0.32, (200, 210, 224), STEEL_D),
          ("ellipse", 0.5, 0.56, 0.20, 0.20, (120, 150, 190), STEEL_D), ("ellipse", 0.5, 0.56, 0.09, 0.09, (170, 200, 230), STEEL_D),
          ("rrect", 0.10, 0.06, 0.40, 0.16, 0.03, STEEL_D, STEEL_D)],
    403: [("rrect", 0, 0, 1, 1, 0.12, STEEL, STEEL_D), ("ellipse", 0.5, 0.18, 0.12, 0.08, (120, 150, 190), STEEL_D),
          ("line", [(0.15, 0.40), (0.85, 0.40)], STEEL_D, 1), ("line", [(0.15, 0.52), (0.85, 0.52)], STEEL_D, 1),
          ("line", [(0.15, 0.64), (0.85, 0.64)], STEEL_D, 1), ("line", [(0.15, 0.76), (0.85, 0.76)], STEEL_D, 1)],
    503: [("ellipse", 0.5, 0.78, 0.26, 0.18, (186, 120, 80), (120, 70, 40)),
          ("ellipse", 0.36, 0.42, 0.26, 0.28, LEAF, LEAF_D), ("ellipse", 0.64, 0.42, 0.26, 0.28, LEAF, LEAF_D),
          ("ellipse", 0.5, 0.30, 0.26, 0.26, (160, 212, 140), LEAF_D)],
    601: [("rrect", 0.12, 0.0, 0.88, 0.34, 0.06, CERAMIC, CERAMIC_D), ("ellipse", 0.5, 0.66, 0.36, 0.32, CERAMIC, CERAMIC_D),
          ("ellipse", 0.5, 0.66, 0.24, 0.20, (214, 226, 240), CERAMIC_D)],
    701: [("rrect", 0.08, 0.40, 0.92, 1.0, 0.04, PET, PET_D), ("poly", [(0.0, 0.44), (0.5, 0.02), (1.0, 0.44)], (210, 120, 90), PET_D),
          ("rrect", 0.36, 0.60, 0.64, 1.0, 0.10, (120, 80, 60), PET_D)],
    702: [("rrect", 0.04, 0.04, 0.96, 0.96, 0.10, (200, 210, 220), STEEL_D), ("rrect", 0.12, 0.14, 0.88, 0.90, 0.08, PET, PET_D),
          ("ellipse", 0.32, 0.40, 0.05, 0.05, PET_D, PET_D), ("ellipse", 0.58, 0.32, 0.05, 0.05, PET_D, PET_D),
          ("ellipse", 0.50, 0.68, 0.05, 0.05, PET_D, PET_D), ("ellipse", 0.70, 0.72, 0.05, 0.05, PET_D, PET_D)],
    703: [("ellipse", 0.28, 0.5, 0.24, 0.40, STEEL, STEEL_D), ("ellipse", 0.28, 0.5, 0.15, 0.25, (120, 150, 190), STEEL_D),
          ("ellipse", 0.72, 0.5, 0.24, 0.40, STEEL, STEEL_D), ("ellipse", 0.72, 0.5, 0.15, 0.25, PET, PET_D)],
}
_SS = 2   # supersampling factor for the furniture overlay


def _unit_rrect(a0, b0, a1, b1, r, steps=5):
    """Rounded-rectangle outline in unit coordinates (radius r in width units)."""
    r = min(r, (a1 - a0) / 2, (b1 - b0) / 2)
    pts = []
    for cx, cy, start in ((a1 - r, b0 + r, -90), (a1 - r, b1 - r, 0), (a0 + r, b1 - r, 90), (a0 + r, b0 + r, 180)):
        for i in range(steps + 1):
            t = math.radians(start + 90 * i / steps)
            pts.append((cx + r * math.cos(t), cy + r * math.sin(t)))
    return pts


def _draw_furniture(img: Image.Image, furniture: list[dict], to_px) -> None:
    """Illustration and (when it fits) a label per item, drawn in the unit square of the
    item's four corners so the item's own rotation applies."""
    W, H = img.size
    overlay = Image.new("RGBA", (W * _SS, H * _SS), (0, 0, 0, 0))
    od = ImageDraw.Draw(overlay)
    draw = ImageDraw.Draw(img)
    small_font = _font(max(8, FONT_SIZE - 4))
    labels = []
    for f in furniture:
        verts = f.get("vertexs") or []
        if len(verts) < 4:
            continue
        p0, p1, p2, p3 = [to_px(x, y) for x, y in verts[:4]]

        def at(a: float, b: float):
            return ((p0[0] + a * (p1[0] - p0[0]) + b * (p3[0] - p0[0])) * _SS,
                    (p0[1] + a * (p1[1] - p0[1]) + b * (p3[1] - p0[1])) * _SS)

        shapes = FURNITURE_GLYPHS.get(f.get("type")) or [("rrect", 0, 0, 1, 1, 0.06, (236, 236, 240), FURNITURE_OUTLINE)]
        for shape in shapes:
            kind = shape[0]
            if kind == "rrect":
                _, a0, b0, a1, b1, r, fill, outline = shape
                od.polygon([at(a, b) for a, b in _unit_rrect(a0, b0, a1, b1, r)], fill=(*fill, 255), outline=(*outline, 255), width=_SS)
            elif kind == "ellipse":
                _, ca, cb, ra, rb, fill, outline = shape
                od.polygon([at(ca + ra * math.cos(t), cb + rb * math.sin(t)) for t in (i * math.pi / 16 for i in range(32))],
                           fill=(*fill, 255), outline=(*outline, 255), width=_SS)
            elif kind == "poly":
                _, pts, fill, outline = shape
                od.polygon([at(a, b) for a, b in pts], fill=(*fill, 255), outline=(*outline, 255), width=_SS)
            elif kind == "line":
                _, pts, colour, width = shape
                od.line([at(a, b) for a, b in pts], fill=(*colour, 255), width=width * _SS)
        width_px = ((p1[0] - p0[0]) ** 2 + (p1[1] - p0[1]) ** 2) ** 0.5
        height_px = ((p3[0] - p0[0]) ** 2 + (p3[1] - p0[1]) ** 2) ** 0.5
        name = FURNITURE_TYPES.get(f.get("type"))
        if name and height_px >= 24 and draw.textlength(name, font=small_font) <= width_px - 8:
            labels.append((((p0[0] + p2[0]) / 2, (p0[1] + p2[1]) / 2), name))
    img.alpha_composite(overlay.resize((W, H), Image.Resampling.LANCZOS))
    draw = ImageDraw.Draw(img)
    for (cx, cy), name in labels:
        draw.text((cx + 1, cy + 1), name, fill=(255, 255, 255), font=small_font, anchor="mm")
        draw.text((cx, cy), name, fill=(60, 60, 60), font=small_font, anchor="mm")


# The map's display rotation, as the Tapo app stores it per map (rotate_angle): the picture
# turned clockwise by this many degrees. Quarter turns only, so cells stay square and exact.
ROTATIONS = (0, 90, 180, 270)
# PIL turns anticlockwise, so a clockwise quarter turn is its ROTATE_270.
_TRANSPOSE = {90: Image.Transpose.ROTATE_270, 180: Image.Transpose.ROTATE_180, 270: Image.Transpose.ROTATE_90}


def rotation_of(value) -> int:
    """A rotate_angle from the robot as one of ROTATIONS (anything else is 0)."""
    try:
        angle = int(value) % 360
    except (TypeError, ValueError, OverflowError):
        return 0
    return angle if angle in ROTATIONS else 0


def rotate_px(x: float, y: float, w: float, h: float, rotation: int) -> tuple[float, float]:
    """A point of the unrotated w x h picture, in the picture turned clockwise by rotation."""
    if rotation == 90:
        return h - y, x
    if rotation == 180:
        return w - x, h - y
    if rotation == 270:
        return y, w - x
    return x, y


def _turn(img: Image.Image, rotation: int) -> Image.Image:
    return img.transpose(_TRANSPOSE[rotation]) if rotation in _TRANSPOSE else img


def _blend(rgba: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
    *rgb, alpha = rgba
    return (*(round((c * alpha + bg * (255 - alpha)) / 255) for c, bg in zip(rgb, MAP_BACKGROUND)), 255)


def _cell_picture(map_data: dict, pixels: bytes, rotation: int) -> Image.Image:
    """The cells as the Tapo app draws them: its clean-up of the grid, then one flat colour per
    cell (rooms in their colours, plain floor, walls), unknown left transparent. Turned like the
    map and scaled to MAP_SCALE px per cell. A very large grid is drawn without the clean-up."""
    width, height = map_data["width"], map_data["height"]
    wall, floor, rooms = grid_values(map_data)
    raw = np.frombuffer(bytes(pixels), np.uint8).reshape(height, width).astype(np.int16)
    if raw.size <= MAP_CLEAN_MAX_CELLS:
        grid = clean_grid(raw, wall, floor, rooms)
    else:
        known = (raw == wall) | (raw == floor) | ((raw >= rooms[0]) & (raw <= rooms[1]))
        grid = np.where(known, raw, NULL).astype(np.int16)
    preset = {}
    for a in map_data.get("area_list") or []:
        if isinstance(a, dict) and a.get("type") == "room" and isinstance(a.get("id"), int):
            preset[a["id"]] = a.get("color")
    # The app sorts wall and floor out before rooms, so those values are never a room.
    colours = room_colours(np.where((grid == wall) | (grid == floor), NULL, grid), rooms, preset)
    lut = np.zeros((257, 4), np.uint8)   # by value + 1, so unknown (NULL) is transparent
    for rid, colour in colours.items():
        lut[rid + 1] = _blend(ROOM_PALETTE[colour - 1])
    lut[floor + 1] = _blend(FLOOR_COLOR if colours else SPACE_COLOR)
    lut[wall + 1] = _blend(WALL_COLOR)
    small = Image.fromarray(lut[grid + 1], "RGBA")
    small = _turn(small.transpose(Image.Transpose.FLIP_TOP_BOTTOM), rotation)
    return small.resize((small.width * MAP_SCALE, small.height * MAP_SCALE), Image.Resampling.NEAREST)


def _px_transform(map_data: dict, rotation: int = 0):
    """Return mm -> image px function for this map (Y grows upwards in the grid,
    downwards in the image), in the picture turned clockwise by rotation. The robot puts a
    point in cell floor((mm - origin) / res), so origin + cell * res is the cell's lower-left
    corner, not its centre."""
    height = map_data["height"]
    w, h = map_data["width"] * MAP_SCALE, height * MAP_SCALE

    def to_px(x_mm: float, y_mm: float) -> tuple[float, float]:
        gx, gy = mm_to_grid(map_data, x_mm, y_mm)
        return rotate_px(gx * MAP_SCALE, (height - gy) * MAP_SCALE, w, h, rotation)

    return to_px


def _grid_px(gx: float, gy: float, height: int, width: int = 0, rotation: int = 0) -> tuple[int, int]:
    """The centre of grid cell (gx, gy) in image px (in the rotated picture when rotation)."""
    x, y = int(gx * MAP_SCALE + MAP_SCALE // 2), int((height - 1 - gy) * MAP_SCALE + MAP_SCALE // 2)
    if rotation:
        x, y = rotate_px(x, y, width * MAP_SCALE, height * MAP_SCALE, rotation)
    return int(x), int(y)


def render_map(map_data: dict, rotation: int = 0) -> tuple[Image.Image, list[dict], dict]:
    """Decode the LZ4 pixel grid and draw rooms, no-go zones, virtual walls,
    carpets, saved zones, furniture, labels and the dock. With a rotation the grid is turned
    first and everything is drawn on the turned picture, so labels stay upright.

    Returns (base image without the vacuum marker, room_geometry, map_geometry).
    room_geometry: per room id/name, bbox and centre in image px.
    map_geometry: what a card needs to place its own overlays (mm -> px).
    """
    validate_map(map_data)
    width, height, pix_len = map_data["width"], map_data["height"], map_data["pix_len"]
    pixels = lz4_block_decompress(base64.b64decode(map_data["map_data"]), pix_len)

    areas = map_data.get("area_list", [])
    rooms = [a for a in areas if a.get("type") == "room"]

    # The picture is the app's cleaned grid; room geometry below stays on the robot's own grid.
    rotation = rotation_of(rotation)
    img = _cell_picture(map_data, pixels, rotation)

    to_px = _px_transform(map_data, rotation)

    def gpx(gx: float, gy: float) -> tuple[int, int]:
        return _grid_px(gx, gy, height, width, rotation)

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
    cells: dict[int, list[tuple[int, int]]] = {r["id"]: [] for r in rooms}
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
        cx, cy = gpx(sum(xs) / len(xs), sum(ys) / len(ys))
        (ax, ay), (bx, by) = gpx(min(xs), max(ys)), gpx(max(xs), min(ys))
        name = b64name(room.get("name", ""))
        geometry.append({"id": rid, "name": name, "bbox": [min(ax, bx), min(ay, by), max(ax, bx), max(ay, by)],
                         "centre": [cx, cy],
                         "cells": len(pts), "suction": _num(room.get("suction")),
                         "water_level": _num(room.get("cistern")), "passes": _num(room.get("clean_number")),
                         # The room's cleaning direction: raw, and as the picture is turned
                         **({"floor_texture": _num(room["floor_texture"]),
                             "cleaning_direction": texture_direction(_num(room["floor_texture"]), rotation)}
                            if "floor_texture" in room else {})})
        draw.text((cx + 1, cy + 1), name, fill=(0, 0, 0), font=font, anchor="mm")
        draw.text((cx, cy), name, fill=(255, 255, 255), font=font, anchor="mm")

    charge = map_data.get("charge_coor")
    if charge:
        _dot(draw, *gpx(charge[0], charge[1]), (255, 200, 0))

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
        # px_x = ((mm_x - ox) / res) * scale
        # px_y = (grid_h - (mm_y - oy) / res) * scale
        # then turned clockwise by rotation in a (grid_w * scale) x (grid_h * scale) picture:
        # 90: (H - y, x), 180: (W - x, H - y), 270: (y, W - x)
        "rotation": rotation,
        "dock_px": list(gpx(charge[0], charge[1])) if charge else None,
    }
    return img, geometry, map_geometry


def render_record(rec: dict, rotation: int = 0) -> Image.Image:
    """A finished run from getCleanRecordExtraInfo, drawn like the live map (the app's
    clean-up and colours; cells the robot cleaned are plain floor there), with the path it
    drove, where it started (green) and where it stopped (red)."""
    validate_map(rec)
    pixels = lz4_block_decompress(base64.b64decode(rec["map_data"]), rec["pix_len"])
    rotation = rotation_of(rotation)
    img = _cell_picture(rec, pixels, rotation)
    draw = ImageDraw.Draw(img)
    to_px = _px_transform(rec, rotation)
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


def _num(value) -> int | None:
    """A robot level field as an int (or None): it reaches the page, so never a string."""
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return None


def _dot(draw: ImageDraw.ImageDraw, sx: int, sy: int, color, radius: int = 6) -> None:
    draw.ellipse([sx - radius, sy - radius, sx + radius, sy + radius],
                 fill=color, outline=(255, 255, 255), width=2)


def _png(img: Image.Image, fast: bool = False) -> bytes:
    """fast: the frame redrawn every poll while the robot moves; optimize roughly doubles the
    encode time for a few per cent smaller."""
    buf = io.BytesIO()
    img.save(buf, format="PNG", optimize=not fast)
    return buf.getvalue()


_jpeg = _png   # kept for callers; the map is PNG with transparency since 0.11




def room_mask_png(map_data: dict, rotation: int = 0) -> bytes:
    """Lossless 8-bit PNG of the room-id grid (same orientation as the map
    image, rotation included, 1 px per cell). Pixel value = room id, 0 wall, 255 floor, 127 unknown."""
    validate_map(map_data)
    width, height, pix_len = map_data["width"], map_data["height"], map_data["pix_len"]
    pixels = lz4_block_decompress(base64.b64decode(map_data["map_data"]), pix_len)
    img = Image.frombytes("L", (width, height), bytes(min(p, 255) for p in pixels))
    img = _turn(img.transpose(Image.Transpose.FLIP_TOP_BOTTOM), rotation_of(rotation))
    buf = io.BytesIO()
    img.save(buf, format="PNG", optimize=True)
    return buf.getvalue()
