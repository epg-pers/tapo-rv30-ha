import base64

from PIL import Image

from custom_components.tapo_rv30.const import FLOOR_COLOR, ROOM_PALETTE, SPACE_COLOR, WALL_COLOR
from custom_components.tapo_rv30.maprender import MAP_SCALE, _blend, render_map


def b64(s):
    return base64.b64encode(s.encode()).decode()


def _lz4_literal(raw: bytes) -> bytes:
    # literal-only block: token with lit_len=15 and extension bytes
    n = len(raw)
    if n < 15:
        return bytes([n << 4]) + raw
    ext = n - 15
    out = bytes([0xF0])
    while ext >= 255:
        out += b"\xff"; ext -= 255
    return out + bytes([ext]) + raw


def _map(fill=255):
    width, height = 10, 8
    px = bytearray([fill] * (width * height))    # floor (255) or unexplored (127)
    for col in range(10):
        px[0 * width + col] = 0                   # wall along the bottom row (gy=0)
    for row in range(1, 4):
        for col in range(1, 5):
            px[row * width + col] = 1             # room 1: cols 1-4, rows 1-3
    for row in range(4, 7):
        for col in range(5, 9):
            px[row * width + col] = 2             # room 2
    raw = bytes(px)
    return {
        "map_id": 9, "map_name": b64("Test"), "width": width, "height": height, "pix_len": len(raw),
        "map_data": base64.b64encode(_lz4_literal(raw)).decode(),
        "resolution": 50, "real_origin_coor": [-100, -200, 0],
        "charge_coor": [2, 2, 0], "vac_coor": [6, 5, 0],
        "area_list": [
            {"type": "room", "id": 1, "name": b64("Hall")},
            {"type": "room", "id": 2, "name": b64("")},
            {"type": "forbid", "id": 301, "vertexs": [[0, 0], [100, 0], [100, 100], [0, 100]]},
            {"type": "virtual_wall", "id": 401, "vertexs": [[-100, 100], [300, 100]]},
            {"type": "carpet_rectangle", "id": 101, "vertexs": [[200, 0], [300, 0], [300, 50], [200, 50]]},
            {"type": "area", "id": 501, "vertexs": [[150, 150], [250, 150], [250, 250], [150, 250]]},
        ],
        "furniture_list": [{"id": 0, "type": 201, "vertexs": [[-50, -50], [0, -50], [0, 0], [-50, 0]]}],
    }


def test_render_map_geometry_and_image():
    img, rooms, geom = render_map(_map())
    assert isinstance(img, Image.Image)
    assert img.size == (10 * MAP_SCALE, 8 * MAP_SCALE)
    assert geom["grid_size"] == [10, 8] and geom["resolution_mm"] == 50
    assert geom["real_origin_mm"] == [-100, -200] and geom["map_name"] == "Test"
    by_id = {r["id"]: r for r in rooms}
    assert by_id[1]["name"] == "Hall" and by_id[1]["cells"] == 12
    # room 1 spans grid cols 1-4, rows 1-3 -> image y is flipped: rows 1-3 -> y rows 4-6
    x0, y0, x1, y1 = by_id[1]["bbox"]
    assert (x0, x1) == (1 * MAP_SCALE + MAP_SCALE // 2, 4 * MAP_SCALE + MAP_SCALE // 2)
    assert y0 < y1 and y0 == (8 - 1 - 3) * MAP_SCALE + MAP_SCALE // 2 and y1 == (8 - 1 - 1) * MAP_SCALE + MAP_SCALE // 2
    # dock marker position is reported for cards
    assert geom["dock_px"] == [2 * MAP_SCALE + MAP_SCALE // 2, (8 - 1 - 2) * MAP_SCALE + MAP_SCALE // 2]
    # the wall row (gy=0) is at the bottom of the image, in the app's wall colour
    assert img.getpixel((MAP_SCALE * 9 + 1, img.height - 1)) == WALL_COLOR


def test_render_map_without_overlays():
    md = _map()
    md["area_list"] = [a for a in md["area_list"] if a["type"] == "room"]
    md.pop("furniture_list"); md.pop("charge_coor")
    img, rooms, geom = render_map(md)
    assert len(rooms) == 2 and geom["dock_px"] is None


def test_unknown_area_is_transparent():
    img, _, _ = render_map(_map(fill=127))
    assert img.mode == "RGBA"
    assert img.getpixel((img.width - 2, 2))[3] == 0          # unexplored corner: transparent
    assert img.getpixel((MAP_SCALE * 2 + 1, img.height - MAP_SCALE * 2 - 1))[3] == 255   # room 1 cell: opaque


def test_saved_zones_and_room_settings_in_geometry():
    md = _map(); md["area_list"][0]["suction"] = 3; md["area_list"][0]["cistern"] = 1; md["area_list"][0]["clean_number"] = 2
    _, rooms, geom = render_map(md)
    assert geom["saved_zones"][0]["id"] == 501 and len(geom["saved_zones"][0]["px"]) == 4
    assert geom["saved_zones"][0]["mm"] == [[150, 150], [250, 150], [250, 250], [150, 250]]
    r1 = next(r for r in rooms if r["id"] == 1)
    assert (r1["suction"], r1["water_level"], r1["passes"]) == (3, 1, 2)


def test_furniture_in_geometry():
    _, _, geom = render_map(_map())
    assert geom["furniture"][0]["type"] == 201
    assert geom["furniture"][0]["type_name"] == "Table and chairs"
    assert len(geom["furniture"][0]["px"]) == 4


def _bare(md=None):
    """The test map with only its rooms: no overlays drawn over the cells."""
    md = md or _map()
    md["area_list"] = [a for a in md["area_list"] if a["type"] == "room"]
    md.pop("furniture_list"); md.pop("charge_coor")
    return md


def _cell(img, gx, gy, height=8):
    """The colour drawn for grid cell (gx, gy) of an unrotated picture."""
    return img.getpixel((gx * MAP_SCALE + 1, (height - 1 - gy) * MAP_SCALE + 1))


def test_render_map_draws_the_apps_cleaned_grid_in_its_colours():
    img, rooms, _ = render_map(_bare())
    # Rooms touch, so they get different colours, 1 and 2 by id; the clean-up hands the floor
    # round them to the rooms and drops cells next to the grid edge.
    assert _cell(img, 2, 2) == _blend(ROOM_PALETTE[0]) == _cell(img, 1, 6)
    assert _cell(img, 6, 5) == _blend(ROOM_PALETTE[1]) == _cell(img, 5, 7)
    assert _cell(img, 0, 7)[3] == 0 and _cell(img, 9, 6)[3] == 0
    # Room geometry is still the robot's own grid.
    assert {r["id"]: r["cells"] for r in rooms} == {1: 12, 2: 12}


def test_render_map_keeps_a_rooms_own_colour():
    md = _bare()
    md["area_list"][0]["color"] = 2
    img, _, _ = render_map(md)
    assert _cell(img, 2, 2) == _blend(ROOM_PALETTE[1])
    assert _cell(img, 6, 5) == _blend(ROOM_PALETTE[0])     # its neighbour avoids colour 2


def test_render_map_without_rooms_uses_the_space_colour():
    md = _bare()
    raw = bytearray(base64.b64decode(md["map_data"])[-md["pix_len"]:])
    md["map_data"] = base64.b64encode(_lz4_literal(bytes(255 if v in (1, 2) else v for v in raw))).decode()
    img, _, _ = render_map(md)
    assert _cell(img, 4, 3) == _blend(SPACE_COLOR)


def test_render_map_skips_the_clean_up_on_a_huge_grid(monkeypatch):
    from custom_components.tapo_rv30 import maprender
    monkeypatch.setattr(maprender, "MAP_CLEAN_MAX_CELLS", 79)    # the test map has 80 cells
    img, _, _ = render_map(_bare())
    # The robot's own cells: floor stays floor next to the rooms and at the grid edge.
    assert _cell(img, 1, 6) == _cell(img, 0, 7) == _blend(FLOOR_COLOR)
    assert _cell(img, 2, 2) == _blend(ROOM_PALETTE[0]) and _cell(img, 9, 0) == WALL_COLOR


def test_render_map_turns_the_cleaned_grid():
    img, _, _ = render_map(_bare(), 90)
    assert img.size == (8 * MAP_SCALE, 10 * MAP_SCALE)
    # turned clockwise, the wall row along the bottom becomes the left column
    assert img.getpixel((1, 5 * MAP_SCALE)) == WALL_COLOR
    assert img.getpixel((6 * MAP_SCALE + 1, 8 * MAP_SCALE + 1)) == _blend(ROOM_PALETTE[1])   # cell (8, 6)


def test_render_record_draws_the_cleaned_grid_and_path():
    from custom_components.tapo_rv30.maprender import render_record
    rec = _map()
    # a record: room 1 cells cleaned (255), room 2 left as room id, plus a short path
    width = rec["width"]
    px = bytearray(base64.b64decode(rec["map_data"])[-rec["pix_len"]:])
    for row in range(1, 4):
        for col in range(1, 5):
            px[row * width + col] = 255
    rec["map_data"] = base64.b64encode(_lz4_literal(bytes(px))).decode()
    rec["pos_array"] = "8C3/xQAMAAEAAPzRCnz/8f/k/MkKnPyVCoz8YQqI/C0KgPv5Cnj7wAps+2wKaPtsCjT7bAoA+2wJzPtsCZQ="
    rec["pos_len"] = 60
    rec["real_charge_coor"] = [300, 0, 0]       # clear of the cells sampled below
    img = render_record(rec)
    assert img.size == (width * MAP_SCALE, rec["height"] * MAP_SCALE)
    # Drawn like the live map: room 1's cleaned cells are plain floor (room 2 grows over some),
    # room 2 is the only room, so colour 1.
    assert _cell(img, 0, 2) == _blend(FLOOR_COLOR)
    assert _cell(img, 6, 5) == _blend(ROOM_PALETTE[0])


def test_furniture_glyphs_every_type_renders():
    from custom_components.tapo_rv30.const import FURNITURE_TYPES
    from custom_components.tapo_rv30.maprender import FURNITURE_GLYPHS
    assert set(FURNITURE_GLYPHS) == set(FURNITURE_TYPES)        # every named type has a glyph
    md = _map()
    md["furniture_list"] = [{"id": i, "type": t, "angle": 30 * i,
                             "vertexs": [[-80, -80], [-20, -60], [-40, 0], [-100, -20]]}   # rotated quad
                            for i, t in enumerate(FURNITURE_TYPES)]
    img, _, geom = render_map(md)
    assert len(geom["furniture"]) == len(FURNITURE_TYPES)
    assert geom["furniture"][0]["angle"] == 0 and geom["furniture"][1]["angle"] == 30


def test_room_coverage_maps_record_cells_onto_live_rooms():
    from custom_components.tapo_rv30.mapdata import grid_pixels, room_coverage
    live = _map()
    live_px = grid_pixels(live)
    rec = _map()
    width = rec["width"]
    px = bytearray(live_px)
    for row in range(1, 4):          # all of room 1 cleaned, room 2 untouched
        for col in range(1, 5):
            px[row * width + col] = 255
    rec["map_data"] = base64.b64encode(_lz4_literal(bytes(px))).decode()
    cov = room_coverage(rec, live, live_px)
    assert cov[1] == (12, 12) and cov[2] == (0, 12)
    # a record with a shifted origin still lands on the same rooms
    rec["real_origin_coor"] = [live["real_origin_coor"][0] - 50, live["real_origin_coor"][1], 0]
    px2 = bytearray(live_px)
    for row in range(1, 4):
        for col in range(2, 6):      # one cell to the right in the record grid = same mm as cols 1-4
            px2[row * width + col] = 255
    rec["map_data"] = base64.b64encode(_lz4_literal(bytes(px2))).decode()
    assert room_coverage(rec, live, live_px)[1] == (12, 12)


def _pos_array(points):
    """Encode (x_mm, y_mm) points the way getCleanRecordExtraInfo does: an 8-byte header then
    big-endian int16 pairs, LZ4 block, base64. Returns (pos_array, pos_len)."""
    import struct
    raw = b"\x00" * 8 + b"".join(struct.pack(">hh", x, y) for x, y in points)
    return base64.b64encode(_lz4_literal(raw)).decode(), len(raw)


def test_room_coverage_uses_path_not_segmentation():
    from custom_components.tapo_rv30.mapdata import grid_pixels, room_coverage
    live = _map()
    live_px = grid_pixels(live)
    # a record whose grid is the FULL room segmentation (both rooms present, no 255 mask) - the
    # format auto-area cleans use. Only the path tells which room was actually cleaned.
    rec = _map()
    ox, oy = rec["real_origin_coor"][:2]
    res = rec["resolution"]
    # drive only through room 1 (cols 1-2, rows 1-2 in grid coords), away from room 2
    pts = [(ox + gx * res, oy + gy * res) for gy in (1, 2) for gx in (1, 2)]
    rec["pos_array"], rec["pos_len"] = _pos_array(pts)
    cov = room_coverage(rec, live, live_px)
    assert cov[1][0] > 0            # room 1 was driven, so it is counted as cleaned
    assert cov[2] == (0, 12)        # room 2 is in the grid but was not driven: not cleaned
