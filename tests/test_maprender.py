import base64

from PIL import Image

from custom_components.tapo_rv30.maprender import MAP_SCALE, render_map


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
    # the wall row (gy=0) is at the bottom of the image and dark
    assert img.getpixel((MAP_SCALE * 9 + 1, img.height - 1))[:3] == (60, 60, 60)


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
