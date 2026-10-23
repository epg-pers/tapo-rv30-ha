"""Tests for .bkmap decoding and the backup folder store (pure, no Home Assistant)."""
import base64
import gzip
import io
import json
import struct
import tarfile

import pytest
from PIL import Image

from custom_components.tapo_rv30 import backupstore, mapbackup


def _make_bkmap(md5="105730522cf4c252d51650e49c41b045", bound=None, dock=(-0.6, 0.03),
                area_list=None, furniture=None, gridmap_size=400):
    """Build a .bkmap the way the robot does: MZ header + md5 name + gzip(tar) + JSON tail.
    Byte-exact layout is not required; the parser locates the parts by their markers."""
    bound = bound or {"navmap_min_x": -3.75, "navmap_max_x": 4.75,
                      "navmap_min_y": -5.2, "navmap_max_y": 4.3}
    files = {
        "navmap_bound.json": json.dumps(bound).encode(),
        "charger_pose.json": json.dumps({"charger_phi": 0.0, "charger_pose": list(dock)}).encode(),
        "map.gridmap": struct.pack("<if4fii", 2, 0.05, 10, -10, 10, -10, 400, 400) + bytes(gridmap_size),
        "area_info.json": b"{}\n",
        "area_user.json": b"{}\n",
    }
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w") as tf:
        for name, raw in files.items():
            ti = tarfile.TarInfo("./" + name)
            ti.size = len(raw)
            tf.addfile(ti, io.BytesIO(raw))
    gz = gzip.compress(tar_buf.getvalue())
    tail = json.dumps({"real_origin_coor": [-3274, -4025, 0],
                       "area_list": area_list or [], "furniture_list": furniture or []}).encode()
    header = b"MZ" + bytes(16) + b"\xaa\x55" + struct.pack("<I", 2)
    header += bytes([len(md5)]) + md5.encode() + b"\x01\x00\x00\xd0\x42"
    return header + gz + struct.pack("<I", len(tail)) + tail


def test_parse_bkmap_roundtrip():
    data = _make_bkmap()
    parsed = mapbackup.parse_bkmap(data)
    assert parsed["md5"] == "105730522cf4c252d51650e49c41b045"
    assert set(parsed["members"]) == {"navmap_bound.json", "charger_pose.json", "map.gridmap",
                                      "area_info.json", "area_user.json"}
    assert parsed["tail"]["real_origin_coor"] == [-3274, -4025, 0]


def test_parse_bkmap_rejects_junk():
    with pytest.raises(ValueError):
        mapbackup.parse_bkmap(b"not a backup, no magic here")
    with pytest.raises(ValueError):
        mapbackup.parse_bkmap(b"MZ" + b"\x00" * 50)  # magic but no gzip member


def test_facts():
    data = _make_bkmap(area_list=[{"type": "room", "id": 1}, {"type": "room", "id": 2}],
                       furniture=[{"type": 101}])
    f = mapbackup.facts(data)
    assert f["extent"]["width_m"] == 8.5
    assert f["extent"]["height_m"] == 9.5
    assert f["extent"]["area_m2"] == pytest.approx(80.8, abs=0.1)
    assert f["dock_m"] == [-0.6, 0.03]
    assert f["room_count"] == 2
    assert f["furniture_count"] == 1
    assert "map.gridmap" in f["components"]
    assert f["md5"] == "105730522cf4c252d51650e49c41b045"


def test_scan_groups_and_orders(tmp_path):
    (tmp_path / "cloud_7_1000.bin").write_bytes(_make_bkmap())
    (tmp_path / "cloud_7_1000_snapshot.png").write_bytes(b"\x89PNG\r\n\x1a\n")
    (tmp_path / "cloud_9_2000.bin").write_bytes(_make_bkmap())
    (tmp_path / "local_9_20250101-000000.json").write_text("{}")
    (tmp_path / "unrelated.txt").write_text("x")
    entries = backupstore.scan(str(tmp_path))
    assert [e["file"] for e in entries] == ["cloud_9_2000.bin", "cloud_7_1000.bin"]  # newest first
    e7 = next(e for e in entries if e["map_id"] == 7)
    assert e7["snapshot"] == "cloud_7_1000_snapshot.png"
    e9 = next(e for e in entries if e["map_id"] == 9)
    assert e9["local_json"] == "local_9_20250101-000000.json"


def test_scan_missing_folder():
    assert backupstore.scan("/no/such/folder") == []


def test_safe_path_rejects_traversal(tmp_path):
    (tmp_path / "ok.bin").write_bytes(b"x")
    assert backupstore.safe_path(str(tmp_path), "ok.bin") is not None
    assert backupstore.safe_path(str(tmp_path), "../ok.bin") is None
    assert backupstore.safe_path(str(tmp_path), "/etc/passwd") is None
    assert backupstore.safe_path(str(tmp_path), "nope.bin") is None


def test_image_png_prefers_snapshot(tmp_path):
    snap = io.BytesIO()
    Image.new("RGB", (4, 4), (10, 20, 30)).save(snap, format="PNG")
    (tmp_path / "cloud_7_1000.bin").write_bytes(_make_bkmap())
    (tmp_path / "cloud_7_1000_snapshot.png").write_bytes(snap.getvalue())
    entry = backupstore.scan(str(tmp_path))[0]
    png, mime = backupstore.image_png(str(tmp_path), entry)
    assert mime == "image/png"
    assert png == snap.getvalue()  # served as-is


def test_image_png_schematic_fallback(tmp_path):
    (tmp_path / "cloud_7_1000.bin").write_bytes(_make_bkmap())
    entry = backupstore.scan(str(tmp_path))[0]
    png, mime = backupstore.image_png(str(tmp_path), entry)
    assert mime == "image/png"
    img = Image.open(io.BytesIO(png))
    assert img.width > 0 and img.height > 0  # explored extent drawn to scale


def _lz4_literal(raw: bytes) -> bytes:
    n = len(raw)
    if n < 15:
        return bytes([n << 4]) + raw
    ext = n - 15
    out = bytes([0xF0])
    while ext >= 255:
        out += b"\xff"; ext -= 255
    return out + bytes([ext]) + raw


def _getmapdata():
    w, h = 10, 8
    px = bytearray([255] * (w * h))
    for col in range(w):
        px[col] = 0
    raw = bytes(px)
    return {"map_id": 9, "map_name": base64.b64encode(b"Down").decode(), "width": w, "height": h,
            "pix_len": len(raw), "map_data": base64.b64encode(_lz4_literal(raw)).decode(),
            "resolution": 50, "real_origin_coor": [-100, -200, 0], "charge_coor": [2, 2, 0],
            "area_list": []}


def test_image_png_renders_companion_getmapdata(tmp_path):
    (tmp_path / "cloud_9_2000.bin").write_bytes(_make_bkmap())  # no snapshot
    (tmp_path / "local_9_20250101-000000.json").write_text(json.dumps(_getmapdata()))
    entry = backupstore.scan(str(tmp_path))[0]
    png, mime = backupstore.image_png(str(tmp_path), entry)
    assert mime == "image/png"
    img = Image.open(io.BytesIO(png))
    assert img.size == (10 * 4, 8 * 4)  # render_map scales the grid by MAP_SCALE


def test_thumb_downscales():
    big = io.BytesIO()
    Image.new("RGBA", (800, 600), (0, 0, 0, 255)).save(big, format="PNG")
    uri = backupstore.thumb(big.getvalue(), "image/png")
    assert uri.startswith("data:image/png;base64,")
    img = Image.open(io.BytesIO(base64.b64decode(uri.split(",", 1)[1])))
    assert max(img.size) <= backupstore.THUMB_PX
