"""Map rotation (the robot's rotate_angle): the picture, the room mask, the mm -> px transform
and the geometry all turn together, at every quarter turn, and the card / editor maths in the
sidebar page and card turns back exactly."""
import base64
import io
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from PIL import Image
from test_maprender import _map

from custom_components.tapo_rv30 import maprender as M

ROT = (0, 90, 180, 270)
FRONT = Path(__file__).resolve().parent.parent / "custom_components" / "tapo_rv30" / "frontend"


def _points(m):
    """Cell centres in mm across the whole grid."""
    res, (ox, oy) = m["resolution"], m["real_origin_coor"][:2]
    return [(ox + (gx + 0.5) * res, oy + (gy + 0.5) * res) for gx in range(m["width"]) for gy in range(m["height"])]


@pytest.mark.parametrize("rot", ROT)
def test_picture_and_transform_turn_together(rot):
    # The bare grid (labels, outlines and the dock are drawn upright on purpose, so they would
    # differ): every cell must land on the same colour.
    m = {**_map(), "area_list": [], "furniture_list": [], "charge_coor": None}
    base, _, g0 = M.render_map(m, 0)
    img, _, g = M.render_map(m, rot)
    w, h = base.size
    assert img.size == ((h, w) if rot in (90, 270) else (w, h))
    assert g["rotation"] == rot and g["image_size"] == list(img.size)
    t0, t = M._px_transform(m, 0), M._px_transform(m, rot)
    for x, y in _points(m):
        a, b = t0(x, y), t(x, y)
        assert b == M.rotate_px(*a, w, h, rot)
        assert img.getpixel((int(b[0]), int(b[1]))) == base.getpixel((int(a[0]), int(a[1])))


def test_labels_stay_upright():
    # A label drawn on the turned picture reads the same way: the 90 degree picture is not just
    # the 0 degree one turned (that would put the text on its side).
    m = _map()
    a, b = M.render_map(m, 0)[0], M.render_map(m, 90)[0]
    assert b.tobytes() != a.transpose(Image.Transpose.ROTATE_270).tobytes()


@pytest.mark.parametrize("rot", ROT)
def test_room_mask_turns_with_the_picture(rot):
    m = _map()
    mask0 = Image.open(io.BytesIO(M.room_mask_png(m, 0)))
    mask = Image.open(io.BytesIO(M.room_mask_png(m, rot)))
    t0, t = M._px_transform(m, 0), M._px_transform(m, rot)
    for x, y in _points(m):
        a, b = t0(x, y), t(x, y)
        s = M.MAP_SCALE
        assert mask.getpixel((int(b[0] // s), int(b[1] // s))) == mask0.getpixel((int(a[0] // s), int(a[1] // s)))


@pytest.mark.parametrize("rot", ROT)
def test_room_boxes_and_dock_follow(rot):
    m = _map()
    base, rooms0, g0 = M.render_map(m, 0)
    _, rooms, g = M.render_map(m, rot)
    w, h = base.size
    for r0, r in zip(rooms0, rooms, strict=True):
        assert r["centre"] == list(M.rotate_px(*r0["centre"], w, h, rot))
        x0, y0, x1, y1 = r["bbox"]
        assert x0 <= x1 and y0 <= y1
        corners = [M.rotate_px(x, y, w, h, rot) for x in r0["bbox"][::2] for y in r0["bbox"][1::2]]
        assert [x0, y0, x1, y1] == [min(c[0] for c in corners), min(c[1] for c in corners),
                                    max(c[0] for c in corners), max(c[1] for c in corners)]
    if g0["dock_px"]:
        assert g["dock_px"] == list(M.rotate_px(*g0["dock_px"], w, h, rot))


@pytest.mark.parametrize("rot", ROT)
def test_record_picture_turns(rot):
    rec = _map()
    a, b = M.render_record(rec, 0), M.render_record(rec, rot)
    assert b.size == ((a.height, a.width) if rot in (90, 270) else a.size)


def test_rotation_values_are_sanitised():
    assert [M.rotation_of(v) for v in (0, 90, "180", 270, 360, 450, 45, None, "x")] == [0, 90, 180, 270, 0, 90, 0, 0, 0]


def _js_helpers(name):
    src = (FRONT / name).read_text()
    return "\n".join(re.search(rf"const {f} = \(x, y, g\) => {{.*?\n}};", src, re.S).group(0) for f in ("turnPx", "unturnPx"))


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
@pytest.mark.parametrize("name", ["tapo-rv30-card.js", "tapo-rv30-panel.js"])
def test_frontend_turns_like_the_integration_and_back(name):
    m = _map()
    _, _, g = M.render_map(m, 0)
    cases = []
    for rot in ROT:
        geo = {**g, "rotation": rot}
        t0, t = M._px_transform(m, 0), M._px_transform(m, rot)
        cases.append({"g": geo, "pts": [[*t0(x, y), *t(x, y)] for x, y in _points(m)[::7]]})
    script = _js_helpers(name) + f"""
const cases = {json.dumps(cases)}; let bad = 0;
for (const c of cases) for (const [ux, uy, rx, ry] of c.pts) {{
  const [a, b] = turnPx(ux, uy, c.g), [p, q] = unturnPx(rx, ry, c.g);
  if (Math.abs(a - rx) > 1e-9 || Math.abs(b - ry) > 1e-9 || Math.abs(p - ux) > 1e-9 || Math.abs(q - uy) > 1e-9) bad++;
}}
console.log(bad);"""
    out = subprocess.run(["node", "-e", script], capture_output=True, text=True, check=True).stdout.strip()
    assert out == "0"


def test_the_robots_payload(tmp_path, monkeypatch):
    from custom_components.tapo_rv30 import tpap as T
    c = T.TapoVacuumClient("192.0.2.1", "u", "p", cache_dir=tmp_path)
    sent = []
    monkeypatch.setattr(c, "send", lambda m, p=None: sent.append((m, p)) or {"result": {}})
    c.set_map_rotation(1792568378, 90)
    assert sent == [("setMapInfo", {"map_list": [{"map_id": 1792568378, "rotate_angle": 90}]})]
    assert base64  # (imported for parity with the other map tests)
