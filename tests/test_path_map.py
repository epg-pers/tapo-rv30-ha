"""The live map's trail belongs to the map it was drawn on: switching maps while docked must not
draw one floor's path across another, and switching back shows it again."""
import io
import types

from PIL import Image
from test_maprender import _map

from custom_components.tapo_rv30 import coordinator as C
from custom_components.tapo_rv30.camera import TapoMapCamera

TRAIL_A = [(-50, -150), (300, -150), (300, 150), (-50, 150)]
TRAIL_B = [(0, -100), (200, -100), (200, 100)]


def _blue(png: bytes) -> int:
    raw = Image.open(io.BytesIO(png)).convert("RGB").tobytes()
    return sum(1 for i in range(0, len(raw), 3)
               if raw[i] < 40 and abs(raw[i + 1] - 140) < 40 and abs(raw[i + 2] - 220) < 40)


def _camera_points(c) -> int:
    return TapoMapCamera.extra_state_attributes.fget(types.SimpleNamespace(coordinator=c))["path_points"]


def _coordinator(monkeypatch):
    maps = {1: {**_map(), "map_id": 1, "path_id": 11},
            2: {**_map(), "map_id": 2, "path_id": 11, "vac_coor": [2, 2, 0], "real_vac_coor": [0, -100]}}
    state = {"current": 1, "path": "A"}
    client = types.SimpleNamespace(
        get_map_info=lambda: (state["current"], [{"map_id": 1, "map_name": "", "is_saved": True},
                                                 {"map_id": 2, "map_name": "", "is_saved": True}]),
        get_map_data=lambda mid: maps[mid],
        get_path=lambda pid, s: {"pos_array": state["path"], "pos_len": 4})
    monkeypatch.setattr(C, "decode_path", lambda arr, n: list(TRAIL_A if arr == "A" else TRAIL_B))
    c = C.TapoCoordinator.__new__(C.TapoCoordinator)
    c.client = client; c.components = {}; c.lock_supported = False; c.rotation_supported = False
    c.maps = []; c.last_clean_info = {}; c._record_rendered_ts = None; c._frame_key = None
    c.map_image_bytes = None; c.path_points = []; c._path_id = None; c._path_map_id = None
    c.map_id = None; c._map_base = None; c._live_map = None
    c.rooms_last_cleaned = {}; c.entry = None
    return c, maps, state


def test_trail_stays_on_its_own_map(monkeypatch):
    c, maps, state = _coordinator(monkeypatch)
    c.data = {"status_code": 1}         # cleaning on map A
    c._refresh_map()
    assert c.shown_path() == TRAIL_A and _camera_points(c) == len(TRAIL_A)
    with_trail = _blue(c.map_image_bytes)
    assert with_trail > 0

    c.data = {"status_code": 6}         # docked, then map B made current (set_map, the app)
    state["current"] = 2
    c._refresh_map()
    assert c.map_id == 2 and c.shown_path() == []
    assert _blue(c.map_image_bytes) == 0 and _camera_points(c) == 0
    assert c.path_points == TRAIL_A     # kept: a map edit switches away and back

    state["current"] = 1                # back to A: its trail is still the right one
    c._refresh_map()
    assert c.shown_path() == TRAIL_A and _blue(c.map_image_bytes) == with_trail
    assert _camera_points(c) == len(TRAIL_A)

    state["current"] = 2                # a new run on B draws B's own trail
    maps[2]["path_id"] = 12
    state["path"] = "B"
    c.data = {"status_code": 1}
    c._refresh_map()
    assert c.shown_path() == TRAIL_B and _blue(c.map_image_bytes) > 0
    assert _camera_points(c) == len(TRAIL_B)

    c.data = {"status_code": 6}         # and A no longer shows a trail (B's is the last run)
    state["current"] = 1
    c._refresh_map()
    assert c.shown_path() == [] and _blue(c.map_image_bytes) == 0


def test_docked_poll_frame_key_follows_shown_trail(monkeypatch):
    """A docked poll on map B after a run on A must not reuse or redraw with A's trail."""
    c, maps, state = _coordinator(monkeypatch)
    c.data = {"status_code": 1}
    c._refresh_map()
    c.data = {"status_code": 6}
    state["current"] = 2
    c._refresh_map()
    assert c._frame_key[2] == 0
    c._refresh_position()               # the docked position poll
    assert c._frame_key[2] == 0 and _blue(c.map_image_bytes) == 0
