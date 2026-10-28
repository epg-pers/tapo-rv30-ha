"""Per-room cleaning direction (floor_texture): horizontal and vertical as the map is shown, mapped to
the robot's frame both ways; the room write sends every room back as read with only the target's
floor_texture changed; refused without the robot's support, while a restore is being tidied, on an
unsaved map, or while the robot works. Made-up house."""
import asyncio
import base64

import pytest

from custom_components.tapo_rv30 import map_edit_ws
from custom_components.tapo_rv30.coordinator import TapoCoordinator
from custom_components.tapo_rv30.mapdata import direction_texture, room_areas, texture_direction, valid_texture
from custom_components.tapo_rv30.maprender import render_map

HOME, LOFT, NEW = 100, 200, 300


def b64(s):
    return base64.b64encode(s.encode()).decode()


def _rooms():
    return [
        {"type": "room", "id": 1, "name": b64("Hall"), "color": 2, "floor_material": 1, "floor_texture": -1,
         "carpet_strategy": 0, "label": 3, "define_type": 0, "vertexs": [[0, 0], [10, 0], [10, 10]]},
        {"type": "room", "id": 2, "name": b64("Den"), "color": 5, "floor_material": 0, "floor_texture": 90,
         "carpet_strategy": 1, "label": 0},
        {"type": "room", "id": 3, "name": b64("Pantry"), "color": 1},
        {"type": "forbid", "id": 301, "vertexs": [[0, 0], [5, 0], [5, 5], [0, 5]]},
    ]


# ---- the mapping, both ways ---------------------------------------------------------------

@pytest.mark.parametrize("rotation,horizontal,vertical", [(0, 0, 90), (180, 0, 90), (90, 90, 0), (270, 90, 0)])
def test_direction_follows_the_map_as_shown(rotation, horizontal, vertical):
    assert direction_texture("horizontal", rotation) == horizontal
    assert direction_texture("Vertical ", rotation) == vertical
    assert direction_texture("default", rotation) == -1
    assert texture_direction(horizontal, rotation) == "horizontal"
    assert texture_direction(vertical, rotation) == "vertical"
    assert texture_direction(-1, rotation) == texture_direction(None, rotation) == "default"


def test_direction_values_are_checked():
    with pytest.raises(ValueError):
        direction_texture("diagonal")
    assert texture_direction(45) is None and texture_direction(True) is None
    assert [v for v in (-1, 0, 90, 45, 180, True, "0", None, 0.0) if valid_texture(v)] == [-1, 0, 90]


def test_room_write_changes_only_the_targets_direction():
    before = _rooms()
    out = room_areas(before, {2: {"floor_texture": 0}})
    assert before == _rooms()                                           # the read is not changed
    assert [r["id"] for r in out] == [1, 2, 3]                          # every room, no zones
    assert out[1] == {"type": "room", "id": 2, "name": b64("Den"), "color": 5, "floor_material": 0,
                      "floor_texture": 0, "carpet_strategy": 1, "label": 0}
    # The others exactly as read, without vertexs (as every room write here sends them).
    assert out[0] == {k: v for k, v in _rooms()[0].items() if k != "vertexs"}
    assert out[2] == {"type": "room", "id": 3, "name": b64("Pantry"), "color": 1}


def test_room_write_renames():
    out = room_areas(_rooms(), {3: {"name": "Larder", "floor_texture": 90}})
    assert [r["id"] for r in out] == [1, 2, 3]
    assert out[2] == {"type": "room", "id": 3, "name": b64("Larder"), "color": 1, "floor_texture": 90}


@pytest.mark.parametrize("area_list,changes,match", [
    ([], {}, "no rooms"),
    (None, {1: {"floor_texture": 0}}, "no rooms"),
    ([a for a in _rooms() if a["type"] != "room"], {1: {"floor_texture": 0}}, "no rooms"),
    (_rooms(), {9: {"floor_texture": 0}, 1: {"floor_texture": 0}}, r"no room \[9\]"),
])
def test_room_write_never_clears_or_drops_rooms(area_list, changes, match):
    with pytest.raises(ValueError, match=match):
        room_areas(area_list, changes)


def test_room_geometry_reports_the_direction_as_shown():
    width, height = 4, 2
    raw = bytes([1, 1, 2, 2] * height)
    md = {"map_id": 9, "map_name": b64("Test"), "width": width, "height": height, "pix_len": len(raw),
          "map_data": base64.b64encode(bytes([len(raw) << 4]) + raw).decode(), "resolution": 50,
          "real_origin_coor": [0, 0, 0],
          "area_list": [{"type": "room", "id": 1, "name": b64("Hall"), "floor_texture": 0},
                        {"type": "room", "id": 2, "name": b64("Den")}]}
    for rotation, shown in ((0, "horizontal"), (90, "vertical")):
        _, rooms, _ = render_map(md, rotation)
        by_id = {r["id"]: r for r in rooms}
        assert by_id[1]["floor_texture"] == 0 and by_id[1]["cleaning_direction"] == shown
        assert "floor_texture" not in by_id[2] and "cleaning_direction" not in by_id[2]


# ---- the coordinator's write (the service) ----------------------------------------------------

class Client:
    def __init__(self):
        self.maps = {HOME: {"area_list": _rooms()}, LOFT: {"area_list": _rooms()}, NEW: {"area_list": _rooms()}}
        self.rotate = {HOME: 0, LOFT: 90, NEW: 0}
        self.saved = {HOME: True, LOFT: True, NEW: False}
        self.writes = []
        self.ignore = False         # accept the write but keep the old directions
        self.mangle = None          # after a write, change the map like this (a robot gone wrong)

    def get_map_info(self):
        return HOME, [{"map_id": m, "is_saved": self.saved[m], "rotate_angle": self.rotate[m]} for m in self.maps]

    def get_map_data(self, map_id):
        import copy
        return copy.deepcopy(self.maps[map_id])

    def set_areas(self, map_id, t, items):
        self.writes.append((map_id, t, items))
        if not self.ignore:
            by_id = {a["id"]: a for a in items}
            for a in self.maps[map_id]["area_list"]:
                if a["type"] == t and a["id"] in by_id:
                    a["floor_texture"] = by_id[a["id"]].get("floor_texture")
        if self.mangle:
            self.mangle(self.maps[map_id]["area_list"])
        return 0

    def set_furniture(self, map_id, items):
        self.writes.append((map_id, "furniture", items))
        return 0


class Hass:
    async def async_add_executor_job(self, fn, *args):
        return fn(*args)


class Coord(TapoCoordinator):
    map_busy = None

    def __init__(self):
        self.hass, self.client, self.device_name = Hass(), Client(), "Jarvis"
        self.map_lock = asyncio.Lock()
        self.pending_restore = None
        self.components = {"clean": 1, "clean_angle": 1}
        self.working = False
        self.refreshed = 0
        self.maps = [{"id": HOME, "rotation": 0}, {"id": LOFT, "rotation": 90}]
        self.map_id = HOME

    async def _robot_working(self):
        return self.working

    async def async_request_map_refresh(self):
        self.refreshed += 1


def _set(coord, map_id, rooms, direction):
    return asyncio.run(coord.async_set_room_directions(map_id, rooms, direction))


def test_service_write_sends_every_room_with_only_the_target_changed():
    coord = Coord()
    out = _set(coord, HOME, [1], "vertical")
    (map_id, t, items), = coord.client.writes
    assert (map_id, t) == (HOME, "room")
    assert items == room_areas(_rooms(), {1: {"floor_texture": 90}})
    assert out == [{"id": 1, "name": "Hall", "old": "default", "new": "vertical", "old_floor_texture": -1,
                    "floor_texture": 90}]
    assert coord.refreshed == 1 and not coord.map_lock.locked()


def test_service_write_uses_the_maps_own_rotation():
    coord = Coord()
    out = _set(coord, LOFT, [1, 2], "horizontal")          # LOFT is shown turned 90
    items = coord.client.writes[0][2]
    assert [r.get("floor_texture") for r in items] == [90, 90, None]
    assert [(o["old"], o["new"]) for o in out] == [("default", "horizontal"), ("horizontal", "horizontal")]


def test_nothing_written_when_already_so():
    coord = Coord()
    out = _set(coord, HOME, [2], "vertical")
    assert coord.client.writes == [] and out[0]["old"] == "vertical"


def test_robot_that_keeps_the_old_direction_is_reported():
    coord = Coord()
    coord.client.ignore = True
    with pytest.raises(RuntimeError, match="old direction"):
        _set(coord, HOME, [1], "horizontal")
    assert coord.refreshed == 1


@pytest.mark.parametrize("mangle", [
    lambda rooms: rooms[1].update(name=b64("Lounge")),
    lambda rooms: rooms[2].update(color=9),
    lambda rooms: rooms.pop(2),
])
def test_robot_that_changes_anything_else_is_reported(mangle):
    coord = Coord()
    coord.client.mangle = mangle
    with pytest.raises(RuntimeError, match="rooms, names or colours"):
        _set(coord, HOME, [1], "horizontal")


def test_a_read_with_no_rooms_is_never_written_back():
    coord = Coord()
    coord.client.maps[HOME] = {"area_list": [a for a in _rooms() if a["type"] != "room"]}
    with pytest.raises(ValueError, match="no rooms"):
        _set(coord, HOME, [1], "horizontal")
    coord.client.maps[HOME] = {}
    with pytest.raises(ValueError, match="no rooms"):
        _set(coord, HOME, [1], "horizontal")
    assert coord.client.writes == []


@pytest.mark.parametrize("components", [{}, {"clean": 1}, {"clean_angle": 0}, {"clean_angle": "x"}, {"clean_angle": None}])
def test_support_needs_clean_angle_read_from_the_robot(components):
    coord = Coord()
    coord.components = components
    assert coord.clean_direction_supported is False


@pytest.mark.parametrize("setup,match", [
    (lambda c: c.components.pop("clean_angle"), "no per-room cleaning direction"),
    (lambda c: c.components.update(clean_angle=0), "no per-room cleaning direction"),
    (lambda c: setattr(c, "map_busy", "cleaning"), "is cleaning"),
    (lambda c: setattr(c, "working", True), "is working"),
    (lambda c: setattr(c, "pending_restore", {"map_id": NEW, "carrier": HOME, "tidied": False}), "restore"),
])
def test_refused_before_anything_is_written(setup, match):
    coord = Coord()
    setup(coord)
    with pytest.raises(ValueError, match=match):
        _set(coord, HOME, [1], "horizontal")
    assert coord.client.writes == [] and not coord.map_lock.locked()


def test_refused_on_an_unsaved_map_and_for_bad_input():
    coord = Coord()
    with pytest.raises(ValueError, match="not saved"):
        _set(coord, NEW, [1], "horizontal")
    with pytest.raises(ValueError, match="direction must be"):
        _set(coord, HOME, [1], "sideways")
    with pytest.raises(ValueError, match="no room"):
        _set(coord, HOME, [7], "horizontal")
    assert coord.client.writes == []


def test_refused_while_another_map_write_runs():
    coord = Coord()

    async def go():
        async with coord.map_lock:
            await coord.async_set_room_directions(HOME, [1], "horizontal")
    with pytest.raises(ValueError, match="map written"):
        asyncio.run(go())


def test_another_restores_maps_are_not_held_up():
    coord = Coord()
    coord.pending_restore = {"map_id": NEW, "carrier": LOFT, "tidied": False}
    _set(coord, HOME, [1], "horizontal")
    assert coord.client.writes


# ---- the editor's save -------------------------------------------------------------------------

class EditClient(Client):
    def send(self, method, params=None):
        assert method == "getMapInfo"
        return {"result": {"current_map_id": HOME}}


class Conn:
    def __init__(self):
        self.errors, self.results = [], []

    def send_error(self, msg_id, code, message):
        self.errors.append((code, message))

    def send_result(self, msg_id, result):
        self.results.append(result)


def _edit(coord, monkeypatch, rooms, map_id=HOME):
    coord.client = EditClient()
    monkeypatch.setattr(map_edit_ws, "_coord", lambda hass, entity_id: coord)
    conn = Conn()
    asyncio.run(map_edit_ws.ws_edit_apply(coord.hass, conn, {"id": 1, "entity_id": "vacuum.jarvis",
                                                              "map_id": map_id, "rooms": rooms}))
    return conn


def test_editor_save_writes_every_room_with_the_directions_changed(monkeypatch):
    coord = Coord()
    conn = _edit(coord, monkeypatch, [{"id": 3, "floor_texture": 0}, {"id": 2, "floor_texture": -1}])
    assert not conn.errors and conn.results
    (map_id, t, items), = coord.client.writes
    assert items == room_areas(_rooms(), {3: {"floor_texture": 0}, 2: {"floor_texture": -1}})
    assert items[0]["name"] == b64("Hall") and items[1]["name"] == b64("Den")      # names kept as read


@pytest.mark.parametrize("value", [45, "0", True, None])
def test_editor_save_refuses_a_bad_direction(monkeypatch, value):
    coord = Coord()
    conn = _edit(coord, monkeypatch, [{"id": 1, "floor_texture": value}])
    assert conn.errors[0][0] == "invalid" and coord.client.writes == []


def test_editor_save_refuses_a_direction_the_robot_cannot_take(monkeypatch):
    coord = Coord()
    coord.components.pop("clean_angle")
    conn = _edit(coord, monkeypatch, [{"id": 1, "floor_texture": 0}])
    assert conn.errors[0][0] == "not_supported" and coord.client.writes == []
    conn = _edit(coord, monkeypatch, [{"id": 1, "name": "Hallway"}])       # names still go
    assert not conn.errors and coord.client.writes[0][2][0]["name"] == b64("Hallway")


@pytest.mark.parametrize("area_list", [[], [a for a in _rooms() if a["type"] != "room"], None])
def test_editor_save_refused_when_the_read_has_no_rooms(monkeypatch, area_list):
    coord = Coord()
    coord.client = EditClient()
    coord.client.maps[HOME] = {} if area_list is None else {"area_list": area_list}
    monkeypatch.setattr(map_edit_ws, "_coord", lambda hass, entity_id: coord)
    conn = Conn()
    asyncio.run(map_edit_ws.ws_edit_apply(coord.hass, conn, {
        "id": 1, "entity_id": "vacuum.jarvis", "map_id": HOME, "furniture": [],
        "areas": {"forbid": []}, "rooms": [{"id": 1, "floor_texture": 0}]}))
    assert conn.errors[0][0] == "write_failed" and "no rooms" in conn.errors[0][1]
    assert coord.client.writes == []           # nor the zones or furniture of the same save


def test_editor_save_refused_for_a_room_not_on_the_map(monkeypatch):
    coord = Coord()
    conn = _edit(coord, monkeypatch, [{"id": 1, "floor_texture": 0}, {"id": 9, "floor_texture": 90}])
    assert conn.errors[0][0] == "write_failed" and "[9]" in conn.errors[0][1] and coord.client.writes == []


def test_editor_save_refused_during_a_restore_of_that_map(monkeypatch):
    coord = Coord()
    coord.pending_restore = {"map_id": NEW, "carrier": HOME, "tidied": False}
    conn = _edit(coord, monkeypatch, [{"id": 1, "floor_texture": 0}])
    assert conn.errors[0][0] == "busy" and "restore" in conn.errors[0][1] and coord.client.writes == []
