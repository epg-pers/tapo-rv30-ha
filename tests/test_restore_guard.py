"""While a restore onto a carrier is not tidied yet, the Edit tab's save and apply_map_setup must
not write to the carrier or the restored map: tidying writes the carrier's earlier setup back
and would quietly undo them. Other maps, and the coordinator's own finish, are not held up."""
import asyncio
import base64
import sys

import pytest

from custom_components.tapo_rv30 import map_edit_ws, setup_apply
from custom_components.tapo_rv30.coordinator import TapoCoordinator

CARRIER, RESTORED, OTHER = 100, 300, 200


def b64(s):
    return base64.b64encode(s.encode()).decode()


class Client:
    def __init__(self):
        self.maps = {m: {"area_list": [{"type": "room", "id": 1, "name": b64("Hall")}], "furniture_list": []}
                     for m in (CARRIER, RESTORED, OTHER)}
        self.writes = []
        self.current = CARRIER

    def send(self, method, params=None):
        assert method == "getMapInfo"
        return {"result": {"current_map_id": self.current}}

    def get_map_data(self, map_id):
        return self.maps[map_id]

    def get_presets(self):
        return []

    def get_schedules(self):
        return []

    def set_areas(self, map_id, t, items):
        self.writes.append(("set_areas", map_id, t))
        return 0

    def set_furniture(self, map_id, items):
        self.writes.append(("set_furniture", map_id))
        return 0

    def set_current_map(self, map_id):
        self.writes.append(("set_current_map", map_id))
        self.current = map_id


class Hass:
    class config:
        @staticmethod
        def path(*parts):
            return "/nonexistent/" + "/".join(parts)

    async def async_add_executor_job(self, fn, *args):
        return fn(*args)


class Coord(TapoCoordinator):
    map_busy = None

    def __init__(self):
        self.hass, self.client, self.device_name = Hass(), Client(), "Jarvis"
        self.map_lock = asyncio.Lock()
        self.pending_restore = None
        self._restore_store = None
        self.snapshot_hold, self._snapshot_hash = {}, {}
        self._finishing = False
        self.asked = 0          # live asks of the robot whether it is working
        self.maps = [{"id": m, "name": f"Map {m}"} for m in (CARRIER, RESTORED, OTHER)]

    async def _robot_working(self):
        self.asked += 1
        return False

    async def async_request_map_refresh(self):
        pass

    async def async_settings_changed(self):
        pass


def _unfinished(coord):
    coord.pending_restore = {"map_id": RESTORED, "name": "Garage", "carrier": CARRIER, "before": {"rooms": []},
                             "tail": None, "copy": False, "tidied": False, "started": 0, "done": {}}


class Conn:
    def __init__(self):
        self.errors, self.results = [], []

    def send_error(self, msg_id, code, message):
        self.errors.append((code, message))

    def send_result(self, msg_id, result):
        self.results.append(result)


def _edit(coord, map_id, monkeypatch):
    monkeypatch.setattr(map_edit_ws, "_coord", lambda hass, entity_id: coord)
    conn = Conn()
    msg = {"id": 1, "entity_id": "vacuum.jarvis", "map_id": map_id, "furniture": [],
           "rooms": [{"id": 1, "name": "Kitchen"}]}
    asyncio.run(map_edit_ws.ws_edit_apply(coord.hass, conn, msg))
    return conn


@pytest.mark.parametrize("map_id", [CARRIER, RESTORED])
def test_edit_refused_on_the_restore_maps_while_unfinished(monkeypatch, map_id):
    coord = Coord()
    _unfinished(coord)
    conn = _edit(coord, map_id, monkeypatch)
    assert conn.errors and conn.errors[0][0] == "busy" and "restore" in conn.errors[0][1]
    assert not conn.results and coord.client.writes == []
    assert not coord.map_lock.locked() and coord.asked == 0     # refused without asking the robot


def test_edit_allowed_on_an_unrelated_map_while_unfinished(monkeypatch):
    coord = Coord()
    _unfinished(coord)
    conn = _edit(coord, OTHER, monkeypatch)
    assert not conn.errors and conn.results
    assert ("set_furniture", OTHER) in coord.client.writes


def test_edit_allowed_once_the_restore_is_tidied(monkeypatch):
    coord = Coord()
    _unfinished(coord)
    coord.pending_restore["tidied"] = True       # carrier put back; only the app save is awaited
    conn = _edit(coord, CARRIER, monkeypatch)
    assert not conn.errors and ("set_areas", CARRIER, "room") in coord.client.writes
    coord.pending_restore = None
    conn = _edit(coord, RESTORED, monkeypatch)
    assert not conn.errors and ("set_areas", RESTORED, "room") in coord.client.writes


def test_an_older_record_without_a_carrier_guards_only_its_map(monkeypatch):
    coord = Coord()
    coord.pending_restore = {"map_id": RESTORED, "name": "Garage", "tidied": False, "started": 0, "done": {}}
    conn = _edit(coord, RESTORED, monkeypatch)
    assert conn.errors and conn.errors[0][0] == "busy" and coord.client.writes == []
    conn = _edit(coord, CARRIER, monkeypatch)
    assert not conn.errors and ("set_areas", CARRIER, "room") in coord.client.writes


SNAP = {"map_id": RESTORED, "map_name": "Garage", "areas": {"room": [{"type": "room", "id": 1, "name": b64("Garage hall")}]},
        "furniture": [], "presets": [], "schedules": []}


def test_apply_setup_refused_while_unfinished_but_a_dry_run_is_not():
    coord = Coord()
    _unfinished(coord)
    hass = coord.hass
    for map_id in (CARRIER, RESTORED):
        with pytest.raises(setup_apply.MapBusy, match="part of a restore that is still being tidied up"):
            asyncio.run(setup_apply.apply_setup(hass, coord, map_id, SNAP))
    assert coord.client.writes == [] and not coord.map_lock.locked() and coord.asked == 0
    out = asyncio.run(setup_apply.apply_setup(hass, coord, CARRIER, SNAP, dry_run=True))
    assert out["dry_run"] is True and out["plan"]["room_names"]
    coord.client.current = OTHER        # already on it: no switch (and no wait for one)
    asyncio.run(setup_apply.apply_setup(hass, coord, OTHER, SNAP))
    assert ("set_areas", OTHER, "room") in coord.client.writes


def test_finish_restore_still_applies_the_saved_setup(monkeypatch):
    coord = Coord()
    _unfinished(coord)
    notes = []
    monkeypatch.setattr(sys.modules["homeassistant.components.persistent_notification"], "async_create",
                        lambda hass, msg, **kw: notes.append(msg), raising=False)
    monkeypatch.setattr(setup_apply, "snapshot_folders", lambda hass, coord: [])
    monkeypatch.setattr(setup_apply, "find_snapshot", lambda folders, map_id, ref: SNAP)
    assert asyncio.run(coord.async_finish_restore()) is None      # not tidied: does nothing yet
    assert coord.client.writes == [] and coord.pending_restore is not None
    coord.pending_restore["tidied"] = True
    coord.client.current = RESTORED     # a restored map comes back as the current one
    result = asyncio.run(coord.async_finish_restore())
    assert result and result["written"].get("room") == 0
    assert ("set_areas", RESTORED, "room") in coord.client.writes
    assert coord.pending_restore is None and notes and "is restored" in notes[0]


def _snapshot_coord(monkeypatch, folder, area_list):
    coord = Coord()
    coord.map_id, coord._snapshot_hash, coord.snapshot_hold = OTHER, {}, {}
    coord._map_layers = {"map_id": OTHER, "map_name": "Map", "area_list": area_list, "furniture_list": []}
    coord._presets_raw, coord.settings = [], {"schedules": {"rule_list": []}}
    monkeypatch.setattr(setup_apply, "snapshots_folder", lambda hass, c: str(folder))
    return coord


def test_a_map_restored_over_itself_keeps_its_saved_setup(monkeypatch, tmp_path):
    """The restored map can lose zones yet keep its room names (so it does not look degraded):
    until apply_map_setup or save_map_setup, or the hold runs out, it only goes to history."""
    import json
    import time
    room = {"type": "room", "id": 1, "name": b64("Hall")}
    zone = {"type": "forbid", "id": 301, "vertexs": [[0, 0], [9, 0], [9, 9], [0, 9]]}
    coord = _snapshot_coord(monkeypatch, tmp_path, [room, zone])
    asyncio.run(coord._auto_snapshot_now())
    saved = tmp_path / f"{OTHER}.json"
    assert json.loads(saved.read_text())["areas"].get("forbid")
    assert coord.hold_snapshot(OTHER) and not coord.hold_snapshot(OTHER)
    coord._map_layers["area_list"] = [room]          # restored: the zone is gone
    asyncio.run(coord._auto_snapshot_now())
    assert json.loads(saved.read_text())["areas"].get("forbid")
    assert list((tmp_path / "history").iterdir())     # (history keeps it)
    coord.release_snapshot(OTHER)                    # apply_map_setup / save_map_setup
    asyncio.run(coord._auto_snapshot_now())
    assert not json.loads(saved.read_text())["areas"].get("forbid")
    # and a hold that is never released runs out
    coord._map_layers["area_list"] = [room, zone]
    coord.snapshot_hold[OTHER] = time.time() - coord.SNAPSHOT_HOLD_S - 1
    asyncio.run(coord._auto_snapshot_now())
    assert json.loads(saved.read_text())["areas"].get("forbid") and not coord.snapshot_hold


def test_only_a_full_apply_of_the_maps_own_setup_releases_the_hold():
    import time
    coord = Coord()
    coord._snapshot_hash, coord.snapshot_hold = {}, {OTHER: time.time()}
    own, other = {"map_id": OTHER}, {"map_id": RESTORED}
    coord.release_after_apply(OTHER, own, {"skipped": ["preset 'Daily': refused"]})
    coord.release_after_apply(OTHER, other, {"skipped": []})
    assert OTHER in coord.snapshot_hold
    coord.release_after_apply(OTHER, own, {"skipped": []})
    assert OTHER not in coord.snapshot_hold
