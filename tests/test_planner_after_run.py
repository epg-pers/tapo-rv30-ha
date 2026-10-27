"""A run the planner did not start (the card, the app, the robot's own schedule) ends at the dock:
the planner must not send the robot straight back to the rooms it has just cleaned. The run's
record is folded into room freshness on the poll that reads it, and while the robot has not
written it yet the planner waits."""
import asyncio
import time
import types

from custom_components.tapo_rv30 import coordinator as C
from custom_components.tapo_rv30 import planner as P
from custom_components.tapo_rv30.planlogic import decide

NOW = int(time.time())
OLD = NOW - 5 * 86400       # the kitchen's last clean before this run: due
NEW = NOW - 40 * 60         # the run that has just ended (a record's timestamp is its start)
OLD_RECORDS = {"record_list": [{"timestamp": OLD, "record_index": 0, "map_id": 1}]}
NEW_RECORDS = {"record_list": OLD_RECORDS["record_list"] + [{"timestamp": NEW, "record_index": 1, "map_id": 1}]}


class Hass:
    bus = types.SimpleNamespace(async_fire=lambda *a, **k: None)

    async def async_add_executor_job(self, fn, *a):
        return fn(*a)


class Client:
    def __init__(self, written):
        self.written = written      # has the robot written this run's record yet?

    def get_clean_records(self):
        return NEW_RECORDS if self.written else OLD_RECORDS

    def get_clean_record_detail(self, index):
        return {"map_id": 1, "map_name": ""}


def _coord(monkeypatch, written):
    monkeypatch.setattr(C, "render_record", lambda detail, rotation: None)
    monkeypatch.setattr(C, "_png", lambda image: b"")
    c = C.TapoCoordinator.__new__(C.TapoCoordinator)
    c.hass, c.entry, c.client = Hass(), None, Client(written)
    c.settings, c.settings_read_at, c.schedules, c._robot_tz = {"records": OLD_RECORDS}, NOW, [], None
    c.map_id, c.rooms, c.maps = 1, [{"id": 3, "name": ""}], []
    c._live_map, c._live_pixels = {"map_id": 1}, b"x"
    c._freshness_loaded, c._freshness_store = True, None
    c._processed_records, c._record_failures, c._record_rendered_ts = {OLD}, {}, OLD
    c.rooms_last_cleaned = {"1:3": {"last_cleaned": OLD}}
    c._history_pruned_at = time.time()
    c.last_clean_info, c.device_name, c.device_model = {}, "Robot", "RV30"
    c.rotation_for = lambda map_id: 0
    c.dock_actions, c.current_room = set(), None
    c.bool_settings, c.presets, c.vac_pos, c.path_points, c._path_map_id = {}, [], None, [], None
    # A poll that reads only the status and the position, as between full map reads.
    c._info_fetched = c._caps_fetched = True
    c._map_base, c._map_read_at, c._map_retry = b"map", time.monotonic(), False
    c.map_lock, c.last_update_success = asyncio.Lock(), True
    c._last_record_ts = OLD
    c._run = {"phase": "active", "at": time.monotonic(), "recharge": False, "resumed": False}
    c.data = {"status_code": 4, "battery": 70, "error_codes": [0], "prompts": []}     # driving home

    async def load_restore():
        return None

    async def fetch_status():
        return {"status_code": 6, "battery": 70, "error_codes": [0], "prompts": []}     # docked
    c._load_restore, c._fetch_status, c._refresh_position = load_restore, fetch_status, lambda: None

    def fold(record, detail):       # the run covered the kitchen
        c.rooms_last_cleaned["1:3"] = {"last_cleaned": C._ts(record), "coverage": 90}
        return True
    c._fold_coverage = fold
    return c


def _planner(monkeypatch, c):
    monkeypatch.setattr(P.TapoPlanner, "vacuum_entity_id", property(lambda self: "vacuum.robot"))
    pl = P.TapoPlanner(c.hass, c, types.SimpleNamespace(entry_id="e1"))
    pl.config.update({"enabled": True, "preview": False, "min_battery": 40, "require_away": False,
                      "windows": {"weekdays": ["00:00", "23:59"], "weekends": ["00:00", "23:59"]}})
    pl.room_areas = lambda: {}
    pl._sensors_by_area = lambda: {}
    pl.people = lambda: []
    return pl


def _poll(c):
    c.data = asyncio.run(c._update_once())      # what the planner then sees


def test_record_written_by_the_dock_poll_is_folded_before_the_planner_decides(monkeypatch):
    c = _coord(monkeypatch, written=True)
    pl = _planner(monkeypatch, c)
    assert decide(pl.snapshot(), pl.config).action != "clean"      # not docked yet
    _poll(c)
    assert c.rooms_last_cleaned["1:3"]["last_cleaned"] == NEW
    assert c.last_clean_info.get("map_id") == 1                    # the new run is drawn as well
    d = decide(pl.snapshot(), pl.config)
    assert d.action != "clean" and d.waiting_for == "nothing_due"


def test_planner_waits_for_a_record_written_late(monkeypatch):
    c = _coord(monkeypatch, written=False)
    pl = _planner(monkeypatch, c)
    _poll(c)
    assert c._run_phase() == "over" and c.rooms_last_cleaned["1:3"]["last_cleaned"] == OLD
    d = decide(pl.snapshot(), pl.config)
    assert d.action != "clean" and d.waiting_for == "busy"
    # A minute on, the robot has written it: the poll that finds it folds it in.
    c.client.written = True
    c._run["checked"] -= 61
    _poll(c)
    assert c._run is None and c.rooms_last_cleaned["1:3"]["last_cleaned"] == NEW
    d = decide(pl.snapshot(), pl.config)
    assert d.action != "clean" and d.waiting_for == "nothing_due"
