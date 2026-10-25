"""A planner start that fails (or is held back by a map write) must not be published as "Cleaning":
the status sensor and the sidebar say it is waiting to try again, the due rooms stay, and the
decision log holds only the failure, not a wait as well."""
import asyncio
import time
import types
from datetime import UTC, datetime

from custom_components.tapo_rv30 import planner as P
from custom_components.tapo_rv30.planlogic import RoomState, Snapshot

NOW = datetime(2026, 10, 21, 12, 0, tzinfo=UTC)     # a Wednesday, inside the window


class Client:
    def __init__(self, fail=False):
        self.fail, self.calls = fail, []

    def clean_rooms(self, ids, map_id):
        self.calls.append((ids, map_id))
        if self.fail:
            raise TimeoutError("timed out")


class Hass:
    bus = types.SimpleNamespace(async_fire=lambda *a, **k: None)

    async def async_add_executor_job(self, fn, *a):
        return fn(*a)


async def _refresh_soon():
    return None


def _planner(monkeypatch, client, **cfg):
    monkeypatch.setattr(P.TapoPlanner, "vacuum_entity_id", property(lambda self: "vacuum.robot"))
    coord = types.SimpleNamespace(client=client, map_id=1, data={"status_code": 6}, busy=None,
                                  map_lock=asyncio.Lock(), current_room=None, device_name="Robot",
                                  _event_base=lambda: {}, async_refresh_soon=_refresh_soon)
    pl = P.TapoPlanner(Hass(), coord, types.SimpleNamespace(entry_id="e1"))
    pl.config.update({"enabled": True, "preview": False, "require_away": False, "min_battery": 0,
                      "avoid_schedules": False,
                      "windows": {"weekdays": ["00:00", "23:59"], "weekends": ["00:00", "23:59"]}, **cfg})
    pl.battery = 90
    pl.snapshot = lambda: Snapshot(
        now=NOW, robot_docked=True, robot_busy=None, robot_error=False, battery=pl.battery, dnd=None,
        people_home=[], schedules=[], skip_today=False, ran_window=pl.ran_window,
        rooms=[RoomState("1:3", "Kitchen", NOW.timestamp() - 5 * 86400, 2)], robot_now=NOW)
    pl.room_areas = lambda: {}
    pl._sensors_by_area = lambda: {}
    pl.occupancy_sensors = lambda: []
    pl.people = lambda: []
    return pl


def _at(ts):
    return datetime.fromtimestamp(ts, UTC).astimezone().strftime("%H:%M")


def test_failed_start_is_published_as_a_retry_wait(monkeypatch):
    client = Client(fail=True)
    pl = _planner(monkeypatch, client)
    asyncio.run(pl.async_evaluate("tick"))
    assert len(client.calls) == 1 and pl._retry_at > time.time() + 800
    v = pl.view
    assert (v["action"], v["waiting_for"], v["running"]) == ("wait", "retry", False)
    assert v["status"] == f"Could not start; trying again at {_at(pl._retry_at)}"
    assert v["due"] == ["Kitchen"] and v["chips"]           # the due rooms and Clean now still work
    assert pl.decision.rooms == ["1:3"]
    assert [e["kind"] for e in pl.log] == ["error"]          # the failure, not a wait on top

    asyncio.run(pl.async_evaluate("tick"))                    # inside the hold-off: not tried again
    assert len(client.calls) == 1
    assert (pl.view["action"], pl.view["waiting_for"]) == ("wait", "retry")
    assert [e["kind"] for e in pl.log] == ["error"]

    pl.config["min_battery"], pl.battery = 50, 30             # a real wait afterwards is still logged
    asyncio.run(pl.async_evaluate("tick"))
    assert pl.view["waiting_for"] == "battery" and [e["kind"] for e in pl.log] == ["wait", "error"]

    pl.battery, pl._retry_at, client.fail = 90, 0.0, False   # hold-off over: tried again and started
    asyncio.run(pl.async_evaluate("tick"))
    assert len(client.calls) == 2
    assert (pl.view["action"], pl.view["waiting_for"], pl.view["running"]) == ("wait", "ran", True)


def test_successful_start_is_unchanged(monkeypatch):
    client = Client()
    pl = _planner(monkeypatch, client)
    asyncio.run(pl.async_evaluate("tick"))
    assert len(client.calls) == 1 and pl._retry_at == 0.0
    v = pl.view
    assert (v["action"], v["waiting_for"], v["running"]) == ("wait", "ran", True)
    assert v["status"] == "Already cleaned in today's window"
    assert [e["kind"] for e in pl.log] == ["start"]


def test_preview_is_unchanged(monkeypatch):
    client = Client(fail=True)
    pl = _planner(monkeypatch, client, preview=True)
    asyncio.run(pl.async_evaluate("tick"))
    assert client.calls == [] and pl._retry_at == 0.0
    v = pl.view
    assert (v["action"], v["waiting_for"], v["running"]) == ("wait", "ran", False)
    assert v["status"] == "Preview: would have cleaned Kitchen today"
    assert [e["kind"] for e in pl.log] == ["preview"]


def test_map_write_in_progress_is_a_retry_wait(monkeypatch):
    client = Client()
    pl = _planner(monkeypatch, client)

    async def run():
        async with pl.coordinator.map_lock:
            await pl.async_evaluate("tick")
    asyncio.run(run())
    assert client.calls == [] and pl._retry_at == 0.0       # not a failure: no hold-off, tried next minute
    v = pl.view
    assert (v["action"], v["waiting_for"], v["running"]) == ("wait", "retry", False)
    assert v["status"] == "Waiting for a map change to finish"
    assert v["due"] == ["Kitchen"] and pl.log == []


def test_hold_off_wins_over_a_map_write(monkeypatch):
    client = Client()
    pl = _planner(monkeypatch, client)
    pl._retry_at = time.time() + 600                          # an earlier start failed

    async def run():
        async with pl.coordinator.map_lock:
            await pl.async_evaluate("tick")
    asyncio.run(run())
    assert client.calls == []
    assert (pl.view["action"], pl.view["waiting_for"]) == ("wait", "retry")
    assert pl.view["status"] == f"Could not start; trying again at {_at(pl._retry_at)}"
