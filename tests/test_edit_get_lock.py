"""The Edit tab's read (wait: true) while a map write (an editor save, setup apply, restore or copy) holds the
map lock: it waits for the write to end and reads what it wrote, so a later save from that
editor cannot send the zones from before the write and undo it. Without an end, it says busy."""
import asyncio
import base64

from custom_components.tapo_rv30 import map_edit_ws


def b64(s):
    return base64.b64encode(s.encode()).decode()


class Client:
    def __init__(self):
        self.forbid = 301

    def get_map_data(self, map_id):
        return {"area_list": [{"type": "forbid", "id": self.forbid, "vertexs": [[0, 0], [1, 1]]},
                              {"type": "room", "id": 1, "name": b64("Hall")}], "furniture_list": []}


class Hass:
    async def async_add_executor_job(self, fn, *args):
        return fn(*args)


class Coord:
    def __init__(self):
        self.hass, self.client, self.device_name, self.map_id = Hass(), Client(), "Jarvis", 100
        self.map_lock = asyncio.Lock()


class Conn:
    def __init__(self):
        self.errors, self.results = [], []

    def send_error(self, msg_id, code, message):
        self.errors.append((code, message))

    def send_result(self, msg_id, result):
        self.results.append(result)


def _setup(monkeypatch, wait):
    monkeypatch.setattr(map_edit_ws, "_LOCK_POLL", 0.01)
    monkeypatch.setattr(map_edit_ws, "_LOCK_WAIT", wait)
    coord = Coord()
    monkeypatch.setattr(map_edit_ws, "_coord", lambda hass, entity_id: coord)
    return coord, Conn(), {"id": 1, "entity_id": "vacuum.jarvis", "map_id": 100, "wait": True}


def test_edit_get_waits_for_a_running_write_and_reads_after_it(monkeypatch):
    coord, conn, msg = _setup(monkeypatch, 5.0)

    async def run():
        async with coord.map_lock:      # a save from another editor is still with the robot
            read = asyncio.ensure_future(map_edit_ws.ws_edit_get(coord.hass, conn, msg))
            await asyncio.sleep(0.1)
            assert not read.done() and not conn.results and not conn.errors
            coord.client.forbid = 999   # what that save wrote
        await asyncio.wait_for(read, 2)
    asyncio.run(run())
    assert not conn.errors
    assert [z["id"] for z in conn.results[0]["areas"]["forbid"]] == [999]
    assert not coord.map_lock.locked()


def test_edit_get_says_busy_when_the_write_does_not_end(monkeypatch):
    coord, conn, msg = _setup(monkeypatch, 0.05)

    async def run():
        async with coord.map_lock:
            await asyncio.wait_for(map_edit_ws.ws_edit_get(coord.hass, conn, msg), 2)
    asyncio.run(run())
    assert not conn.results and conn.errors and conn.errors[0][0] == "busy"
    assert "still running" in conn.errors[0][1]


def test_edit_get_reads_straight_away_with_no_write_running(monkeypatch):
    coord, conn, msg = _setup(monkeypatch, 0.05)
    asyncio.run(map_edit_ws.ws_edit_get(coord.hass, conn, msg))
    assert not conn.errors and [z["id"] for z in conn.results[0]["areas"]["forbid"]] == [301]


def test_a_read_without_wait_is_not_held_up_by_a_running_write(monkeypatch):
    """A preview (Presets pane, Maps lightbox) only looks: a backup or restore holding the lock for
    minutes must not keep it waiting."""
    coord, conn, msg = _setup(monkeypatch, 5.0)
    del msg["wait"]

    async def run():
        async with coord.map_lock:
            await asyncio.wait_for(map_edit_ws.ws_edit_get(coord.hass, conn, msg), 0.5)
    asyncio.run(run())
    assert not conn.errors and [z["id"] for z in conn.results[0]["areas"]["forbid"]] == [301]
