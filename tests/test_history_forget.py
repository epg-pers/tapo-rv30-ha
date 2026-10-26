"""A clean map forgotten on the History tab stays forgotten: redrawing the newest run after a
restart (or a map turn) must not keep it again, but opening it on purpose does."""
import asyncio
import collections
import time
import types

from custom_components.tapo_rv30 import cleanhistory
from custom_components.tapo_rv30 import coordinator as C
from tests.test_maprender import _map

TS = int(time.time()) - 3600

def _recs(map_id=1):
    return {"record_list": [{"timestamp": TS, "record_index": 0, "clean_time": 30, "clean_area": 20,
                             "map_id": map_id}]}


class _Hass:
    async def async_add_executor_job(self, fn, *a):
        return fn(*a)


def _coord(folder, processed=(), run_map=1, map_id=1):
    detail = {**_map(), "map_id": run_map, "map_name": ""}
    c = C.TapoCoordinator.__new__(C.TapoCoordinator)
    c.hass = _Hass()
    c.entry = types.SimpleNamespace(options={}, entry_id="e")
    c.client = types.SimpleNamespace(get_clean_record_detail=lambda i: detail)
    c.settings = {"records": _recs(run_map)}
    c.map_id, c.rooms, c.maps = map_id, [], []
    c._live_map, c._live_pixels = {"x": 1}, b"x"
    c._freshness_loaded, c._freshness_store = True, None
    c._processed_records, c._record_failures = set(processed), {}
    c._record_rendered_ts, c.rooms_last_cleaned = None, {}
    c._history = cleanhistory.CleanHistory(folder)
    c.history = lambda: c._history
    c._history_pruned_at, c._history_png = 0.0, collections.OrderedDict()
    c.last_clean_info, c.device_name = {}, "RV30"
    c._fold_coverage = lambda r, d: True
    return c


def test_a_forgotten_newest_run_stays_forgotten_after_a_restart(tmp_path):
    async def run():
        c = _coord(str(tmp_path))
        await c._maybe_render_last_clean(6)                     # docked: the run is kept
        assert c._history.has(TS)
        assert await c.async_history_delete(TS) and not c._history.has(TS)
        c2 = _coord(str(tmp_path), c._processed_records)      # restart: processed set is persisted
        await c2._maybe_render_last_clean(6)
        assert not c2._history.has(TS)
        assert c2.last_clean_image_bytes                         # still redrawn
    asyncio.run(run())


def test_a_forgotten_run_on_another_floor_stays_forgotten(tmp_path):
    async def run():
        c = _coord(str(tmp_path), run_map=2)                    # newest run is on map 2, map 1 is active
        await c._maybe_render_last_clean(6)
        assert c._history.has(TS) and TS not in c._processed_records
        assert await c.async_history_delete(TS)
        c2 = _coord(str(tmp_path), c._processed_records, run_map=2)     # restart
        await c2._maybe_render_last_clean(6)
        assert not c2._history.has(TS)
        c3 = _coord(str(tmp_path), c2._processed_records, run_map=2, map_id=2)  # back on that floor
        await c3._maybe_render_last_clean(6)
        assert TS in c3._processed_records and not c3._history.has(TS)
    asyncio.run(run())


def test_opening_a_forgotten_run_keeps_it_again(tmp_path):
    async def run():
        c = _coord(str(tmp_path))
        await c._maybe_render_last_clean(6)
        await c.async_history_delete(TS)
        c.data = {"status_code": 6}
        c.map_lock = asyncio.Lock()
        c.rotation_for = lambda m: 0
        assert await c.async_history_image(TS)
        assert c._history.has(TS)
        await c.async_history_delete(TS)                        # and can be forgotten again
        assert not c._history.has(TS)
    asyncio.run(run())


def test_a_failed_keep_is_retried_on_the_next_redraw(tmp_path):
    async def run():
        c = _coord(str(tmp_path))
        c._history.add = lambda *a: (_ for _ in ()).throw(OSError("disk full"))
        await c._maybe_render_last_clean(6)
        assert TS in c._processed_records
        c2 = _coord(str(tmp_path), c._processed_records)       # restart: redraw only
        await c2._maybe_render_last_clean(6)
        assert c2._history.has(TS)
    asyncio.run(run())
