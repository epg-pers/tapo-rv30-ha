"""Clean map history: what is kept of a run, that it draws the same, and retention."""
import gzip
import json

from test_maprender import _map, _pos_array

from custom_components.tapo_rv30 import cleanhistory as ch
from custom_components.tapo_rv30.maprender import render_record

DAY = 86400


def _record():
    rec = _map()
    rec["pos_array"], rec["pos_len"] = _pos_array([(0, 0), (100, 50), (200, 100)])
    rec["real_charge_coor"] = [300, 0, 0]
    rec["room_list"] = [{"id": 1, "suction": 2}] * 50      # not needed to draw: not kept
    return rec


def test_slim_keeps_what_drawing_needs_and_draws_the_same():
    rec = _record()
    small = ch.slim(rec)
    assert "room_list" not in small and "furniture_list" not in small
    assert [a["type"] for a in small["area_list"]] == ["room", "room", "forbid"]
    assert render_record(small).tobytes() == render_record(rec).tobytes()


def test_slim_keeps_room_colours_and_cell_values():
    rec = _record()
    rec["area_list"][0]["color"] = 4
    rec["area_list"][1]["color"] = 2
    rec["area_list"][0]["suction"] = 3                      # a room setting: not kept
    # Rooms as values 1-2 and walls as 0 are the defaults; say so, and widen the room range.
    rec["bit_list"] = {"barrier": 0, "clean": 255, "none": 127, "auto_area": [0, 50]}
    small = ch.slim(rec)
    assert small["bit_list"] == rec["bit_list"]
    assert small["area_list"][:2] == [{"type": "room", "id": 1, "color": 4}, {"type": "room", "id": 2, "color": 2}]
    assert render_record(small).tobytes() == render_record(rec).tobytes()
    # The colours matter: without them the run draws differently.
    plain = dict(small, area_list=[{"type": "room", "id": a["id"]} for a in small["area_list"][:2]])
    assert render_record(plain).tobytes() != render_record(rec).tobytes()


def test_add_get_list_and_no_rewrite(tmp_path):
    h = ch.CleanHistory(str(tmp_path / "robot"))
    meta = {"area": 13, "minutes": 11, "map_id": 9, "map_name": "Downstairs", "start_type": 1, "secret": "x"}
    assert h.add(1000, meta, _record())
    assert not h.add(1000, meta, _record())             # already kept
    [entry] = h.entries()
    assert entry["started"] == 1000 and entry["area"] == 13 and "secret" not in entry and entry["bytes"] > 0
    assert render_record(h.get(1000)).size == render_record(_record()).size
    assert h.get(2000) is None and h.has(1000) and not h.has(2000)
    assert h.usage() == {"runs": 1, "bytes": entry["bytes"]}


def test_index_survives_damage_and_hand_edits(tmp_path):
    folder = tmp_path / "robot"
    h = ch.CleanHistory(str(folder))
    h.add(1000, {"area": 1}, _record())
    h.add(2000, {"area": 2}, _record())
    (folder / "index.json").write_text("{not json")
    (folder / "1000.json.gz").unlink()                   # removed by hand
    with gzip.open(folder / "3000.json.gz", "wt") as fh:  # copied in without an index entry
        json.dump({"meta": {"started": 3000, "area": 3}, "map": ch.slim(_record())}, fh)
    fresh = ch.CleanHistory(str(folder))
    assert [e["started"] for e in fresh.entries()] == [3000, 2000]


def test_prune_by_age_and_count(tmp_path):
    h = ch.CleanHistory(str(tmp_path / "robot"))
    now = 100 * DAY
    for d in (1, 5, 20, 40, 95):
        h.add(int(now - d * DAY), {}, _record())
    assert h.prune(now, 30, 200) == 2                    # 40 and 95 days old
    assert h.prune(now, None, 2) == 1                    # only the newest two stay
    assert [e["started"] for e in h.entries()] == [now - DAY, now - 5 * DAY]
    assert h.prune(now, ch.retention_days("Off"), 200) == 2   # Off keeps nothing
    assert h.entries() == [] and not list((tmp_path / "robot").glob("*.json.gz"))
    h.add(int(now + DAY), {}, _record())                   # the robot's clock ahead of this one
    assert h.prune(now, 0, 200) == 1


def test_retention_labels():
    assert ch.retention_days("Forever") is None and ch.retention_days("1 week") == 7
    assert ch.retention_days("nonsense") == ch.retention_days(ch.DEFAULT_RETENTION)


def test_missing_folder_is_empty(tmp_path):
    h = ch.CleanHistory(str(tmp_path / "nothing"))
    assert h.entries() == [] and h.prune(0, 0, 10) == 0 and not h.delete(5)


def test_forgotten_runs_are_only_kept_again_on_purpose(tmp_path):
    h = ch.CleanHistory(str(tmp_path))
    assert h.add(1000, {}, _record()) and h.delete(1000)
    h2 = ch.CleanHistory(str(tmp_path))           # read back from disk
    assert not h2.add(1000, {}, _record()) and not h2.has(1000)
    assert h2.add(1000, {}, _record(), auto=False) and h2.has(1000)
    assert h2.delete(1000) and not h2.add(1000, {}, _record())


def test_forgotten_marks_are_capped_and_survive_damage(tmp_path):
    h = ch.CleanHistory(str(tmp_path))
    for t in range(1, ch._MAX_FORGOTTEN + 3):
        h.add(t, {}, _record())
        h.delete(t)
    assert len(h._load_forgotten()) == ch._MAX_FORGOTTEN and 1 not in h._load_forgotten()
    (tmp_path / "forgotten.json").write_text("[1e400]")
    h3 = ch.CleanHistory(str(tmp_path))
    assert h3.add(5, {}, _record()) and h3.has(5)
