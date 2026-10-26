"""Regression tests for the 0.30 fixes that need no Home Assistant: map setup snapshots,
voice room matching, the security profile, odd numbers from the robot and setup files."""
import base64
import json

from custom_components.tapo_rv30 import mapdata, planlogic, setup_apply, voice
from custom_components.tapo_rv30 import mapsnapshot as ms
from custom_components.tapo_rv30 import tpap as T


def _room(rid, name):
    return {"type": "room", "id": rid, "name": base64.b64encode(name.encode()).decode() if name else ""}


def _snap(*rooms):
    return ms.build(1, "Home", list(rooms), [], [], [], "now")


def test_merged_or_deleted_rooms_are_not_degraded():
    old = _snap(_room(1, "Hall"), _room(2, "Lounge"), _room(3, "Kitchen"))
    assert not ms.is_degraded(old, _snap(_room(1, "Hall"), _room(2, "Lounge")))       # merged in the app
    assert ms.is_degraded(old, _snap(_room(1, "Hall"), _room(2, ""), _room(3, "Kitchen")))  # a name lost
    assert ms.is_degraded(old, _snap())                                              # rooms gone
    assert ms.is_degraded(old, _snap(_room(1, ""), _room(2, "")))                     # nothing named


def test_voice_partial_names_start_a_word():
    assert voice._room_match("bath", "bathroom") and voice._room_match("dining", "dining room")
    assert not voice._room_match("it", "kitchen")
    assert not voice._room_match("room", "dining room")
    assert not voice._room_match("en", "kitchen")
    assert voice._room_match("kitchen", "kitchen")


def test_security_profile_only_moves_up():
    old = {"tls": 1, "pake": [2], "dac": False}
    assert T.security_stronger({"tls": 2, "pake": [2], "dac": True}, old)
    assert T.security_stronger({"tls": 1, "pake": [2], "dac": True}, old)
    assert not T.security_stronger(old, old)
    assert not T.security_stronger({"tls": 0, "pake": [2], "dac": True}, old)      # other mode, not the pin
    assert not T.security_stronger({"tls": 2, "pake": [0, 2], "dac": True}, old)   # a new passcode type
    assert not T.security_stronger({"tls": 2, "pake": [], "dac": True}, old)       # MAC-derived default
    assert not T.security_stronger({"tls": 2, "pake": [2], "dac": False},
                                   {"tls": 2, "pake": [2], "dac": True})


def test_infinite_numbers_do_not_break_parsing():
    inf = float("inf")
    assert mapdata.minutes_of(inf) == 0 and mapdata.as_int(inf, 7) == 7
    assert mapdata.int_list([inf, 3]) == [3]
    assert T._ints([inf, "1e999", 4]) == [4] and T._opt_int(inf) is None
    assert planlogic._minutes(inf) == 0


def test_damaged_setup_falls_back_to_another_copy(tmp_path):
    own, shared = tmp_path / "own", tmp_path / "shared"
    own.mkdir(); shared.mkdir()
    (own / "5.json").write_text('{"map_id": 5, "are')            # cut off by a crash
    setup_apply.write_json(str(shared / "5.json"), {"map_id": 5, "map_name": "Home"})
    assert setup_apply.find_snapshot([str(own), str(shared)], 5)["map_name"] == "Home"
    assert not (shared / "5.json.tmp").exists()
    assert json.loads((shared / "5.json").read_text())["map_id"] == 5


def _setup(folder, map_id, name, saved_at=None):
    snap = {"map_id": map_id, "map_name": name}
    if saved_at:
        snap["saved_at"] = saved_at
    setup_apply.write_json(str(folder / f"{map_id}.json"), snap)


def test_setup_by_name_takes_the_newest_other_map(tmp_path):
    # Downstairs re-mapped twice: two old setups and the newest map's own (nearly empty) one.
    _setup(tmp_path, 1001, "Downstairs", "2025-01-10T09:00:00")
    _setup(tmp_path, 1002, "Downstairs", "2025-05-20T09:00:00")
    _setup(tmp_path, 1003, "Downstairs", "2025-09-01T09:00:00")
    _setup(tmp_path, 1004, "Upstairs", "2025-12-01T09:00:00")
    find = setup_apply.find_snapshot
    assert find([str(tmp_path)], 1003, "downstairs", exclude=1003)["map_id"] == 1002
    assert find([str(tmp_path)], None, "Downstairs")["map_id"] == 1003
    # An exact id still wins, even the target's own.
    assert find([str(tmp_path)], 1003, "1001", exclude=1003)["map_id"] == 1001
    assert find([str(tmp_path)], 1003, "1003", exclude=1003)["map_id"] == 1003
    # Only the target's own setup has the name: that is still better than nothing.
    assert find([str(tmp_path)], 1004, "Upstairs", exclude=1004)["map_id"] == 1004


def test_setup_by_name_without_saved_at_takes_the_higher_id(tmp_path):
    _setup(tmp_path, 1001, "Loft")
    _setup(tmp_path, 1002, "Loft")
    assert setup_apply.find_snapshot([str(tmp_path)], None, "Loft")["map_id"] == 1002


def test_setup_by_name_single_remap(tmp_path):
    # The documented case: one old map, and the re-mapped floor's own file saved since.
    _setup(tmp_path, 1001, "Downstairs", "2025-01-10T09:00:00")
    _setup(tmp_path, 1005, "Downstairs", "2025-09-01T09:00:00")
    assert setup_apply.find_snapshot([str(tmp_path)], 1005, "Downstairs", exclude=1005)["map_id"] == 1001
    (tmp_path / "1005.json").unlink()      # or the new map was never saved
    assert setup_apply.find_snapshot([str(tmp_path)], 1005, "Downstairs", exclude=1005)["map_id"] == 1001


def test_setup_by_name_looks_in_every_folder(tmp_path):
    # The target's own setup in the robot's folder, the old map's in the shared one.
    own, shared = tmp_path / "own", tmp_path / "shared"
    own.mkdir(); shared.mkdir()
    _setup(shared, 1001, "Downstairs", "2024-03-01T09:00:00")
    _setup(own, 1005, "Downstairs", "2025-09-01T09:00:00")
    _setup(own, 1006, "Upstairs", "2025-09-01T09:00:00")
    folders = [str(own), str(shared)]
    assert setup_apply.find_snapshot(folders, 1005, "Downstairs", exclude=1005)["map_id"] == 1001
    # The robot's maps can be left out as a collection; the backed-up one is preferred.
    _setup(shared, 1002, "Downstairs", "2024-01-01T09:00:00")
    assert setup_apply.find_snapshot(folders, None, "Downstairs", exclude={1005, 1006})["map_id"] == 1001
    assert setup_apply.find_snapshot(folders, None, "Downstairs", exclude=[1005], prefer={1002})["map_id"] == 1002
    # An exact id in the robot's folder beats a same-id copy in the shared one.
    _setup(shared, 1006, "Upstairs (old)", "2026-01-01T09:00:00")
    assert setup_apply.find_snapshot(folders, None, "1006")["map_name"] == "Upstairs"


def test_setup_by_name_ignores_odd_saved_at(tmp_path):
    _setup(tmp_path, 1001, "Loft", "2025-01-10T09:00:00")
    for mid, when in ((1002, "not a date"), (1003, 20991231), (1004, ["2099-01-01"])):
        setup_apply.write_json(str(tmp_path / f"{mid}.json"), {"map_id": mid, "map_name": "Loft", "saved_at": when})
    (tmp_path / "1009.json").write_text('["Loft"]')           # not a setup at all
    assert setup_apply.find_snapshot([str(tmp_path)], None, "Loft")["map_id"] == 1001
