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
