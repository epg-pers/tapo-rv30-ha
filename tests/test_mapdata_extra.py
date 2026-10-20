import base64

import pytest

from custom_components.tapo_rv30.mapdata import (
    decode_clean_record, dnd_active, fold, mm_to_grid, resolve_rooms,
)


def b64(s):
    return base64.b64encode(s.encode()).decode()


@pytest.mark.parametrize("text,expected", [
    ("Kúpeľňa", "kupelna"), ("Küche", "kuche"), ("Hallway", "hallway"), ("", ""),
])
def test_fold(text, expected):
    assert fold(text) == expected


def test_resolve_rooms_is_accent_insensitive():
    maps = [{"map_id": 1, "map_name": b64("Prízemie")}]
    rooms = lambda mid: {"area_list": [{"type": "room", "id": 4, "name": b64("Kúpeľňa")}]}
    assert resolve_rooms(1, maps, rooms, ["kupelna"], "prizemie") == ([4], 1)


def test_mm_to_grid_matches_device_values():
    # Taken from a live RV30 map: real_vac_coor -> vac_coor
    md = {"real_origin_coor": [-5375, -1474, 0], "resolution": 50}
    gx, gy = mm_to_grid(md, -1245, 2728)
    assert (int(gx), int(gy)) == (82, 84)
    gx, gy = mm_to_grid(md, -1462, 2734)      # dock
    assert (int(gx), int(gy)) == (78, 84)


@pytest.mark.parametrize("dnd,minute,expected", [
    (None, 600, False),
    ({"do_not_disturb": False, "s_min": 1320, "e_min": 480}, 1380, False),
    ({"do_not_disturb": True, "s_min": 1320, "e_min": 480}, 1380, True),    # 23:00, window 22:00-08:00
    ({"do_not_disturb": True, "s_min": 1320, "e_min": 480}, 120, True),     # 02:00
    ({"do_not_disturb": True, "s_min": 1320, "e_min": 480}, 480, False),    # 08:00 exactly: over
    ({"do_not_disturb": True, "s_min": 1320, "e_min": 480}, 720, False),    # noon
    ({"do_not_disturb": True, "s_min": 540, "e_min": 1020}, 600, True),     # 09:00-17:00 at 10:00
    ({"do_not_disturb": True, "s_min": 540, "e_min": 1020}, 1080, False),
    ({"do_not_disturb": True, "s_min": 0, "e_min": 0}, 300, True),          # degenerate: all day
])
def test_dnd_active(dnd, minute, expected):
    assert dnd_active(dnd, minute) is expected


def test_decode_clean_record():
    rec = {"map_id": 5, "error": 0, "clean_time": 57, "clean_area": 64, "dust_collection": True,
           "timestamp": 1791479539, "start_type": 5, "task_type": 5, "rule_name": b64("Daytime Vacuum")}
    d = decode_clean_record(rec)
    assert d == {"started": 1791479539, "minutes": 57, "area": 64, "emptied_bin": True, "error": 0,
                 "map_id": 5, "start_type": 5, "rule_name": "Daytime Vacuum"}
    assert decode_clean_record({})["rule_name"] is None


def test_clean_transition():
    from custom_components.tapo_rv30.mapdata import clean_transition
    C, P = {1, 2, 3}, {7}
    assert clean_transition(5, 1, C, P) == "started"      # docked -> cleaning
    assert clean_transition(0, 1, C, P) == "started"
    assert clean_transition(1, 7, C, P) is None           # pause
    assert clean_transition(7, 1, C, P) is None           # resume
    assert clean_transition(1, 4, C, P) == "finished"     # cleaning -> returning
    assert clean_transition(7, 0, C, P) == "finished"     # paused -> stopped
    assert clean_transition(1, 1, C, P) is None
    assert clean_transition(None, 1, C, P) is None
    assert clean_transition(5, 6, C, P) is None           # charging -> charged
