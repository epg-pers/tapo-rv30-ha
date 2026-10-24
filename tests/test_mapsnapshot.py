"""Snapshot / restore planning, modelled on a real total-map-loss recovery."""
import base64

from custom_components.tapo_rv30 import mapsnapshot as ms

MAP = 1792568378


def b64(s):
    return base64.b64encode(s.encode()).decode()


def room(rid, name=None, **kw):
    r = {"type": "room", "id": rid, "color": rid, "floor_texture": 90, **kw}
    if name is not None:
        r["name"] = b64(name)
    return r


Z1 = {"type": "forbid", "id": 301, "vertexs": [[0, 0], [100, 0], [100, 100], [0, 100]]}
Z2 = {"type": "forbid", "id": 302, "vertexs": [[200, 0], [300, 0], [300, 100], [200, 100]]}
TABLE = {"id": 0, "type": 201, "angle": 0, "vertexs": [[-2051, 567], [152, 567], [152, -604], [-2051, -604]]}
PRESET = {"rule_id": 1, "rule_name": b64("All downstairs"), "mode": "room", "map_id": MAP, "clean_order": True,
          "area_list": [{"id": 4, "type": "room", "suction": 2, "cistern": 2, "clean_number": 3},
                        {"id": 5, "type": "room", "suction": 2, "cistern": 2, "clean_number": 3, "carpet_strategy": 1}]}
SCHED = {"id": "S1", "enable": True, "mode": "repeat", "week_day": 62, "s_min": 510, "start_remind": False,
         "alarm_min": 0, "year": 2026, "month": 10, "day": 26, "cancel": False, "invalid": 0, "clean_attr": {"suction": 4, "cistern": 2, "clean_number": 3, "clean_mode": 5,
                                        "map_id": MAP, "clean_order": True, "custom_rule_id": 1}}

GOOD_AREAS = [room(4, "Hallway"), room(5, "Lounge", carpet_strategy=1), Z1, Z2]
LOST_AREAS = [room(4), room(5, carpet_strategy=1), Z1]   # what the restore left behind


def good():
    return ms.build(MAP, "Downstairs", GOOD_AREAS, [TABLE], [PRESET], [SCHED], "2026-10-23T22:45:00")


def test_build_keeps_only_this_maps_presets_and_schedules():
    other = dict(PRESET, map_id=999, rule_id=9)
    other_s = dict(SCHED, clean_attr=dict(SCHED["clean_attr"], map_id=999))
    s = ms.build(MAP, "Downstairs", GOOD_AREAS, [TABLE], [PRESET, other], [SCHED, other_s], "t")
    assert [p["rule_id"] for p in s["presets"]] == [1]
    assert len(s["schedules"]) == 1
    assert s["counts"] == {"room": 2, "forbid": 2}


def test_degraded_snapshot_never_replaces_a_good_one():
    old = good()
    lost = ms.build(MAP, "Downstairs", LOST_AREAS, [], [], [], "t")
    assert ms.is_degraded(old, lost)                                  # names gone
    assert ms.is_degraded(old, ms.build(MAP, "", [], [], [], [], "t"))  # no rooms at all
    assert not ms.is_degraded(None, lost)
    # a real edit (a zone removed, names intact) is not degraded
    assert not ms.is_degraded(old, ms.build(MAP, "Downstairs", GOOD_AREAS[:3], [TABLE], [PRESET], [SCHED], "t"))


def test_content_hash_ignores_timestamp():
    a = good()
    b = dict(a, saved_at="later")
    assert ms.content_hash(a) == ms.content_hash(b)


def test_plan_puts_back_everything_the_restore_lost():
    p = ms.plan(good(), MAP, LOST_AREAS, [], [], [])
    names = [base64.b64decode(r["name"]).decode() for r in p["rooms"]]
    assert names == ["Hallway", "Lounge"]
    assert all("vertexs" not in r for r in p["rooms"])              # room shapes stay in the grid
    assert [z["id"] for z in p["zones"]["forbid"]] == [301, 302]
    assert p["furniture"] == [TABLE]
    assert [pr["map_id"] for pr in p["presets"]] == [MAP]
    assert len(p["schedules"]) == 1 and p["schedules"][0]["preset_name"] == "All downstairs"


def test_plan_is_empty_when_nothing_was_lost():
    p = ms.plan(good(), MAP, GOOD_AREAS, [TABLE], [PRESET], [SCHED])
    assert p["rooms"] is None and not p["zones"] and p["furniture"] is None
    assert not p["presets"] and not p["schedules"]


def test_plan_skips_rooms_and_preset_rooms_not_on_a_remapped_map():
    remapped = [room(7), room(8)]                                      # new segmentation, new ids
    p = ms.plan(good(), 555, remapped, [], [], [])
    assert p["rooms"] is None
    assert not p["presets"]
    assert any("not on the target map" in s for s in p["skipped"])
    assert any("All downstairs" in s for s in p["skipped"])


def test_schedule_is_pointed_at_the_recreated_presets_new_id():
    p = ms.plan(good(), MAP, LOST_AREAS, [], [], [])
    recreated = [dict(PRESET, rule_id=2)]
    ready, skipped = ms.resolve_schedules(p["schedules"], recreated, MAP)
    assert not skipped
    assert ready[0]["clean_attr"]["custom_rule_id"] == 2
    assert ready[0]["clean_attr"]["map_id"] == MAP
    assert "id" not in ready[0]                                      # the robot assigns a new one
    assert "year" not in ready[0]                                    # repeat rules carry no date


def test_schedule_skipped_when_its_preset_is_missing():
    p = ms.plan(good(), MAP, LOST_AREAS, [], [], [])
    ready, skipped = ms.resolve_schedules(p["schedules"], [], MAP)
    assert not ready and "All downstairs" in skipped[0]


def test_restore_target_uses_backups_own_map_when_present():
    assert ms.restore_target({MAP: "Downstairs", 7: "Up"}, 7, MAP) == (MAP, False)


def test_restore_target_uses_a_carrier_when_the_map_is_gone():
    assert ms.restore_target({7: "new"}, 7, MAP) == (7, True)
    assert ms.restore_target({7: "new", 8: "x"}, None, MAP) == (7, True)


def test_restore_target_explains_when_the_robot_has_no_maps():
    import pytest
    with pytest.raises(ValueError, match="no maps at all"):
        ms.restore_target({}, 0, MAP)


def test_describe_shows_the_safety_net():
    d = ms.describe(good())
    assert d["rooms"] == ["Hallway", "Lounge"] and d["zones"] == {"forbid": 2}
    assert d["furniture"] == 1 and d["presets"] == ["All downstairs"] and d["schedules"] == 1


def test_summary_is_readable():
    s = ms.summary(ms.plan(good(), MAP, LOST_AREAS, [], [], []))
    assert s["room_names"] == ["Hallway", "Lounge"]
    assert s["zones"] == {"forbid": 1} and s["furniture"] == 1   # Z1 is still on the map: only one is added
    assert s["presets"] == ["All downstairs"] and s["schedules"] == [510]


def test_zones_are_matched_by_outline_and_new_ones_kept():
    renumbered = dict(Z1, id=9)                                       # same shape, robot renumbered it
    drawn_since = {"type": "forbid", "id": 10, "vertexs": [[500, 0], [600, 0], [600, 100], [500, 100]]}
    p = ms.plan(good(), MAP, [room(4, "Hallway"), room(5, "Lounge", carpet_strategy=1), renumbered, drawn_since],
                [TABLE], [PRESET], [SCHED])
    zones = p["zones"]["forbid"]
    assert [z["vertexs"] for z in zones] == [renumbered["vertexs"], drawn_since["vertexs"], Z2["vertexs"]]
    assert len({z["id"] for z in zones}) == 3                         # the added zone gets a free id
    same = ms.plan(good(), MAP, [room(4, "Hallway"), room(5, "Lounge", carpet_strategy=1), dict(Z1, id=7),
                                 dict(Z2, id=8)], [TABLE], [PRESET], [SCHED])
    assert not same["zones"]                                          # renumbering alone is not a change


def test_whole_house_schedule_without_map_id_is_not_added_twice():
    whole = {"id": "S2", "enable": True, "mode": "repeat", "week_day": 2, "s_min": 700,
             "clean_attr": {"clean_mode": 0, "suction": 2, "cistern": 1, "clean_number": 1}}
    snap = ms.build(MAP, "Downstairs", GOOD_AREAS, [TABLE], [PRESET], [SCHED, whole], "t")
    p = ms.plan(snap, MAP, GOOD_AREAS, [TABLE], [PRESET], [SCHED, whole])
    assert not p["schedules"]
    q = ms.plan(snap, MAP, GOOD_AREAS, [TABLE], [PRESET], [SCHED])     # missing: put back, still map-less
    assert len(q["schedules"]) == 1 and "map_id" not in q["schedules"][0]["rule"]["clean_attr"]


def test_schedule_for_rooms_not_on_the_target_is_skipped_and_said():
    rooms_sched = {"id": "S3", "enable": True, "mode": "repeat", "week_day": 2, "s_min": 600,
                   "clean_attr": {"clean_mode": 3, "map_id": MAP, "room_list": [4, 9]}}
    snap = ms.build(MAP, "Downstairs", GOOD_AREAS, [TABLE], [PRESET], [rooms_sched], "t")
    p = ms.plan(snap, MAP, GOOD_AREAS, [TABLE], [PRESET], [])
    assert not p["schedules"]
    assert any("10:00" in s and "[9]" in s for s in p["skipped"])


def test_preset_that_lost_rooms_is_reported():
    p = ms.plan(good(), MAP, [room(4, "Hallway"), Z1, Z2], [TABLE], [], [SCHED])
    assert p["presets"] and [a["id"] for a in p["presets"][0]["area_list"]] == [4]
    assert any("recreated without them" in s for s in p["skipped"])
