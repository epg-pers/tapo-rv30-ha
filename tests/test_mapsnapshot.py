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


def test_summary_is_readable():
    s = ms.summary(ms.plan(good(), MAP, LOST_AREAS, [], [], []))
    assert s["room_names"] == ["Hallway", "Lounge"]
    assert s["zones"] == {"forbid": 2} and s["furniture"] == 1
    assert s["presets"] == ["All downstairs"] and s["schedules"] == [510]
