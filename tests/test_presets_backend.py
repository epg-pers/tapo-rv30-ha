"""The preset editor's checks and listing (presetedit), and a copied map taking its source map's
presets and, if asked, its schedules switched off (mapsnapshot.carry_setup, mapcopy.carry and
the tidy step). Pure, no Home Assistant."""
import base64
import json

import pytest

from custom_components.tapo_rv30 import mapcopy, mapsnapshot, presetedit

SRC, NEW = 1792568378, 1792999999


def _b64(s):
    return base64.b64encode(s.encode()).decode()


# What a preset made in the Tapo app looks like on the robot (read from an RV30 Max Plus, 1.3.3).
APP_PRESET = {"rule_name": _b64("All downstairs"), "mode": "room", "map_id": SRC, "clean_order": True,
              "area_list": [{"id": 4, "type": "room", "suction": 2, "cistern": 2, "clean_number": 3},
                            {"id": 5, "type": "room", "suction": 2, "cistern": 2, "clean_number": 3,
                             "carpet_strategy": 1},
                            {"id": 1, "type": "room", "suction": 2, "cistern": 2, "clean_number": 3}],
              "rule_id": 2, "invalid": 0}
MAP_ROOMS = [{"type": "room", "id": 1}, {"type": "room", "id": 4},
             {"type": "room", "id": 5, "carpet_strategy": 1}]
SCHEDULE = {"id": "S1", "enable": True, "mode": "repeat", "week_day": 62, "s_min": 510, "start_remind": False,
            "alarm_min": 0, "clean_attr": {"suction": 4, "cistern": 2, "clean_number": 3, "clean_mode": 5,
                                           "map_id": SRC, "clean_order": True, "custom_rule_id": 2}}
WHOLE_HOUSE = {"id": "S2", "enable": True, "mode": "repeat", "week_day": 1, "s_min": 600,
               "clean_attr": {"clean_mode": 0}}


# ---- presetedit -----------------------------------------------------------------------------
def test_view_lists_rooms_in_order_with_their_own_levels_and_the_schedules_that_run_it():
    rules = [{"rule_id": 2, "rule_name": _b64("All downstairs"), "mode": "room", "map_id": SRC, "invalid": 0}]
    out = presetedit.view(rules, {(SRC, 2): APP_PRESET}, {SRC: {4: "Hallway", 5: "Lounge"}},
                          [{"id": "S1", "time": "08:30", "days": ["Mon"], "enabled": True, "preset_id": 2},
                           {"id": "S9", "time": "10:00", "days": [], "enabled": True, "preset_id": None}])
    assert out == [{"id": 2, "map_id": SRC, "name": "All downstairs", "clean_order": True, "valid": True,
                    "rooms": [{"id": 4, "name": "Hallway", "suction": 2, "water": 2, "passes": 3},
                              {"id": 5, "name": "Lounge", "suction": 2, "water": 2, "passes": 3},
                              {"id": 1, "name": "Room 1", "suction": 2, "water": 2, "passes": 3}],
                    "schedules": [{"id": "S1", "time": "08:30", "days": ["Mon"], "enabled": True}]}]


def test_view_shows_a_preset_whose_detail_failed_to_read_without_rooms():
    out = presetedit.view([{"rule_id": 3, "rule_name": "", "map_id": SRC}], {}, {}, [])
    assert out[0]["name"] == "Preset 3" and out[0]["rooms"] == []


def test_body_is_what_the_app_sends():
    rooms = [{"id": 4, "suction": 2, "water": 2, "passes": 3}, {"id": 5, "suction": 2, "water": 2, "passes": 3},
             {"id": 1, "suction": 2, "water": 2, "passes": 3}]
    body = presetedit.body(" All downstairs ", SRC, rooms, True, MAP_ROOMS, [])
    want = {k: APP_PRESET[k] for k in ("rule_name", "mode", "map_id", "clean_order", "area_list")}
    # carpet handling comes from the map's room, and is left out where the room has none
    assert body == want


def test_body_keeps_the_order_and_per_room_levels_and_edits_by_id():
    rooms = [{"id": 5, "suction": 4, "water": 0, "passes": 1}, {"id": 1, "suction": 1, "water": 3, "passes": 2}]
    body = presetedit.body("Mix", SRC, rooms, False, MAP_ROOMS, [{"id": 7, "name": "Mix"}], preset_id=7)
    assert body["rule_id"] == 7 and body["clean_order"] is False
    assert [(a["id"], a["suction"], a["cistern"], a["clean_number"]) for a in body["area_list"]] == [
        (5, 4, 0, 1), (1, 1, 3, 2)]


@pytest.mark.parametrize("name,rooms,others,why", [
    ("", [{"id": 1, "suction": 2, "water": 1, "passes": 1}], [], "name"),
    ("x" * 41, [{"id": 1, "suction": 2, "water": 1, "passes": 1}], [], "too long"),
    ("kitchen", [{"id": 1, "suction": 2, "water": 1, "passes": 1}], [{"id": 9, "name": "Kitchen"}], "already"),
    ("A", [], [], "at least one room"),
    ("A", [{"id": 99, "suction": 2, "water": 1, "passes": 1}], [], "not on this map"),
    ("A", [{"id": 1, "suction": 2, "water": 1, "passes": 1}] * 2, [], "twice"),
    ("A", [{"id": 1, "suction": 9, "water": 1, "passes": 1}], [], "suction"),
    ("A", [{"id": 1, "suction": 2, "water": 1, "passes": 4}], [], "passes"),
    ("A", [{"id": 1, "suction": 2}], [], "missing"),
    ("A", [{"id": 1, "suction": True, "water": 1, "passes": 1}], [], "whole numbers"),
    ("A", [{"id": 1, "suction": 2.7, "water": 1, "passes": 1}], [], "whole numbers"),
])
def test_body_refuses_what_the_robot_should_not_be_sent(name, rooms, others, why):
    with pytest.raises(presetedit.PresetError, match=why):
        presetedit.body(name, SRC, rooms, True, MAP_ROOMS, others)


# ---- carrying presets to a copy -------------------------------------------------------------
def test_carry_setup_takes_the_maps_presets_and_only_asked_for_schedules_switched_off():
    other = {**APP_PRESET, "map_id": 111, "rule_id": 5}
    plain = mapsnapshot.carry_setup([APP_PRESET, other], [SCHEDULE, WHOLE_HOUSE], SRC)
    assert [p["rule_id"] for p in plain["presets"]] == [2] and plain["schedules"] == []
    both = mapsnapshot.carry_setup([APP_PRESET], [SCHEDULE, WHOLE_HOUSE], SRC, with_schedules=True)
    assert [s["id"] for s in both["schedules"]] == ["S1"]          # the whole-house one stays put
    assert both["schedules"][0]["enable"] is False and SCHEDULE["enable"] is True    # not the original


class _Robot:
    """The robot's presets and schedules, enough for mapcopy.carry."""

    def __init__(self, fail_add=()):
        self.rules, self.schedules, self.fail_add, self.next_id = [], [], set(fail_add), 10

    def get_map_data(self, mid):
        return {"area_list": json.loads(json.dumps(MAP_ROOMS)), "furniture_list": []}

    def get_presets(self):
        return [{k: r[k] for k in ("rule_id", "rule_name", "mode", "map_id")} for r in self.rules]

    def get_preset_detail(self, mid, rid):
        return json.loads(json.dumps(next(r for r in self.rules if r["rule_id"] == rid)))

    def add_preset(self, body):
        if base64.b64decode(body["rule_name"]).decode() in self.fail_add:
            raise RuntimeError("Device error -1")
        self.rules.append({**body, "rule_id": self.next_id})
        self.next_id += 1
        return 0

    def get_schedules(self):
        return list(self.schedules)

    def add_schedule(self, rule):
        self.schedules.append(rule)
        return "S9"


def test_carry_recreates_presets_on_the_new_map_and_points_schedules_at_them():
    robot = _Robot()
    setup = mapsnapshot.carry_setup([APP_PRESET], [SCHEDULE], SRC, with_schedules=True)
    out = mapcopy.carry(robot, NEW, setup)
    assert out == {"presets": 1, "schedules": 1, "skipped": [], "failed": False}
    made = robot.rules[0]
    assert made["map_id"] == NEW and made["rule_name"] == APP_PRESET["rule_name"] and made["clean_order"] is True
    assert made["area_list"] == APP_PRESET["area_list"]                       # same order and levels
    rule = robot.schedules[0]
    assert rule["enable"] is False and rule["clean_attr"]["map_id"] == NEW
    assert rule["clean_attr"]["custom_rule_id"] == made["rule_id"]            # the copy's own preset


def test_carry_again_adds_only_what_is_missing():
    robot = _Robot()
    setup = mapsnapshot.carry_setup([APP_PRESET, {**APP_PRESET, "rule_id": 3, "rule_name": _b64("Kitchen")}],
                                    [], SRC)
    mapcopy.carry(robot, NEW, setup)
    out = mapcopy.carry(robot, NEW, setup)
    assert out["presets"] == 0 and len(robot.rules) == 2


def test_carry_reports_a_refused_preset_and_does_the_rest():
    robot = _Robot(fail_add={"All downstairs"})
    setup = mapsnapshot.carry_setup([APP_PRESET, {**APP_PRESET, "rule_id": 3, "rule_name": _b64("Kitchen")}],
                                    [], SRC)
    out = mapcopy.carry(robot, NEW, setup)
    assert out["presets"] == 1 and "All downstairs" in out["skipped"][0]


class _TidyRobot(_Robot):
    def __init__(self, **kw):
        super().__init__(**kw)
        self.current, self.saved, self.calls = NEW, False, []

    def get_map_info(self):
        return self.current, [{"map_id": SRC, "map_name": _b64("Downstairs"), "is_saved": True},
                              {"map_id": NEW, "map_name": "", "is_saved": self.saved}]

    def save_current_map(self, name):
        self.calls.append("save")
        self.saved = True
        return 0

    def add_preset(self, body):
        self.calls.append(("add_preset", self.current))
        return super().add_preset(body)

    def set_current_map(self, mid):
        self.calls.append(("switch", mid))
        self.current = mid


def test_tidy_carries_presets_once_saved_while_the_copy_is_current():
    robot = _TidyRobot()
    pend = {"map_id": NEW, "carrier": SRC, "name": "Copy", "copy": True, "done": {"carrier": True},
            "carry": mapsnapshot.carry_setup([APP_PRESET], [], SRC)}
    out = mapcopy.tidy(robot, pend)
    assert out["carried"]["presets"] == 1 and not out["errors"]
    assert robot.calls == ["save", ("add_preset", NEW), ("switch", SRC)]
    assert pend["done"]["carry"] and pend["done"]["finished"]
    mapcopy.tidy(robot, pend)                                     # finished: nothing again
    assert len(robot.rules) == 1


def test_tidy_without_carry_is_as_before():
    robot = _TidyRobot()
    pend = {"map_id": NEW, "carrier": SRC, "name": "Copy", "copy": True, "done": {"carrier": True}}
    out = mapcopy.tidy(robot, pend)
    assert "carried" not in out and robot.rules == []


def test_tidy_retries_a_carry_the_robot_refused_and_adds_it_once():
    robot = _TidyRobot()
    refuse = [True]
    real_add = _Robot.add_preset

    def flaky(self, body):              # refused once, then taken
        if refuse[0]:
            refuse[0] = False
            raise RuntimeError("Device error -1")
        return real_add(self, body)
    robot.add_preset = flaky.__get__(robot)
    pend = {"map_id": NEW, "carrier": SRC, "name": "Copy", "copy": True, "done": {"carrier": True},
            "carry": mapsnapshot.carry_setup([APP_PRESET], [SCHEDULE], SRC, with_schedules=True)}
    out = mapcopy.tidy(robot, pend)
    assert out["carried"]["failed"] and not pend["done"].get("carry") and not pend["done"].get("finished")
    out = mapcopy.tidy(robot, pend)
    assert not out["carried"]["failed"] and pend["done"]["carry"] and pend["done"]["finished"]
    assert len(robot.rules) == 1 and len(robot.schedules) == 1
    assert robot.schedules[0]["clean_attr"]["custom_rule_id"] == robot.rules[0]["rule_id"]


def test_carried_text():
    assert mapcopy.carried_text({"presets": 2, "schedules": 1}) == ", plus 2 presets and 1 schedule (switched off)"
    assert mapcopy.carried_text({"presets": 1, "schedules": 0}) == ", plus 1 preset"
    assert mapcopy.carried_text(None) == ""


def test_find_preset_needs_the_map_when_two_maps_share_an_id():
    import types

    from custom_components.tapo_rv30.coordinator import TapoCoordinator
    c = types.SimpleNamespace(presets=[{"id": 3, "map_id": 1, "name": "Mop"}, {"id": 3, "map_id": 2, "name": "Up"},
                                       {"id": 4, "map_id": 1, "name": "Vac"}])
    find = TapoCoordinator.find_preset
    assert find(c, 3) is None                                 # which one? say so rather than guess
    assert find(c, 3, 2)["name"] == "Up" and find(c, "3", 1)["name"] == "Mop"
    assert find(c, 4)["name"] == "Vac" and find(c, "vac")["name"] == "Vac"
    assert find(c, "Up", 1) is None


def test_find_preset_never_matches_a_number_inside_a_name():
    # A preset made in the app since the last read: its id must not land on "Kids 6+".
    import types

    from custom_components.tapo_rv30.coordinator import TapoCoordinator
    c = types.SimpleNamespace(presets=[{"id": 1, "map_id": 1, "name": "Kids 6+"}, {"id": 3, "map_id": 1, "name": "2"},
                                       {"id": 4, "map_id": 2, "name": "Kitchen"}])
    find = TapoCoordinator.find_preset
    assert find(c, 6) is None and find(c, "6") is None and find(c, " 6 ", 1) is None
    assert find(c, 2)["id"] == 3 and find(c, "2", 1)["id"] == 3     # named exactly "2", no id 2
    assert find(c, 2, 2) is None                                     # not on that map
    assert find(c, 1)["name"] == "Kids 6+"                           # an id still wins
    assert find(c, "kids")["id"] == 1 and find(c, "kitch")["id"] == 4 and find(c, "Kids 6+")["id"] == 1
    assert find(c, "kit", 2)["id"] == 4 and find(c, "k") is None     # text: exact, then a unique part


def test_preset_ref_id():
    from custom_components.tapo_rv30.mapdata import preset_ref_id
    assert preset_ref_id(6) == 6 and preset_ref_id("6") == 6 and preset_ref_id(" 12 ") == 12 and preset_ref_id(6.0) == 6
    for ref in ("Kids 6+", "6a", "", "-1", "\u00b2", True, None, 6.5, [6]):
        assert preset_ref_id(ref) is None, ref
