"""Planner decisions."""
from datetime import UTC, datetime

from custom_components.tapo_rv30.planlogic import (
    DAY,
    RoomState,
    Snapshot,
    decide,
    due_chip,
    in_window,
    merged_config,
    next_window_start,
    room_score,
    room_status,
    schedule_soon,
    sensors_in_use,
)

TUE_11 = datetime(2026, 10, 20, 11, 0, tzinfo=UTC)      # a Tuesday
SAT_11 = datetime(2026, 10, 24, 11, 0, tzinfo=UTC)


def cfg(**over):
    c = merged_config({"enabled": True, "preview": False})
    c.update(over)
    return c


def snap(now=TUE_11, **over):
    t = now.timestamp()
    base = dict(now=now, robot_docked=True, robot_busy=None, robot_error=False, battery=90, dnd=None,
                people_home=[], schedules=[], skip_today=False, ran_window=None,
                rooms=[RoomState("1:2", "Kitchen", t - 3 * DAY, 2), RoomState("1:4", "Hall", t - 2.2 * DAY, 2),
                       RoomState("1:5", "Lounge", t - 0.2 * DAY, 2), RoomState("1:3", "Bedroom", t - 4 * DAY, 7)])
    base.update(over)
    return Snapshot(**base)


def test_config_merge_keeps_defaults():
    c = merged_config({"windows": {"weekends": ["08:00", "12:00"]}, "min_battery": 30, "junk": 1})
    assert c["windows"] == {"weekdays": ["09:00", "17:00"], "weekends": ["08:00", "12:00"]}
    assert c["min_battery"] == 30 and "junk" not in c and c["enabled"] is False and c["preview"] is True


def test_scores_and_statuses():
    now = TUE_11.timestamp()
    assert room_score(now - 3 * DAY, 2, now) == 1.5 and room_score(None, 2, now) == 99.0
    assert room_score(now, 0, now) is None
    assert room_status(now - 3 * DAY, 2, now) == "Overdue"
    assert room_status(now - 2.2 * DAY, 2, now) == "Due today"
    assert room_status(now - 0.2 * DAY, 2, now) == "Fresh"
    assert room_status(now - 4 * DAY, 7, now) == "In 3 days"
    assert room_status(now - 1.5 * DAY, 2, now) == "In 1 day"
    assert room_status(None, 0, now) == "Left out"
    assert due_chip("Kitchen", now - 3 * DAY, 2, now) == "Kitchen 1 day overdue"
    assert due_chip("Hall", now - 2.2 * DAY, 2, now) == "Hall due today"


def test_windows():
    c = cfg()
    assert in_window(TUE_11, c) and not in_window(TUE_11.replace(hour=8), c)
    assert not in_window(TUE_11.replace(hour=17), c)
    assert in_window(SAT_11, c) and not in_window(SAT_11.replace(hour=16, minute=30), c)
    assert next_window_start(TUE_11.replace(hour=7), c).hour == 9
    nxt = next_window_start(TUE_11.replace(hour=18), c)
    assert (nxt.day, nxt.hour) == (21, 9)
    nxt = next_window_start(datetime(2026, 10, 23, 18, 0, tzinfo=UTC), c)   # Friday evening
    assert (nxt.day, nxt.hour) == (24, 10)


def test_cleans_due_rooms_most_overdue_first():
    d = decide(snap(), cfg())
    assert d.action == "clean" and d.names == ["Kitchen", "Hall"] and d.rooms == ["1:2", "1:4"]
    assert d.status == "Cleaning Kitchen and Hall"
    assert d.chips == ["Kitchen 1 day overdue", "Hall due today"]


def test_preview_says_would():
    d = decide(snap(), cfg(preview=True))
    assert d.action == "clean" and d.status == "Would clean Kitchen and Hall"


def test_each_condition_holds_it_back():
    c = cfg()
    assert decide(snap(), merged_config({})).waiting_for == "off"
    assert decide(snap(skip_today=True), c).waiting_for == "skipped"
    assert decide(snap(now=TUE_11.replace(hour=7)), c).status == "Waiting for the cleaning window at 09:00"
    assert decide(snap(ran_window="2026-10-20"), c).waiting_for == "ran"
    assert decide(snap(robot_error=True), c).waiting_for == "error"
    assert decide(snap(robot_docked=False), c).waiting_for == "busy"
    assert decide(snap(robot_busy="cleaning"), c).waiting_for == "busy"
    dnd = {"do_not_disturb": True, "s_min": 10 * 60, "e_min": 12 * 60}
    assert decide(snap(dnd=dnd), c).status == "Do Not Disturb until 12:00"
    assert decide(snap(battery=20), c).status == "Battery at 20%, waiting for 40%"
    assert decide(snap(people_home=["Ed"]), c).status == "Waiting: Ed is home"
    assert decide(snap(people_home=["Ed", "Kaj"]), c).status == "Waiting: Ed and Kaj are home"
    assert decide(snap(people_home=["Ed"]), cfg(require_away=False)).action == "clean"
    sched = [{"enabled": True, "time": "11:30", "days": ["Tue"]}]
    assert decide(snap(schedules=sched), c).status == "A schedule on the robot runs at 11:30"
    assert decide(snap(schedules=sched), cfg(avoid_schedules=False)).action == "clean"


def test_rooms_in_use_are_left_out_or_hold_the_run():
    t = TUE_11.timestamp()
    rooms = [RoomState("1:2", "Kitchen", t - 3 * DAY, 2, ["Kitchen motion"]), RoomState("1:4", "Hall", t - 2.2 * DAY, 2)]
    d = decide(snap(rooms=rooms), cfg())
    assert d.action == "clean" and d.names == ["Hall"]
    rooms[1].in_use_by = ["Hall presence"]
    d = decide(snap(rooms=rooms), cfg())
    assert d.waiting_for == "in_use" and "Kitchen (Kitchen motion)" in d.status
    assert decide(snap(rooms=rooms), cfg(skip_in_use=False)).action == "clean"


def test_nothing_due_and_room_skipped_today():
    t = TUE_11.timestamp()
    assert decide(snap(rooms=[RoomState("1:5", "Lounge", t - 0.2 * DAY, 2)]), cfg()).waiting_for == "nothing_due"
    rooms = [RoomState("1:2", "Kitchen", t - 3 * DAY, 2, skipped_today=True), RoomState("1:4", "Hall", t - 2.2 * DAY, 2)]
    assert decide(snap(rooms=rooms), cfg()).names == ["Hall"]
    assert decide(snap(rooms=[RoomState("1:2", "Kitchen", t - 9 * DAY, 0)]), cfg()).waiting_for == "nothing_due"


def test_schedule_soon_ignores_disabled_blocked_and_other_days():
    s = [{"enabled": False, "time": "11:20", "days": ["Tue"]}, {"enabled": True, "time": "11:20", "days": ["Wed"]},
         {"enabled": True, "time": "11:20", "days": ["Tue"], "blocked_by_dnd": True}, {"enabled": True, "time": "13:00", "days": ["Tue"]}]
    assert schedule_soon(TUE_11, s) is None
    assert schedule_soon(TUE_11, [{"enabled": True, "time": "11:59", "days": ["Tue"]}])


def test_sensors_in_use():
    now = TUE_11.timestamp()
    readings = [("Kitchen motion", True, now - 30), ("Hall motion", False, now - 5 * 60), ("Lounge motion", False, now - 20 * 60),
                ("Old", False, None)]
    assert sensors_in_use(readings, now, 10) == ["Kitchen motion", "Hall motion"]


def test_validate_changes():
    import pytest

    from custom_components.tapo_rv30.planlogic import PlannerError, validate_changes
    cur = merged_config({})
    out = validate_changes({"enabled": 1, "min_battery": 150, "windows": {"weekdays": ["08:30", "16:00"]},
                            "rooms": {"1:2": {"target_days": 3, "add_sensors": ["binary_sensor.k", "light.x"]}},
                            "people": ["person.ed", "sensor.nope"]}, cur)
    assert out["enabled"] is True and out["min_battery"] == 100
    assert out["windows"] == {"weekdays": ["08:30", "16:00"], "weekends": ["10:00", "16:00"]}
    assert out["rooms"] == {"1:2": {"target_days": 3, "add_sensors": ["binary_sensor.k"]}}
    assert out["people"] == ["person.ed"] and validate_changes({"people": None}, cur) == {"people": None}
    for bad in ({"nope": 1}, {"windows": {"weekdays": ["17:00", "09:00"]}}, {"windows": {"weekdays": ["9", "10:00"]}},
                {"rooms": {"1:2": {"target_days": 6}}}, {"rooms": {"1:2": {"colour": "red"}}}, {"on_return": "panic"}):
        with pytest.raises(PlannerError):
            validate_changes(bad, cur)
