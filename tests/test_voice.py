"""Voice helpers: which robot a sentence is about, and cleaning up the room phrase."""
import types

from custom_components.tapo_rv30 import voice
from custom_components.tapo_rv30.const import DOMAIN


def robot(name, rooms, busy=None, code=6):
    return types.SimpleNamespace(device_name=name, busy=busy, status_code=code,
                                 rooms_named=lambda: [{"name_text": r} for r in rooms])


def hass_with(*robots):
    return types.SimpleNamespace(data={DOMAIN: {str(i): r for i, r in enumerate(robots)}})


def test_one_robot_is_always_picked():
    j = robot("Jarvis", ["Kitchen"])
    assert voice._pick(hass_with(j), "vacuum the attic") is j


def test_two_robots_named_by_rooms_or_activity_or_asked():
    j, u = robot("Jarvis", ["Kitchen", "Lounge"]), robot("Upstairs Bot", ["Bedroom"], busy="cleaning", code=1)
    h = hass_with(j, u)
    assert voice._pick(h, "tell upstairs bot to clean the landing") is u           # by name
    assert voice._pick(h, "vacuum the kitchen", rooms=["kitchen"]) is j          # only one has it
    assert voice._pick(h, "stop the vacuum", active=True) is u                   # only one working
    assert voice._pick(h, "send the robot home") is None                        # ask which
    assert "Jarvis or Upstairs Bot" in voice._which(h)


def test_room_phrase_drops_please_and_the_robot_name():
    h = hass_with(robot("Jarvis", []), robot("Bot", []))
    assert voice._clean_phrase("kitchen please", h) == "kitchen"
    assert voice._clean_phrase("the kitchen with jarvis", h) == "the kitchen"
    assert voice._clean_phrase("kitchen with the lounge", h) == "kitchen with the lounge"   # not a robot
