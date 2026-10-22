"""Service targets: named entities, devices, areas, floors and labels."""
import pytest

from custom_components.tapo_rv30.targets import TargetError, as_list, has_indirect_target, resolve

REG = {
    "vacuum.jarvis": ("tapo_rv30", "e1"), "sensor.jarvis_battery": ("tapo_rv30", "e1"),
    "vacuum.upstairs": ("tapo_rv30", "e2"),
    "light.kitchen": ("hue", "h1"), "vacuum.other_brand": ("roborock", "r1"),
}
LOADED = {"e1": "jarvis", "e2": "upstairs"}
entry_of = REG.get


def test_helpers():
    assert as_list(None) == [] and as_list("a") == ["a"] and as_list(["a", "b"]) == ["a", "b"]
    assert has_indirect_target({"area_id": "kitchen"}) and has_indirect_target({"label_id": ["x"]})
    assert not has_indirect_target({"entity_id": "vacuum.jarvis", "area_id": []})


def test_no_target_uses_the_only_robot_or_asks():
    assert resolve({"e1": "jarvis"}, [], [], entry_of, "tapo_rv30", False) == ["jarvis"]
    with pytest.raises(TargetError, match="2 Tapo vacuums"):
        resolve(LOADED, [], [], entry_of, "tapo_rv30", False)


def test_named_entities_are_strict():
    assert resolve(LOADED, ["vacuum.upstairs"], [], entry_of, "tapo_rv30", False) == ["upstairs"]
    with pytest.raises(TargetError, match=r"light\.kitchen is not a Tapo"):
        resolve(LOADED, ["light.kitchen"], [], entry_of, "tapo_rv30", False)


def test_area_or_device_keeps_only_our_robots_once():
    # an area holding a light, another brand's vacuum and Jarvis plus its own sensor
    got = resolve(LOADED, [], ["light.kitchen", "vacuum.other_brand", "vacuum.jarvis",
                               "sensor.jarvis_battery"], entry_of, "tapo_rv30", True)
    assert got == ["jarvis"]
    # a floor with both robots, with two robots set up: both, in order
    assert resolve(LOADED, [], ["vacuum.jarvis", "vacuum.upstairs"], entry_of, "tapo_rv30", True) == ["jarvis", "upstairs"]


def test_target_with_no_robot_is_a_clear_error_not_a_fallback():
    with pytest.raises(TargetError, match="no Tapo robot vacuum"):
        resolve({"e1": "jarvis"}, [], ["light.kitchen"], entry_of, "tapo_rv30", True)
    with pytest.raises(TargetError, match="no Tapo robot vacuum"):
        resolve({"e1": "jarvis"}, [], [], entry_of, "tapo_rv30", True)
