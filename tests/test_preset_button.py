"""A preset button names its preset's map by id as well as by name: the sidebar page's Schedules
tab, before the Presets tab has been read, builds its preset list from these attributes, and a
preset id alone can be a different preset on another map."""
import sys
import types

# button.py needs the button base and EntityCategory; plain stand-ins are enough here.
for _name in ("homeassistant.components.button", "homeassistant.const"):
    if _name not in sys.modules:
        sys.modules[_name] = types.ModuleType(_name)
if not hasattr(sys.modules["homeassistant.components.button"], "ButtonEntity"):
    sys.modules["homeassistant.components.button"].ButtonEntity = type("ButtonEntity", (), {})
_cat = getattr(sys.modules["homeassistant.const"], "EntityCategory", None) or types.SimpleNamespace()
for _k, _v in (("CONFIG", "config"), ("DIAGNOSTIC", "diagnostic")):
    if not hasattr(_cat, _k):
        setattr(_cat, _k, _v)
sys.modules["homeassistant.const"].EntityCategory = _cat

from custom_components.tapo_rv30.button import TapoPresetButton

PRESETS = [{"id": 3, "map_id": 1, "map_name": "Down", "name": "Mop", "rooms": ["Kitchen"],
            "room_settings": [], "clean_order": True},
           {"id": 3, "map_id": 2, "map_name": "Up", "name": "Upstairs mop", "rooms": ["Landing"],
            "room_settings": [], "clean_order": False}]


def _button(rule_id, map_id):
    b = TapoPresetButton.__new__(TapoPresetButton)
    b.coordinator = types.SimpleNamespace(presets=PRESETS)
    b._rule_id, b._map_id = rule_id, map_id
    return b


def test_preset_button_names_its_map_by_id():
    attrs = _button(3, 2).extra_state_attributes
    assert attrs == {"preset_id": 3, "preset_name": "Upstairs mop", "map_id": 2, "map_name": "Up",
                     "rooms": ["Landing"], "room_settings": [], "clean_order": False}
    assert _button(3, 1).extra_state_attributes["map_id"] == 1


def test_gone_preset_button_has_no_map():
    assert _button(9, 1).extra_state_attributes["map_id"] is None
