"""The Map Rotation select's registry entry (its renamed entity_id, area, disabled state) is only
dropped when a map list was read and no map has rotate_angle: a failed or empty first map read
keeps it, and rotation reported later reloads the entry to add the select back."""
import asyncio
import sys
import types

import pytest

from custom_components.tapo_rv30 import coordinator as C

# select.py needs the select base and EntityCategory; plain stand-ins are enough here.
if "homeassistant.components.select" not in sys.modules:
    sys.modules["homeassistant.components.select"] = types.ModuleType("homeassistant.components.select")
if "homeassistant.const" not in sys.modules:
    sys.modules["homeassistant.const"] = types.ModuleType("homeassistant.const")
if not hasattr(sys.modules["homeassistant.components.select"], "SelectEntity"):
    sys.modules["homeassistant.components.select"].SelectEntity = type("SelectEntity", (), {})
if not hasattr(sys.modules["homeassistant.const"], "EntityCategory"):
    sys.modules["homeassistant.const"].EntityCategory = types.SimpleNamespace(CONFIG="config")

from custom_components.tapo_rv30 import select as S

ENTRY = types.SimpleNamespace(entry_id="abc123")
MAP = {"width": 2, "height": 2, "resolution": 50, "real_origin_coor": [0, 0, 0],
       "map_data": "", "area_list": [], "map_name": ""}


class _Registry:
    def __init__(self):
        self.ids = {("select", f"{ENTRY.entry_id}_map_rotation"): "select.kitchen_map_turn"}
        self.removed = []

    def async_get_entity_id(self, domain, platform, unique_id):
        return self.ids.get((domain, unique_id))

    def async_remove(self, eid):
        self.removed.append(eid)


def _coordinator(monkeypatch, map_list):
    def get_map_info():
        if map_list is None:
            raise RuntimeError("map refused (-3016)")
        return 7, map_list

    reloads = []
    monkeypatch.setattr(C, "render_map", lambda m, rot: (None, [], {}))
    monkeypatch.setattr(C, "room_mask_png", lambda m, rot: b"")
    c = C.TapoCoordinator.__new__(C.TapoCoordinator)
    c.client = types.SimpleNamespace(get_map_info=get_map_info, get_map_data=lambda mid: dict(MAP))
    c.components = {}; c.settings = {}; c.lock_supported = False
    c.rotation_supported = False; c.rotation_known = False; c._rotation_at_setup = False
    c.maps = []; c.last_clean_info = {}; c._record_rendered_ts = None
    c._live_map = None; c._apply_position = lambda m: None; c.map_image_bytes = None
    c.device_name = "Test Robot"; c.entry = ENTRY; c._reload_asked = False; c.data = None
    c.hass = types.SimpleNamespace(data={"tapo_rv30": {ENTRY.entry_id: c}}, config_entries=types.SimpleNamespace(
        async_schedule_reload=reloads.append))
    return c, reloads


def _setup(c, monkeypatch):
    """First poll (map read, then what the platforms see), then the select platform."""
    try:
        c._refresh_map()
    except Exception:       # _update_once catches a failed map read and carries on
        pass
    c._note_rotation()
    c.data = {"consumables": {"filter_time": 12}}     # the parts list was read
    reg = _Registry()
    monkeypatch.setattr(sys.modules["homeassistant.helpers.entity_registry"], "async_get",
                        lambda hass: reg, raising=False)
    added = []
    asyncio.run(S.async_setup_entry(c.hass, ENTRY, added.extend))
    return reg, [type(e).__name__ for e in added]


@pytest.mark.parametrize("map_list", [None, []], ids=["map read failed", "no maps yet"])
def test_unknown_rotation_keeps_the_entry_and_reloads_once_reported(monkeypatch, map_list):
    c, reloads = _coordinator(monkeypatch, map_list)
    reg, added = _setup(c, monkeypatch)
    assert reg.removed == [] and "TapoMapRotationSelect" not in added

    map_list = [{"map_id": 7, "map_name": "", "rotate_angle": 90}]
    c.client.get_map_info = lambda: (7, map_list)
    c._refresh_map()
    c._note_rotation()
    assert c.rotation_supported and reloads == [ENTRY.entry_id]
    c._note_rotation()      # asked once only
    assert reloads == [ENTRY.entry_id]


def test_maps_without_rotate_angle_still_drop_the_entry(monkeypatch):
    c, reloads = _coordinator(monkeypatch, [{"map_id": 7, "map_name": ""}])
    reg, added = _setup(c, monkeypatch)
    assert reg.removed == ["select.kitchen_map_turn"] and "TapoMapRotationSelect" not in added
    c._refresh_map()
    c._note_rotation()
    assert reloads == []


def test_rotation_at_setup_makes_the_select_and_never_reloads(monkeypatch):
    c, reloads = _coordinator(monkeypatch, [{"map_id": 7, "map_name": "", "rotate_angle": 0}])
    reg, added = _setup(c, monkeypatch)
    assert reg.removed == [] and "TapoMapRotationSelect" in added
    c._refresh_map()
    c._note_rotation()
    assert reloads == []
