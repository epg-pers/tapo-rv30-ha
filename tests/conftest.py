"""Make the integration's pure modules importable without Home Assistant.

custom_components/tapo_rv30/__init__.py imports homeassistant, so register a
bare package object for it and import the submodules we test directly.
"""
import importlib.util
import sys
import types
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PKG_DIR = ROOT / "custom_components" / "tapo_rv30"

for name, path in (("custom_components", ROOT / "custom_components"), ("custom_components.tapo_rv30", PKG_DIR)):
    if name not in sys.modules:
        pkg = types.ModuleType(name)
        pkg.__path__ = [str(path)]
        sys.modules[name] = pkg


# camera.py imports Home Assistant's Camera base; stub just enough for the pure helper test.
for name in ("homeassistant", "homeassistant.components", "homeassistant.components.camera",
             "homeassistant.config_entries", "homeassistant.core", "homeassistant.helpers",
             "homeassistant.helpers.device_registry", "homeassistant.helpers.entity_platform",
             "homeassistant.helpers.update_coordinator", "homeassistant.exceptions",
             "homeassistant.helpers.issue_registry", "homeassistant.helpers.storage",
             "homeassistant.util", "homeassistant.util.dt", "homeassistant.components.websocket_api",
             "homeassistant.components.persistent_notification", "homeassistant.helpers.entity_registry",
             "homeassistant.helpers.area_registry", "homeassistant.helpers.dispatcher", "homeassistant.helpers.event"):
    if name not in sys.modules:
        sys.modules[name] = types.ModuleType(name)
_stub = sys.modules
_stub["homeassistant.components.camera"].Camera = type("Camera", (), {"__init__": lambda self: None})
_stub["homeassistant.config_entries"].ConfigEntry = object
_stub["homeassistant.core"].HomeAssistant = object
_stub["homeassistant.core"].callback = lambda f: f
_stub["homeassistant.helpers.device_registry"].DeviceInfo = dict
_stub["homeassistant.helpers.storage"].Store = type("Store", (), {"__init__": lambda self, *a, **k: None,
                                                                   "async_delay_save": lambda self, *a, **k: None})
_stub["homeassistant.helpers.entity_platform"].AddEntitiesCallback = object
_stub["homeassistant.util"].dt = _stub["homeassistant.util.dt"]
_stub["homeassistant.util.dt"].now = lambda tz=None: __import__("datetime").datetime.now(tz)
_stub["homeassistant.util.dt"].utc_from_timestamp = lambda ts: datetime.fromtimestamp(ts, UTC)
_stub["homeassistant.util.dt"].as_local = lambda d: d.astimezone()

# planner.py: the registries and listeners it touches, as inert stand-ins.
_stub["homeassistant.core"].Event = object
_stub["homeassistant.helpers.area_registry"].async_get = \
    lambda hass: types.SimpleNamespace(async_list_areas=lambda: [], async_get_area=lambda area_id: None)
_stub["homeassistant.helpers.dispatcher"].async_dispatcher_send = lambda *a, **k: None
_stub["homeassistant.helpers.event"].async_track_state_change_event = lambda *a, **k: lambda: None
_stub["homeassistant.helpers.event"].async_track_time_interval = lambda *a, **k: lambda: None


class _Coord:
    def __init__(self, *a, **k): pass
    def __class_getitem__(cls, item): return cls


_stub["homeassistant.helpers.update_coordinator"].CoordinatorEntity = _Coord
_stub["homeassistant.helpers.update_coordinator"].DataUpdateCoordinator = _Coord
_stub["homeassistant.helpers.update_coordinator"].UpdateFailed = Exception
_stub["homeassistant.exceptions"].ConfigEntryAuthFailed = Exception
_stub["homeassistant.exceptions"].HomeAssistantError = Exception
_stub["homeassistant.exceptions"].ServiceValidationError = Exception

_stub["homeassistant.helpers"].issue_registry = _stub["homeassistant.helpers.issue_registry"]

# map_edit_ws: voluptuous (only if not installed) and the websocket decorators, as pass-throughs.
if importlib.util.find_spec("voluptuous") is None and "voluptuous" not in sys.modules:
    _vol = sys.modules["voluptuous"] = types.ModuleType("voluptuous")
    _vol.Required = _vol.Optional = lambda key, **kw: key
_ws = _stub["homeassistant.components.websocket_api"]
if not hasattr(_ws, "websocket_command"):
    _ws.websocket_command = lambda schema: lambda f: f
    _ws.require_admin = _ws.async_response = lambda f: f
    _ws.ActiveConnection = object
_stub["homeassistant.components"].websocket_api = _ws
_stub["homeassistant.components"].persistent_notification = _stub["homeassistant.components.persistent_notification"]
_stub["homeassistant.helpers"].entity_registry = _stub["homeassistant.helpers.entity_registry"]
