"""Make the integration's pure modules importable without Home Assistant.

custom_components/tapo_rv30/__init__.py imports homeassistant, so register a
bare package object for it and import the submodules we test directly.
"""
import sys
import types
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
             "homeassistant.helpers.issue_registry", "homeassistant.helpers.storage"):
    if name not in sys.modules:
        sys.modules[name] = types.ModuleType(name)
_stub = sys.modules
_stub["homeassistant.components.camera"].Camera = type("Camera", (), {"__init__": lambda self: None})
_stub["homeassistant.config_entries"].ConfigEntry = object
_stub["homeassistant.core"].HomeAssistant = object
_stub["homeassistant.core"].callback = lambda f: f
_stub["homeassistant.helpers.device_registry"].DeviceInfo = dict
_stub["homeassistant.helpers.storage"].Store = type("Store", (), {"__init__": lambda self, *a, **k: None})
_stub["homeassistant.helpers.entity_platform"].AddEntitiesCallback = object


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
