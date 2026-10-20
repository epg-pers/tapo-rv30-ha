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
