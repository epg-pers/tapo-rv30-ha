"""Websocket commands for the sidebar page's Presets tab.

tapo_rv30/preset/list  {entity_id}  -> the maps and every preset on the robot: rooms in cleaning
                                       order with their own levels, and the schedules that run it
tapo_rv30/preset/save  {entity_id, map_id, preset_id?, name, clean_order, rooms}
                                    -> make a preset, or change one (preset_id), as the app does

Checking and building what is written lives in presetedit (pure, unit-tested); this is the thin
Home Assistant layer over it. Deleting and running use the delete_preset and run_preset actions.
"""
from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol
from homeassistant.components import websocket_api
from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er

from . import presetedit
from .const import DOMAIN
from .mapdata import b64name, fold

_LOGGER = logging.getLogger(__name__)
_KEY = f"{DOMAIN}_preset_ws"


def _coord(hass: HomeAssistant, entity_id: str):
    entry = er.async_get(hass).async_get(entity_id)
    if entry is None or entry.platform != DOMAIN:
        return None
    return hass.data.get(DOMAIN, {}).get(entry.config_entry_id)


def async_setup_preset_ws(hass: HomeAssistant) -> None:
    if hass.data.get(_KEY):
        return
    hass.data[_KEY] = True
    websocket_api.async_register_command(hass, ws_preset_list)
    websocket_api.async_register_command(hass, ws_preset_save)


def _room_names(coord, map_id: int) -> dict[int, str]:
    """A map's room names (blocking): the current map's from the last poll, another's read."""
    if map_id == coord.map_id and coord.rooms:
        return {r["id"]: b64name(r.get("name", "")) for r in coord.rooms}
    return coord._room_names_for(map_id)


def _read(coord) -> tuple[list, dict, dict]:
    """Every preset with its rooms, and the room names of the maps they are on (blocking)."""
    rules = [r for r in coord.client.get_presets() if isinstance(r, dict) and r.get("rule_id") is not None]
    details = {}
    for r in rules:
        try:
            details[(r.get("map_id"), r["rule_id"])] = coord.client.get_preset_detail(r.get("map_id"), r["rule_id"])
        except Exception as exc:    # shown without its rooms rather than not at all
            _LOGGER.debug("Preset %s detail failed: %s", r.get("rule_id"), exc)
    names = {mid: _room_names(coord, mid) for mid in {r.get("map_id") for r in rules}}
    return rules, details, names


@websocket_api.websocket_command({
    vol.Required("type"): "tapo_rv30/preset/list",
    vol.Required("entity_id"): str,
})
@websocket_api.async_response
async def ws_preset_list(hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict[str, Any]) -> None:
    coord = _coord(hass, msg["entity_id"])
    if coord is None:
        connection.send_error(msg["id"], "not_found", f"No Tapo vacuum for {msg['entity_id']}")
        return
    try:
        rules, details, names = await hass.async_add_executor_job(_read, coord)
    except Exception as exc:
        connection.send_error(msg["id"], "read_failed", f"could not read the presets: {exc}")
        return
    connection.send_result(msg["id"], {
        "maps": [{"id": m["id"], "name": m.get("name"), "current": m["id"] == coord.map_id,
                  "saved": m.get("saved", True) is not False} for m in coord.maps],
        "presets": presetedit.view(rules, details, names, coord.schedules),
    })


@websocket_api.websocket_command({
    vol.Required("type"): "tapo_rv30/preset/save",
    vol.Required("entity_id"): str,
    vol.Required("map_id"): int,
    vol.Optional("preset_id"): int,
    vol.Required("name"): str,
    vol.Optional("clean_order", default=True): bool,
    vol.Required("rooms"): [dict],
})
@websocket_api.async_response
async def ws_preset_save(hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict[str, Any]) -> None:
    coord = _coord(hass, msg["entity_id"])
    if coord is None:
        connection.send_error(msg["id"], "not_found", f"No Tapo vacuum for {msg['entity_id']}")
        return
    map_id, preset_id = msg["map_id"], msg.get("preset_id")
    if not any(m["id"] == map_id and m.get("saved", True) is not False for m in coord.maps):
        connection.send_error(msg["id"], "invalid", f"map {map_id} is not a saved map on {coord.device_name}")
        return

    def _write() -> tuple[int, int | None]:
        rules = [r for r in coord.client.get_presets() if r.get("map_id") == map_id and r.get("rule_id") is not None]
        if preset_id is not None and not any(r["rule_id"] == preset_id for r in rules):
            raise presetedit.PresetError("that preset is not on this map any more")
        others = [{"id": r["rule_id"], "name": b64name(r.get("rule_name", ""))} for r in rules]
        rooms = [a for a in coord.client.get_map_data(map_id).get("area_list", []) if a.get("type") == "room"]
        body = presetedit.body(msg["name"], map_id, msg["rooms"], msg["clean_order"], rooms, others, preset_id)
        code = coord.client.add_preset(body)
        if code or preset_id is not None:
            return code, preset_id
        # A new preset: the robot picks its id; find it by its (unique) name.
        made = [r for r in coord.client.get_presets() if r.get("map_id") == map_id
                and fold(b64name(r.get("rule_name", ""))) == fold(msg["name"].strip())]
        return code, made[0]["rule_id"] if made else None

    try:
        code, rid = await hass.async_add_executor_job(_write)
    except presetedit.PresetError as exc:
        connection.send_error(msg["id"], "invalid", str(exc))
        return
    except Exception as exc:
        connection.send_error(msg["id"], "write_failed", f"the robot did not take the preset: {exc}")
        return
    if code:
        connection.send_error(msg["id"], "write_failed", f"the robot refused the preset (error {code})")
        return
    # The preset buttons, the schedule editor and the map's setup snapshot follow at once.
    await coord.async_settings_changed()
    connection.send_result(msg["id"], {"preset_id": rid, "name": msg["name"].strip(), "map_id": map_id})
