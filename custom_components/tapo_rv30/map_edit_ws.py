"""Websocket commands for the sidebar page's map editor.

tapo_rv30/map/edit_get    {entity_id, map_id?}   -> the editable layers of a map (world mm)
tapo_rv30/map/edit_apply  {entity_id, map_id, areas?, furniture?, rooms?, order?} -> write them

Only the editable layers are touched (no-go zones, virtual walls, carpets, furniture, room
names and order). The map's shape (grid) is the robot's own and is never written.
"""
from __future__ import annotations

import base64
from typing import Any

import voluptuous as vol
from homeassistant.components import websocket_api
from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er

from .const import DOMAIN
from .mapdata import b64name

_KEY = f"{DOMAIN}_map_edit_ws"
_AREA_TYPES = ("forbid", "virtual_wall", "carpet_rectangle", "carpet_round")


def _coord(hass: HomeAssistant, entity_id: str):
    entry = er.async_get(hass).async_get(entity_id)
    if entry is None or entry.platform != DOMAIN:
        return None
    return hass.data.get(DOMAIN, {}).get(entry.config_entry_id)


def async_setup_map_edit_ws(hass: HomeAssistant) -> None:
    if hass.data.get(_KEY):
        return
    hass.data[_KEY] = True
    websocket_api.async_register_command(hass, ws_edit_get)
    websocket_api.async_register_command(hass, ws_edit_apply)


@websocket_api.websocket_command({
    vol.Required("type"): "tapo_rv30/map/edit_get",
    vol.Required("entity_id"): str,
    vol.Optional("map_id"): int,
})
@websocket_api.async_response
async def ws_edit_get(hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict[str, Any]) -> None:
    coord = _coord(hass, msg["entity_id"])
    if coord is None:
        connection.send_error(msg["id"], "not_found", f"No Tapo vacuum for {msg['entity_id']}")
        return
    map_id = msg.get("map_id") or coord.map_id
    try:
        data = await hass.async_add_executor_job(coord.client.get_map_data, map_id)
    except Exception as exc:
        connection.send_error(msg["id"], "read_failed", str(exc))
        return
    areas = {t: [] for t in _AREA_TYPES}
    rooms = []
    for a in data.get("area_list", []):
        t = a.get("type")
        if t in areas:
            areas[t].append({"id": a.get("id"), "vertexs": a.get("vertexs")})
        elif t == "room":
            rooms.append({"id": a.get("id"), "name": b64name(a.get("name", "")),
                          "vertexs": a.get("vertexs")})
    connection.send_result(msg["id"], {
        "map_id": map_id,
        "areas": areas,
        "furniture": data.get("furniture_list", []),
        "rooms": rooms,
    })


@websocket_api.websocket_command({
    vol.Required("type"): "tapo_rv30/map/edit_apply",
    vol.Required("entity_id"): str,
    vol.Required("map_id"): int,
    vol.Optional("areas"): dict,
    vol.Optional("furniture"): list,
    vol.Optional("rooms"): list,
    vol.Optional("order"): list,
})
@websocket_api.require_admin
@websocket_api.async_response
async def ws_edit_apply(hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict[str, Any]) -> None:
    coord = _coord(hass, msg["entity_id"])
    if coord is None:
        connection.send_error(msg["id"], "not_found", f"No Tapo vacuum for {msg['entity_id']}")
        return
    if coord.busy:
        connection.send_error(msg["id"], "busy", f"{coord.device_name} must be docked and idle to edit the map")
        return
    map_id = msg["map_id"]
    result: dict[str, Any] = {}
    try:
        # setAreaInfo writes the active map; switch to the target first.
        info = await hass.async_add_executor_job(coord.client.send, "getMapInfo")
        if (info.get("result") or {}).get("current_map_id") != map_id:
            await hass.async_add_executor_job(coord.client.set_current_map, map_id)
        for t, items in (msg.get("areas") or {}).items():
            if t in _AREA_TYPES:
                result[t] = await hass.async_add_executor_job(coord.client.set_areas, map_id, t, items)
        if "furniture" in msg:
            result["furniture"] = await hass.async_add_executor_job(
                coord.client.set_furniture, map_id, msg["furniture"])
        if msg.get("rooms"):
            room_areas = [{"type": "room", "id": r["id"],
                           "name": base64.b64encode(str(r.get("name", "")).encode()).decode()}
                          for r in msg["rooms"] if r.get("id") is not None]
            result["rooms"] = await hass.async_add_executor_job(
                coord.client.set_areas, map_id, "room", room_areas)
        if msg.get("order"):
            result["order"] = await hass.async_add_executor_job(
                coord.client.set_clean_order, map_id, msg["order"])
    except Exception as exc:
        connection.send_error(msg["id"], "write_failed", str(exc))
        return
    await coord.async_request_map_refresh()
    connection.send_result(msg["id"], {"map_id": map_id, "result": result})
