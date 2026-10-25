"""Websocket commands for the sidebar page's map editor.

tapo_rv30/map/edit_get    {entity_id, map_id?, picture?} -> the editable layers of a map (world mm),
                          and with picture: true its drawing and geometry (any saved map, not just
                          the current one)
tapo_rv30/map/edit_apply  {entity_id, map_id, areas?, furniture?, rooms?, order?} -> write them

Only the editable layers are touched (no-go zones, virtual walls, carpets, furniture, room
names and order). The map's shape (grid) is the robot's own and is never written.
"""
from __future__ import annotations

import base64
import logging
from typing import Any

import voluptuous as vol
from homeassistant.components import websocket_api
from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er

from .const import DOMAIN, FURNITURE_TYPES
from .mapdata import b64name

_LOGGER = logging.getLogger(__name__)

_KEY = f"{DOMAIN}_map_edit_ws"
_AREA_TYPES = ("forbid", "virtual_wall", "carpet_rectangle", "carpet_round")
_KEEP = ("label", "define_type", "carpet_strategy")   # robot fields the editor does not round-trip
_ROOM_KEEP = ("color", "define_type", "floor_material", "floor_texture", "carpet_strategy", "label")


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
    vol.Optional("picture", default=False): bool,
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
    picture = geometry = None
    if msg.get("picture"):
        # Drawn here rather than taken from the camera, which only shows the current map: the
        # same renderer and the map's own rotation, so the picture and geometry always agree.
        from .maprender import _png, render_map

        def _draw():
            # The angle from the robot itself: a turn just made may not have reached the cache.
            from .maprender import rotation_of
            try:
                _, map_list = coord.client.get_map_info()
                turn = next((rotation_of(m.get("rotate_angle")) for m in map_list if m.get("map_id") == map_id), 0)
            except Exception:
                turn = coord.rotation_for(map_id)
            img, _, geom = render_map(data, turn)
            return "data:image/png;base64," + base64.b64encode(_png(img)).decode(), geom
        try:
            picture, geometry = await hass.async_add_executor_job(_draw)
        except Exception as exc:
            connection.send_error(msg["id"], "render_failed", str(exc))
            return
    connection.send_result(msg["id"], {
        "map_id": map_id,
        "current": map_id == coord.map_id,
        "picture": picture,
        "geometry": geometry,
        "areas": areas,
        "furniture": data.get("furniture_list", []),
        "furniture_types": {str(k): v for k, v in FURNITURE_TYPES.items()},
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
    if coord.map_busy:
        connection.send_error(msg["id"], "busy", f"{coord.device_name} must be docked and idle to edit the map")
        return
    if coord.map_lock.locked():
        connection.send_error(msg["id"], "busy", f"Another map write to {coord.device_name} is still running")
        return
    async with coord.map_lock:     # one map write per robot at a time (each switches maps)
        # Asked live: the last poll may predate the robot's own schedule starting it.
        if await coord._robot_working():
            connection.send_error(msg["id"], "busy", f"{coord.device_name} is working; edit the map once it is "
                                  "docked and idle")
            return
        map_id = msg["map_id"]
        result: dict[str, Any] = {}
        previous = None
        try:
            # setAreaInfo and setFurnitureInfo write the map_id they are given, current or not
            # (checked on an RV30 Max Plus), so the robot stays on its map. The room order is not
            # known to, so for that alone switch to the map first (and back after, checked).
            info = await hass.async_add_executor_job(coord.client.send, "getMapInfo")
            current = (info.get("result") or {}).get("current_map_id")
            if current != map_id and msg.get("order"):
                previous = current
                await hass.async_add_executor_job(coord.client.set_current_map, map_id)
            # The editor only round-trips id and shape; keep the robot's own fields (label,
            # define_type, carpet handling) on zones it already has, or the save would drop them.
            existing = {}
            if msg.get("areas") or msg.get("rooms"):
                data = await hass.async_add_executor_job(coord.client.get_map_data, map_id)
                existing = {(a.get("type"), a.get("id")): a for a in data.get("area_list", [])}
            for t, items in (msg.get("areas") or {}).items():
                if t in _AREA_TYPES:
                    items = [{**{k: old[k] for k in _KEEP if k in old}, **item}
                             if (old := existing.get((t, item.get("id")))) else item
                             for item in items]
                    result[t] = await hass.async_add_executor_job(coord.client.set_areas, map_id, t, items)
            if "furniture" in msg:
                result["furniture"] = await hass.async_add_executor_job(
                    coord.client.set_furniture, map_id, msg["furniture"])
            if msg.get("rooms"):
                # Only the name changes: the rest of each room (colour, floor, carpet handling) is
                # kept as the robot has it, since setAreaInfo replaces every room.
                room_areas = [{**{k: old[k] for k in _ROOM_KEEP if k in old}, "type": "room", "id": r["id"],
                               "name": base64.b64encode(str(r.get("name", "")).encode()).decode()}
                              for r in msg["rooms"] if r.get("id") is not None
                              for old in [existing.get(("room", r["id"]), {})]]
                result["rooms"] = await hass.async_add_executor_job(
                    coord.client.set_areas, map_id, "room", room_areas)
            if msg.get("order"):
                result["order"] = await hass.async_add_executor_job(
                    coord.client.set_clean_order, map_id, msg["order"])
        except Exception as exc:
            connection.send_error(msg["id"], "write_failed", str(exc))
            return
        finally:
            if previous is not None:      # leave the robot on the map it was using
                back = None
                try:
                    await hass.async_add_executor_job(coord.client.set_current_map, previous)
                    back = await hass.async_add_executor_job(coord.client.get_map_info)
                except Exception as exc:
                    _LOGGER.warning("Could not switch %s back to map %s: %s", coord.device_name, previous, exc)
                if not back or back[0] != previous:
                    result["switched_back"] = False
                    result["warning"] = (f"{coord.device_name} could not be switched back to map {previous}; "
                                         "choose its map again in the map selector")
    await coord.async_request_map_refresh()
    connection.send_result(msg["id"], {"map_id": map_id, "result": result})
