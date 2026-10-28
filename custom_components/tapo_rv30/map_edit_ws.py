"""Websocket commands for the sidebar page's map editor.

tapo_rv30/map/edit_get    {entity_id, map_id?, picture?, wait?} -> the editable layers of a map (world
                          mm), and with picture: true its drawing, geometry and where each room is
                          on it (any saved map, not just the current one); with wait: true, read
                          only once a running map write has ended
tapo_rv30/map/edit_apply  {entity_id, map_id, areas?, furniture?, rooms?, order?} -> write them
                          rooms: [{id, name?, floor_texture?}], the rooms to change; every
                          other room is written back as the robot has it

Only the editable layers are touched (no-go zones, virtual walls, carpets, furniture, room
names, cleaning directions and order). The map's shape (grid) is the robot's own and is never
written.
"""
from __future__ import annotations

import asyncio
import base64
import logging
from typing import Any

import voluptuous as vol
from homeassistant.components import websocket_api
from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er

from .const import DOMAIN, FURNITURE_TYPES
from .mapdata import b64name, room_areas, valid_texture

_LOGGER = logging.getLogger(__name__)

_KEY = f"{DOMAIN}_map_edit_ws"
_AREA_TYPES = ("forbid", "virtual_wall", "carpet_rectangle", "carpet_round")
_KEEP = ("label", "define_type", "carpet_strategy")   # robot fields the editor does not round-trip
# How long a read waits for a map write (an editor save, setup apply, restore or copy) to finish.
_LOCK_WAIT = 60.0
_LOCK_POLL = 0.5


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
    # The editor's own load: wait for a map write still running (see below). Other reads (a
    # preview) do not, as a backup, copy or restore can hold the lock for minutes.
    vol.Optional("wait", default=False): bool,
})
@websocket_api.async_response
async def ws_edit_get(hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict[str, Any]) -> None:
    coord = _coord(hass, msg["entity_id"])
    if coord is None:
        connection.send_error(msg["id"], "not_found", f"No Tapo vacuum for {msg['entity_id']}")
        return
    # A map write still running would give the zones from before it, and an editor saving those
    # later would undo that write: the editor waits for it to end (without taking the lock), and
    # shows "Loading map..." meanwhile.
    waited = 0.0
    while msg.get("wait") and coord.map_lock.locked():
        if waited >= _LOCK_WAIT:
            connection.send_error(msg["id"], "busy", f"A map write to {coord.device_name} is still running; "
                                  "try again once it has finished")
            return
        await asyncio.sleep(_LOCK_POLL)
        waited += _LOCK_POLL
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
            # floor_texture: the room's cleaning direction (-1 default, 0 or 90 in the map's frame)
            rooms.append({"id": a.get("id"), "name": b64name(a.get("name", "")),
                          "vertexs": a.get("vertexs"), "floor_texture": a.get("floor_texture")})
    picture = geometry = room_geometry = room_mask = None
    if msg.get("picture"):
        # Drawn here rather than taken from the camera, which only shows the current map: the
        # same renderer and the map's own rotation, so the picture and geometry always agree.
        from .maprender import _png, render_map, room_mask_png

        def _draw():
            # The angle from the robot itself: a turn just made may not have reached the cache.
            from .maprender import rotation_of
            try:
                _, map_list = coord.client.get_map_info()
                turn = next((rotation_of(m.get("rotate_angle")) for m in map_list if m.get("map_id") == map_id), 0)
            except Exception:
                turn = coord.rotation_for(map_id)
            img, rooms_geom, geom = render_map(data, turn)
            mask = "data:image/png;base64," + base64.b64encode(room_mask_png(data, turn)).decode()
            return "data:image/png;base64," + base64.b64encode(_png(img)).decode(), geom, rooms_geom, mask
        try:
            picture, geometry, room_geometry, room_mask = await hass.async_add_executor_job(_draw)
        except Exception as exc:
            connection.send_error(msg["id"], "render_failed", str(exc))
            return
    connection.send_result(msg["id"], {
        "map_id": map_id,
        "current": map_id == coord.map_id,
        "picture": picture,
        "geometry": geometry,
        # Rooms are cells in the grid, not outlines: where each is on the picture (bbox, centre, cells).
        "room_geometry": room_geometry,
        # The room-id grid, turned like the picture, 1 px per cell (scale_px_per_cell in geometry):
        # pixel value = room id, 0 wall, 255 floor, 127 unknown. Exact hit-testing for taps.
        "room_mask": room_mask,
        "areas": areas,
        "furniture": data.get("furniture_list", []),
        "furniture_types": {str(k): v for k, v in FURNITURE_TYPES.items()},
        "rooms": rooms,
        # Whether the robot takes a cleaning direction per room (component clean_angle).
        "clean_direction": coord.clean_direction_supported,
    })


def _bad_rooms(coord, rooms) -> tuple[str, str] | None:
    """(code, message) when the rooms to write are not well formed, else None."""
    for r in rooms or []:
        if not isinstance(r, dict) or not isinstance(r.get("id"), int):
            return "invalid", "Each room needs its id"
        if "floor_texture" in r:
            if not valid_texture(r["floor_texture"]):
                return "invalid", f"A room's direction (floor_texture) must be -1, 0 or 90, not {r['floor_texture']!r}"
            if not coord.clean_direction_supported:
                return "not_supported", f"{coord.device_name} has no per-room cleaning direction"
    return None


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
    if (bad := _bad_rooms(coord, msg.get("rooms"))) is not None:
        connection.send_error(msg["id"], *bad)
        return
    if coord.map_busy:
        connection.send_error(msg["id"], "busy", f"{coord.device_name} must be docked and idle to edit the map")
        return
    if coord.map_lock.locked():
        connection.send_error(msg["id"], "busy", f"Another map write to {coord.device_name} is still running")
        return
    async with coord.map_lock:     # one map write per robot at a time (each switches maps)
        map_id = msg["map_id"]
        # Tidying a restore writes the carrier's own setup back (and the backup's onto the restored
        # map), which would quietly undo an edit made to either before then.
        if (pend := coord.restore_unfinished()) is not None and map_id in (pend.get("carrier"), pend.get("map_id")):
            connection.send_error(msg["id"], "busy", "This map is part of a restore that is still being tidied up; "
                                  "try again once the robot is docked and the restore has finished")
            return
        # Asked live: the last poll may predate the robot's own schedule starting it.
        if await coord._robot_working():
            connection.send_error(msg["id"], "busy", f"{coord.device_name} is working; edit the map once it is "
                                  "docked and idle")
            return
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
            rooms = None
            if msg.get("areas") or msg.get("rooms"):
                data = await hass.async_add_executor_job(coord.client.get_map_data, map_id)
                existing = {(a.get("type"), a.get("id")): a for a in data.get("area_list", [])}
            if msg.get("rooms"):
                # setAreaInfo replaces every room: all of them go back as just read, with only the
                # names and directions given changed. Built before any write, so a read with no
                # rooms (or without a room to change) refuses the whole save.
                changes = {r["id"]: {k: r[k] for k in ("name", "floor_texture") if k in r} for r in msg["rooms"]}
                rooms = room_areas(data.get("area_list"), changes)
            for t, items in (msg.get("areas") or {}).items():
                if t in _AREA_TYPES:
                    items = [{**{k: old[k] for k in _KEEP if k in old}, **item}
                             if (old := existing.get((t, item.get("id")))) else item
                             for item in items]
                    result[t] = await hass.async_add_executor_job(coord.client.set_areas, map_id, t, items)
            if "furniture" in msg:
                result["furniture"] = await hass.async_add_executor_job(
                    coord.client.set_furniture, map_id, msg["furniture"])
            if rooms:
                result["rooms"] = await hass.async_add_executor_job(coord.client.set_areas, map_id, "room", rooms)
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
