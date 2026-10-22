"""Websocket commands the sidebar page uses to read, change and follow the planner.

tapo_rv30/planner/get        {entity_id}                      -> the planner's view
tapo_rv30/planner/subscribe  {entity_id}                      -> the view now and on every change
tapo_rv30/planner/set        {entity_id, config}              -> save settings (partial)
tapo_rv30/planner/action     {entity_id, action, room?, on?}  -> clean_now, skip_today, skip_room, match_areas
"""
from __future__ import annotations

from typing import Any

import voluptuous as vol
from homeassistant.components import websocket_api
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import entity_registry as er

from .const import DOMAIN
from .planlogic import PlannerError

_KEY = f"{DOMAIN}_planner_ws"


def _planner(hass: HomeAssistant, entity_id: str):
    entry = er.async_get(hass).async_get(entity_id)
    if entry is None or entry.platform != DOMAIN:
        return None
    coord = hass.data.get(DOMAIN, {}).get(entry.config_entry_id)
    return getattr(coord, "planner", None)


@callback
def async_setup_planner_ws(hass: HomeAssistant) -> None:
    if hass.data.get(_KEY):
        return
    hass.data[_KEY] = True
    for handler in (ws_get, ws_subscribe, ws_set, ws_action):
        websocket_api.async_register_command(hass, handler)


@websocket_api.websocket_command({vol.Required("type"): "tapo_rv30/planner/get", vol.Required("entity_id"): str})
@callback
def ws_get(hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict[str, Any]) -> None:
    planner = _planner(hass, msg["entity_id"])
    if planner is None:
        connection.send_error(msg["id"], "not_found", f"No Tapo planner for {msg['entity_id']}")
        return
    connection.send_result(msg["id"], planner.view)


@websocket_api.websocket_command({vol.Required("type"): "tapo_rv30/planner/subscribe", vol.Required("entity_id"): str})
@callback
def ws_subscribe(hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict[str, Any]) -> None:
    planner = _planner(hass, msg["entity_id"])
    if planner is None:
        connection.send_error(msg["id"], "not_found", f"No Tapo planner for {msg['entity_id']}")
        return

    @callback
    def forward() -> None:
        connection.send_message(websocket_api.event_message(msg["id"], planner.view))

    connection.subscriptions[msg["id"]] = planner.add_listener(forward)
    connection.send_result(msg["id"])
    forward()


@websocket_api.websocket_command({vol.Required("type"): "tapo_rv30/planner/set", vol.Required("entity_id"): str,
                                  vol.Required("config"): dict})
@websocket_api.async_response
async def ws_set(hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict[str, Any]) -> None:
    planner = _planner(hass, msg["entity_id"])
    if planner is None:
        connection.send_error(msg["id"], "not_found", f"No Tapo planner for {msg['entity_id']}")
        return
    try:
        await planner.async_set_config(msg["config"])
    except (PlannerError, ValueError, TypeError) as exc:
        connection.send_error(msg["id"], "invalid", str(exc))
        return
    connection.send_result(msg["id"], planner.view)


@websocket_api.websocket_command({
    vol.Required("type"): "tapo_rv30/planner/action", vol.Required("entity_id"): str,
    vol.Required("action"): vol.In(["clean_now", "skip_today", "skip_room", "match_areas"]),
    vol.Optional("room"): str, vol.Optional("on", default=True): bool,
})
@websocket_api.async_response
async def ws_action(hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict[str, Any]) -> None:
    planner = _planner(hass, msg["entity_id"])
    if planner is None:
        connection.send_error(msg["id"], "not_found", f"No Tapo planner for {msg['entity_id']}")
        return
    try:
        result: Any = None
        if msg["action"] == "clean_now":
            await planner.async_clean_now()
        elif msg["action"] == "skip_today":
            await planner.async_skip_today(msg["on"])
        elif msg["action"] == "skip_room":
            await planner.async_skip_room_today(msg.get("room", ""), msg["on"])
        else:
            result = await planner.async_match_areas()
    except PlannerError as exc:
        connection.send_error(msg["id"], "refused", str(exc))
        return
    connection.send_result(msg["id"], {"result": result, "view": planner.view})
