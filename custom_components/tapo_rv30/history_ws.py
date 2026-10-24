"""Websocket commands for the sidebar page's History tab (clean map history).

tapo_rv30/history/list    {entity_id}           -> kept runs and the runs still on the robot,
                                                   the retention settings and the space used
tapo_rv30/history/image   {entity_id, started}  -> one run's map (a PNG data URI)
tapo_rv30/history/delete  {entity_id, started}  -> forget one kept run (admin)

Retention is changed through the Clean Map History select and limit number, so automations
and the Settings tab can set it too. Storage lives in cleanhistory (pure, unit-tested); the
coordinator decides when runs are kept; this is the thin Home Assistant layer.
"""
from __future__ import annotations

import base64
from typing import Any

import voluptuous as vol
from homeassistant.components import websocket_api
from homeassistant.core import HomeAssistant

from .backup_ws import _coord
from .cleanhistory import HistoryError
from .const import DOMAIN

_KEY = f"{DOMAIN}_history_ws"


def async_setup_history_ws(hass: HomeAssistant) -> None:
    if hass.data.get(_KEY):
        return
    hass.data[_KEY] = True
    websocket_api.async_register_command(hass, ws_history_list)
    websocket_api.async_register_command(hass, ws_history_image)
    websocket_api.async_register_command(hass, ws_history_delete)


def _robot(hass: HomeAssistant, connection, msg: dict):
    coord = _coord(hass, msg["entity_id"])
    if coord is None:
        connection.send_error(msg["id"], "not_found", f"No Tapo vacuum for {msg['entity_id']}")
    return coord


@websocket_api.websocket_command({
    vol.Required("type"): "tapo_rv30/history/list",
    vol.Required("entity_id"): str,
})
@websocket_api.async_response
async def ws_history_list(hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict[str, Any]) -> None:
    if (coord := _robot(hass, connection, msg)) is None:
        return
    connection.send_result(msg["id"], await coord.async_history_list())


@websocket_api.websocket_command({
    vol.Required("type"): "tapo_rv30/history/image",
    vol.Required("entity_id"): str,
    vol.Required("started"): vol.All(vol.Coerce(int), vol.Range(min=1)),
})
@websocket_api.async_response
async def ws_history_image(hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict[str, Any]) -> None:
    if (coord := _robot(hass, connection, msg)) is None:
        return
    try:
        png = await coord.async_history_image(msg["started"])
    except HistoryError as exc:
        connection.send_error(msg["id"], "unavailable", str(exc))
        return
    except Exception as exc:    # a robot read or a damaged record: say so, do not crash the page
        connection.send_error(msg["id"], "failed", f"could not draw that clean: {exc}")
        return
    connection.send_result(msg["id"], {"started": msg["started"],
                                       "image": "data:image/png;base64," + base64.b64encode(png).decode()})


@websocket_api.websocket_command({
    vol.Required("type"): "tapo_rv30/history/delete",
    vol.Required("entity_id"): str,
    vol.Required("started"): vol.All(vol.Coerce(int), vol.Range(min=1)),
})
@websocket_api.require_admin
@websocket_api.async_response
async def ws_history_delete(hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict[str, Any]) -> None:
    if (coord := _robot(hass, connection, msg)) is None:
        return
    if not await coord.async_history_delete(msg["started"]):
        connection.send_error(msg["id"], "not_found", "that clean is not kept")
        return
    connection.send_result(msg["id"], {"deleted": msg["started"]})
