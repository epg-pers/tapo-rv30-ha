"""Websocket commands for the sidebar page's Backups tab.

tapo_rv30/backups/list   {entity_id}         -> every saved backup, with a thumbnail and the
                                                facts decoded from the .bkmap
tapo_rv30/backups/image  {entity_id, file}   -> the full-size image for one backup

The file scanning and rendering live in backupstore (pure, unit-tested); this is the thin
Home Assistant layer over it.
"""
from __future__ import annotations

import time
from typing import Any

import voluptuous as vol
from homeassistant.components import websocket_api
from homeassistant.core import HomeAssistant
from homeassistant.helpers import entity_registry as er

from . import backupstore
from .const import DOMAIN

_KEY = f"{DOMAIN}_backup_ws"


def _coord(hass: HomeAssistant, entity_id: str):
    entry = er.async_get(hass).async_get(entity_id)
    if entry is None or entry.platform != DOMAIN:
        return None
    return hass.data.get(DOMAIN, {}).get(entry.config_entry_id)


def _folders(hass: HomeAssistant, coord) -> list[str]:
    """This robot's backups, then the shared folder older versions saved every robot's to."""
    from .setup_apply import backup_folders
    return backup_folders(hass, coord)


def async_setup_backup_ws(hass: HomeAssistant) -> None:
    if hass.data.get(_KEY):
        return
    hass.data[_KEY] = True
    websocket_api.async_register_command(hass, ws_backups_list)
    websocket_api.async_register_command(hass, ws_backups_image)


@websocket_api.websocket_command({
    vol.Required("type"): "tapo_rv30/backups/list",
    vol.Required("entity_id"): str,
})
@websocket_api.async_response
async def ws_backups_list(hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict[str, Any]) -> None:
    coord = _coord(hass, msg["entity_id"])
    if coord is None:
        connection.send_error(msg["id"], "not_found", f"No Tapo vacuum for {msg['entity_id']}")
        return
    folders = _folders(hass, coord)
    folder = folders[0]
    names = {m["id"]: m["name"] for m in (coord.maps or [])}

    def build() -> list[dict]:
        out = []
        for e in backupstore.scan_all(folders):
            png, mime = backupstore.image_png(e["dir"], e)
            out.append({
                "file": e["file"], "source": e["source"], "map_id": e["map_id"],
                "map_name": names.get(e["map_id"]) or f"Map {e['map_id']}",
                "size": e["size"],
                "when": time.strftime("%Y-%m-%d %H:%M", time.localtime(e["ts"])),
                "has_image": png is not None,
                "thumb": backupstore.thumb(png, mime) if png else None,
                "facts": backupstore.facts_for(e["dir"], e),
            })
        return out

    entries = await hass.async_add_executor_job(build)
    connection.send_result(msg["id"], {"folder": folder, "backups": entries})


@websocket_api.websocket_command({
    vol.Required("type"): "tapo_rv30/backups/image",
    vol.Required("entity_id"): str,
    vol.Required("file"): str,
})
@websocket_api.async_response
async def ws_backups_image(hass: HomeAssistant, connection: websocket_api.ActiveConnection, msg: dict[str, Any]) -> None:
    coord = _coord(hass, msg["entity_id"])
    if coord is None:
        connection.send_error(msg["id"], "not_found", f"No Tapo vacuum for {msg['entity_id']}")
        return
    folders = _folders(hass, coord)

    def build() -> dict | None:
        # All file access (path checks, the folder scan, decoding) runs in the executor.
        if backupstore.locate(folders, msg["file"]) is None:
            return None
        entry = next((e for e in backupstore.scan_all(folders) if e["file"] == msg["file"]), None)
        if entry is None:
            return None
        png, mime = backupstore.image_png(entry["dir"], entry)
        return {"file": entry["file"], "image": backupstore.data_uri(png, mime) if png else None,
                "facts": backupstore.facts_for(entry["dir"], entry)}

    result = await hass.async_add_executor_job(build)
    if result is None:
        connection.send_error(msg["id"], "not_found", "no such backup")
        return
    connection.send_result(msg["id"], result)
