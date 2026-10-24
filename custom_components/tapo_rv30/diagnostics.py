"""Diagnostics for Tapo RV30 (Settings > Devices > ... > Download diagnostics)."""
from __future__ import annotations

from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant

from .const import DOMAIN
from .mapdata import b64name

TO_REDACT = {CONF_USERNAME, CONF_PASSWORD, "host", "ip", "mac", "device_id", "oem_id",
             "hw_id", "fw_id", "cd", "ssid", "nickname", "lang", "longitude", "latitude",
             "region", "time_diff", "setup_code", "setup_payload", "qr_code", "manual_code",
             "bind_code", "account_id", "username", "password", "email", "token"}


async def async_get_config_entry_diagnostics(hass: HomeAssistant, entry: ConfigEntry) -> dict[str, Any]:
    coord = hass.data.get(DOMAIN, {}).get(entry.entry_id)
    out: dict[str, Any] = {"entry": async_redact_data(dict(entry.data), TO_REDACT)}
    if coord is None:
        out["error"] = "coordinator not loaded"
        return out

    def _device_info() -> dict:
        try:
            return coord.client.send("get_device_info").get("result") or {}
        except Exception as exc:
            return {"error": str(exc)}

    info = await hass.async_add_executor_job(_device_info)
    out["device"] = async_redact_data(
        {k: v for k, v in info.items() if k in ("model", "fw_ver", "hw_ver", "type", "device_on", "rssi", "signal_level")}
        | {"client": type(coord.client).__name__}, TO_REDACT)
    # The raw status and settings carry the device info (MAC, IP, Wi-Fi, location) and the
    # Matter setup code, so they are redacted like everything else.
    out["status"] = async_redact_data(coord.data, TO_REDACT) if coord.data else None
    out["settings"] = async_redact_data(coord.settings, TO_REDACT)
    out["map"] = {
        "map_id": coord.map_id,
        "map_name": coord.map_name,
        "poll_interval": coord.poll_interval,
        "rooms": [{"id": r.get("id"), "name": b64name(r.get("name", ""))} for r in coord.rooms],
        "position_mm": coord.vac_pos,
        "current_room": coord.current_room,
        "image_bytes": len(coord.map_image_bytes) if coord.map_image_bytes else 0,
    }
    out["schedules"] = coord.schedules
    out["components"] = coord.components
    out["dock_actions"] = coord.dock_actions
    out["bool_settings"] = coord.bool_settings
    out["presets"] = coord.presets
    return out
