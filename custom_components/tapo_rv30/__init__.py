"""Tapo RV30 Robot Vacuum integration."""
from __future__ import annotations

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME, Platform
from homeassistant.core import HomeAssistant
from homeassistant.loader import async_get_integration

from .aes import AesVacuumClient
from .const import CONF_TRANSPORT, DEFAULT_PORT, DOMAIN, OPT_SHOW_PANEL, TRANSPORT_AES
from .coordinator import TapoCoordinator
from .frontend import async_remove_panel_if_present, async_setup_frontend, async_setup_panel
from .planner import TapoPlanner
from .planner_ws import async_setup_planner_ws
from .services import async_setup_services, async_unload_services
from .voice import async_setup_voice

VOICE_KEY = f"{DOMAIN}_voice"
from .tpap import TapoVacuumClient

_LOGGER = logging.getLogger(__name__)
PLATFORMS = [Platform.VACUUM, Platform.SENSOR, Platform.BINARY_SENSOR, Platform.CAMERA, Platform.IMAGE,
             Platform.SELECT, Platform.BUTTON, Platform.SWITCH, Platform.TIME, Platform.NUMBER,
             Platform.UPDATE]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    integration = await async_get_integration(hass, DOMAIN)
    await async_setup_frontend(hass, integration.version or "0")
    # Entries created before transport detection have no CONF_TRANSPORT: TPAP.
    client_cls = AesVacuumClient if entry.data.get(CONF_TRANSPORT) == TRANSPORT_AES else TapoVacuumClient
    client = client_cls(
        host=entry.data[CONF_HOST],
        username=entry.data[CONF_USERNAME],
        password=entry.data[CONF_PASSWORD],
        port=DEFAULT_PORT,
        cache_dir=hass.config.path(".storage", "tapo_rv30"),
    )
    coordinator = TapoCoordinator(hass, client, entry)
    await coordinator.async_config_entry_first_refresh()
    coordinator.planner = TapoPlanner(hass, coordinator, entry)
    await coordinator.planner.async_load()

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    async_setup_services(hass)
    async_setup_planner_ws(hass)
    coordinator.planner.async_start()
    entry.async_on_unload(coordinator.planner.async_stop)
    if VOICE_KEY not in hass.data:
        hass.data[VOICE_KEY] = async_setup_voice(hass)
    await _async_apply_panel_option(hass, integration.version or "0")
    entry.async_on_unload(entry.add_update_listener(_async_options_updated))
    return True


def _panel_wanted(hass: HomeAssistant) -> bool:
    """The sidebar panel is shown unless every entry has turned it off."""
    entries = hass.config_entries.async_entries(DOMAIN)
    return any(e.options.get(OPT_SHOW_PANEL, True) for e in entries) if entries else False


async def _async_apply_panel_option(hass: HomeAssistant, version: str) -> None:
    if _panel_wanted(hass):
        await async_setup_panel(hass, version)
    else:
        async_remove_panel_if_present(hass)


async def _async_options_updated(hass: HomeAssistant, entry: ConfigEntry) -> None:
    integration = await async_get_integration(hass, DOMAIN)
    await _async_apply_panel_option(hass, integration.version or "0")


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if ok:
        coordinator = hass.data[DOMAIN].pop(entry.entry_id, None)
        if coordinator is not None and hasattr(coordinator.client, "close"):
            coordinator.client.close()
        if not hass.data[DOMAIN]:
            async_unload_services(hass)
            async_remove_panel_if_present(hass)
            if (unregister := hass.data.pop(VOICE_KEY, None)) is not None:
                unregister()
    return ok
