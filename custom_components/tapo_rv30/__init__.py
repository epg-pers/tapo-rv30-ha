"""Tapo RV30 Robot Vacuum integration."""
from __future__ import annotations

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME, Platform
from homeassistant.core import HomeAssistant

from .aes import AesVacuumClient
from .const import CONF_TRANSPORT, DEFAULT_PORT, DOMAIN, TRANSPORT_AES
from .coordinator import TapoCoordinator
from .services import async_setup_services, async_unload_services
from .tpap import TapoVacuumClient

_LOGGER = logging.getLogger(__name__)
PLATFORMS = [Platform.VACUUM, Platform.SENSOR, Platform.BINARY_SENSOR, Platform.CAMERA, Platform.IMAGE,
             Platform.SELECT, Platform.BUTTON, Platform.SWITCH, Platform.TIME, Platform.NUMBER]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
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

    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    async_setup_services(hass)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if ok:
        coordinator = hass.data[DOMAIN].pop(entry.entry_id, None)
        if coordinator is not None and hasattr(coordinator.client, "close"):
            coordinator.client.close()
        if not hass.data[DOMAIN]:
            async_unload_services(hass)
    return ok
