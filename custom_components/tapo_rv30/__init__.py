"""Tapo RV30 Robot Vacuum integration."""
from __future__ import annotations

import logging
from functools import partial

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME, Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.storage import Store
from homeassistant.loader import async_get_integration

from .aes import AesVacuumClient
from .backup_ws import async_setup_backup_ws
from .const import (
    CONF_MAC,
    CONF_SECURITY,
    CONF_TRANSPORT,
    DEFAULT_PORT,
    DOMAIN,
    ISSUE_UNREACHABLE,
    OPT_SHOW_PANEL,
    TRANSPORT_AES,
)
from .coordinator import TapoCoordinator
from .frontend import async_remove_panel_if_present, async_setup_frontend, async_setup_panel
from .history_ws import async_setup_history_ws
from .map_edit_ws import async_setup_map_edit_ws
from .map_restore import async_setup_map_restore
from .planner import TapoPlanner
from .planner_ws import async_setup_planner_ws
from .preset_ws import async_setup_preset_ws
from .services import async_setup_services
from .voice import async_setup_voice

VOICE_KEY = f"{DOMAIN}_voice"
from .tpap import TapoVacuumClient, learned_entry_data

_LOGGER = logging.getLogger(__name__)
CONFIG_SCHEMA = cv.config_entry_only_config_schema(DOMAIN)
PLATFORMS = [Platform.VACUUM, Platform.SENSOR, Platform.BINARY_SENSOR, Platform.CAMERA, Platform.IMAGE,
             Platform.SELECT, Platform.BUTTON, Platform.SWITCH, Platform.TIME, Platform.NUMBER,
             Platform.UPDATE]


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    """Services are registered once, for the whole run: automations calling them while a robot
    is still being set up (or retrying) get a clear error instead of "action not found"."""
    async_setup_services(hass)
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    integration = await async_get_integration(hass, DOMAIN)
    await async_setup_frontend(hass, integration.version or "0")
    # Entries created before transport detection have no CONF_TRANSPORT: TPAP.
    client_cls = AesVacuumClient if entry.data.get(CONF_TRANSPORT) == TRANSPORT_AES else TapoVacuumClient
    # The constructor creates the session cache directory: file I/O, so off the event loop.
    client = await hass.async_add_executor_job(partial(
        client_cls,
        host=entry.data[CONF_HOST],
        username=entry.data[CONF_USERNAME],
        password=entry.data[CONF_PASSWORD],
        port=DEFAULT_PORT,
        cache_dir=hass.config.path(".storage", "tapo_rv30"),
    ))
    if client_cls is TapoVacuumClient:
        client.expected_security = entry.data.get(CONF_SECURITY)
        client.expected_mac = entry.data.get(CONF_MAC)
    coordinator = TapoCoordinator(hass, client, entry)
    try:
        await coordinator.async_config_entry_first_refresh()
    except BaseException:
        # Setup is retried with a new client; release this one (the AES client owns a thread).
        await hass.async_add_executor_job(client.close)
        raise
    # Trust on first use: remember what the robot offered, so a later impostor offering less
    # is refused (a reauth or reconfigure stores what the robot offers then).
    # A firmware update that adds security is followed too (never one that removes it): only
    # after a working session, so an answer that merely claims more cannot be stored.
    # The robot's MAC from discovery is remembered the same way (never replaced), so another
    # robot on the same account that takes this address is refused instead of driven.
    if client_cls is TapoVacuumClient:
        data = learned_entry_data(entry.data, getattr(client, "security", None),
                                  getattr(client, "session_mac", None))
        if data is not None:
            hass.config_entries.async_update_entry(entry, data=data)
    forwarded = False
    try:
        coordinator.planner = TapoPlanner(hass, coordinator, entry)
        await coordinator.planner.async_load()
        hass.data.setdefault(DOMAIN, {})[entry.entry_id] = coordinator
        await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
        forwarded = True
        async_setup_planner_ws(hass)
        async_setup_map_edit_ws(hass)
        async_setup_preset_ws(hass)
        async_setup_map_restore(hass)
        async_setup_backup_ws(hass)
        async_setup_history_ws(hass)
        coordinator.planner.async_start()
        entry.async_on_unload(coordinator.planner.async_stop)
    except BaseException:
        # Undo what was set up so a retry or reload starts clean instead of finding the
        # platforms "already set up" and a client nobody closes.
        if forwarded:
            await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
        hass.data.get(DOMAIN, {}).pop(entry.entry_id, None)
        await hass.async_add_executor_job(client.close)
        raise
    # Extras that must never fail the robot's setup. Voice is registered again whenever a
    # robot is added or removed, so its sentences know every robot's name.
    _async_register_voice(hass)
    try:
        await _async_apply_panel_option(hass, integration.version or "0")
    except Exception as exc:
        _LOGGER.warning("Sidebar page not set up: %s", exc)
    entry.async_on_unload(entry.add_update_listener(_async_options_updated))
    return True


def _panel_wanted(hass: HomeAssistant) -> bool:
    """The sidebar panel is shown unless every entry has turned it off."""
    # Ignored (discovered and dismissed) and disabled entries have no robot to show.
    entries = hass.config_entries.async_entries(DOMAIN, include_ignore=False, include_disabled=False)
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
    # Stop the planner first, so it cannot start a clean while the entities go away.
    planner = getattr((hass.data.get(DOMAIN) or {}).get(entry.entry_id), "planner", None)
    if planner is not None:
        planner.async_stop()
    ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if ok:
        # The "stopped answering" repair belongs to this entry; it must not outlive it.
        ir.async_delete_issue(hass, DOMAIN, f"{ISSUE_UNREACHABLE}_{entry.entry_id}")
        coordinator = hass.data.get(DOMAIN, {}).pop(entry.entry_id, None)
        if coordinator is not None:
            if planner is not None:
                await planner.async_flush()
            await hass.async_add_executor_job(coordinator.client.close)
        if not hass.data.get(DOMAIN):
            async_remove_panel_if_present(hass)
        _async_register_voice(hass)
    elif planner is not None:
        planner.async_start()       # still loaded: keep planning
    return ok


def _async_register_voice(hass: HomeAssistant) -> None:
    if (unregister := hass.data.pop(VOICE_KEY, None)) is not None:
        unregister()
    if not hass.data.get(DOMAIN):
        return
    try:
        hass.data[VOICE_KEY] = async_setup_voice(hass)
    except Exception as exc:
        _LOGGER.warning("Voice sentences not registered: %s", exc)


async def async_remove_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """The integration entry was deleted: drop its stored planner, room history, pending
    restore and session cache. Map setups and backups are kept (they are the user's)."""
    ir.async_delete_issue(hass, DOMAIN, f"{ISSUE_UNREACHABLE}_{entry.entry_id}")
    for key in ("planner", "rooms", "restore"):
        await Store(hass, 1, f"{DOMAIN}.{entry.entry_id}.{key}").async_remove()
    cache_dir = hass.config.path(".storage", "tapo_rv30")

    def _rm() -> None:     # _cache_path touches the disk, so it runs here too
        try:
            TapoVacuumClient._cache_path(entry.data.get(CONF_HOST, ""), cache_dir).unlink()
        except Exception:   # nothing to clean up is fine
            pass
    await hass.async_add_executor_job(_rm)
