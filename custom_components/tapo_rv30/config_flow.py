"""Config flow for Tapo RV30: initial setup, reconfigure (new IP / credentials)
and reauth (the robot started rejecting the stored credentials)."""
from __future__ import annotations

import asyncio
import logging
import tempfile
from collections.abc import Mapping
from typing import Any

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.service_info.dhcp import DhcpServiceInfo

from .aes import AesVacuumClient
from .const import CONF_TRANSPORT, DEFAULT_PORT, DOMAIN, OPT_SHOW_PANEL, TRANSPORT_AES, TRANSPORT_TPAP
from .tpap import AuthError, NotVacuum, TapoVacuumClient

_LOGGER = logging.getLogger(__name__)


def _schema(defaults: Mapping[str, Any] | None = None, password_optional: bool = False) -> vol.Schema:
    d = defaults or {}
    pw = vol.Optional(CONF_PASSWORD, default="") if password_optional else vol.Required(CONF_PASSWORD, default="")
    return vol.Schema({
        vol.Required(CONF_HOST, default=d.get(CONF_HOST, "")): str,
        vol.Required(CONF_USERNAME, default=d.get(CONF_USERNAME, "")): str,
        pw: str,
    })


async def _test_connection(
    hass: HomeAssistant, host: str, user: str, pw: str
) -> tuple[str | None, str | None]:
    """Try TPAP, then AES. Returns (transport, error_key); error_key is None on success.

    A confirmed wrong password on TPAP is final: the same credentials would
    fail on AES too, so it is not tried.
    """
    def _try_tpap():
        # A throwaway session folder: the entry's client makes its own session, and this test
        # one must not leave a live session key behind.
        with tempfile.TemporaryDirectory() as tmp:
            c = TapoVacuumClient(host, user, pw, DEFAULT_PORT, cache_dir=tmp)
            try:
                c.authenticate()
            finally:
                c.close()

    def _try_aes():
        c = AesVacuumClient(host, user, pw, DEFAULT_PORT)
        try:
            c.authenticate()
        finally:
            c.close()

    try:
        await hass.async_add_executor_job(_try_tpap)
        return TRANSPORT_TPAP, None
    except AuthError:
        return None, "invalid_auth"
    except Exception as exc:
        tpap_exc = exc

    try:
        await hass.async_add_executor_job(_try_aes)
        return TRANSPORT_AES, None
    except AuthError:
        return None, "invalid_auth"
    except NotVacuum as exc:
        _LOGGER.info("%s", exc)
        return None, "not_vacuum"
    except Exception as exc:
        _LOGGER.info("Could not connect to %s: TPAP: %r; AES: %r", host, tpap_exc, exc)
        return None, "cannot_connect"


async def _tpap_port_open(host: str, port: int = 4433, timeout: float = 3.0) -> bool:
    """Cheap check that the address is a TPAP robot before offering it: only the robots
    listen on 4433; plugs, bulbs and cameras on the same MAC prefix do not."""
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except (TimeoutError, OSError):
        return False
    writer.close()
    return True


class TapoRV30ConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: config_entries.ConfigEntry) -> config_entries.OptionsFlow:
        return TapoOptionsFlow()

    async def _validate(self, user_input: dict[str, Any]) -> tuple[dict[str, Any] | None, dict[str, str]]:
        """Return (entry data, errors)."""
        host = user_input[CONF_HOST].strip()
        user = user_input[CONF_USERNAME].strip()
        pw = user_input[CONF_PASSWORD]
        transport, err = await _test_connection(self.hass, host, user, pw)
        if err:
            return None, {"base": err}
        return {CONF_HOST: host, CONF_USERNAME: user, CONF_PASSWORD: pw, CONF_TRANSPORT: transport}, {}

    async def async_step_user(self, user_input: dict[str, Any] | None = None):
        errors: dict[str, str] = {}
        if user_input is not None:
            # A discovery flow for the same address may be open: adding by hand still works.
            await self.async_set_unique_id(user_input[CONF_HOST].strip(), raise_on_progress=False)
            self._abort_if_unique_id_configured()
            data, errors = await self._validate(user_input)
            if data:
                return self.async_create_entry(title=f"Tapo Vacuum ({data[CONF_HOST]})", data=data)
        return self.async_show_form(step_id="user", data_schema=_schema(user_input), errors=errors)

    # ---- DHCP discovery: Home Assistant hands us every lease whose MAC prefix matches the
    # manifest (E0:D3:62 so far) and every lease of a robot already set up. A new address
    # for a known robot updates its entry; a new robot is confirmed only if it answers on
    # the TPAP port, so other TP-Link gear on the same prefix is ignored.
    async def async_step_dhcp(self, discovery_info: DhcpServiceInfo):
        ip, mac = discovery_info.ip, dr.format_mac(discovery_info.macaddress)
        # The MAC decides which robot this is; the address alone can belong to another robot
        # that had it before (two robots swapping leases).
        dev_reg = dr.async_get(self.hass)
        device = dev_reg.async_get_device(connections={(dr.CONNECTION_NETWORK_MAC, mac)})
        # Only our own entries count: the same MAC can be a device of another integration.
        ours = [e for e in (self.hass.config_entries.async_get_entry(i) for i in (device.config_entries if device else ()))
                if e is not None and e.domain == DOMAIN]
        if ours:
            for entry in ours:
                if entry.data.get(CONF_HOST) != ip:
                    for other in self._async_current_entries(include_ignore=False):
                        if other.entry_id != entry.entry_id and other.unique_id == ip:
                            # Its robot has moved too; its own lease update will set this.
                            self.hass.config_entries.async_update_entry(
                                other, unique_id=f"moved-{other.entry_id}")
                    old_host = entry.data.get(CONF_HOST, "")
                    self.hass.config_entries.async_update_entry(
                        entry, data={**entry.data, CONF_HOST: ip}, unique_id=ip,
                        title=f"Tapo Vacuum ({ip})")
                    self.hass.config_entries.async_schedule_reload(entry.entry_id)
                    # The session saved for the old address is never used again: do not keep its key.
                    cache = self.hass.config.path(".storage", DOMAIN)
                    self.hass.async_add_executor_job(
                        lambda h=old_host: TapoVacuumClient._cache_path(h, cache).unlink(missing_ok=True))
            return self.async_abort(reason="already_configured")
        for entry in self._async_current_entries(include_ignore=False):
            if entry.data.get(CONF_HOST) == ip:
                return self.async_abort(reason="already_configured")
        if not await _tpap_port_open(ip):
            return self.async_abort(reason="not_tapo_vacuum")
        await self.async_set_unique_id(ip)
        self._abort_if_unique_id_configured()
        self._discovered_host = ip
        self.context["title_placeholders"] = {"name": f"Tapo robot vacuum ({ip})", "host": ip}
        return await self.async_step_discovery_confirm()

    async def async_step_discovery_confirm(self, user_input: dict[str, Any] | None = None):
        errors: dict[str, str] = {}
        host = getattr(self, "_discovered_host", "")
        if user_input is not None:
            data, errors = await self._validate({**user_input, CONF_HOST: host})
            if data:
                return self.async_create_entry(title=f"Tapo Vacuum ({host})", data=data)
        return self.async_show_form(
            step_id="discovery_confirm",
            data_schema=vol.Schema({vol.Required(CONF_USERNAME, default=(user_input or {}).get(CONF_USERNAME, "")): str,
                                    vol.Required(CONF_PASSWORD): str}),
            description_placeholders={"host": host}, errors=errors)

    async def async_step_reconfigure(self, user_input: dict[str, Any] | None = None):
        """Change IP address or credentials of an existing entry."""
        entry = self._get_reconfigure_entry()
        errors: dict[str, str] = {}
        if user_input is not None:
            # A blank password keeps the stored one (the form never shows it).
            if not user_input.get(CONF_PASSWORD):
                user_input = {**user_input, CONF_PASSWORD: entry.data.get(CONF_PASSWORD, "")}
            data, errors = await self._validate(user_input)
            if data:
                await self.async_set_unique_id(data[CONF_HOST], raise_on_progress=False)
                if any(e.unique_id == data[CONF_HOST] and e.entry_id != entry.entry_id
                       for e in self._async_current_entries(include_ignore=False)):
                    return self.async_abort(reason="already_configured")
                return self.async_update_reload_and_abort(
                    entry, data=data, title=f"Tapo Vacuum ({data[CONF_HOST]})", unique_id=data[CONF_HOST])
        return self.async_show_form(
            step_id="reconfigure", data_schema=_schema(user_input or entry.data, password_optional=True),
            errors=errors)

    async def async_step_reauth(self, entry_data: Mapping[str, Any]):
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(self, user_input: dict[str, Any] | None = None):
        """The vacuum rejected the stored credentials; ask for new ones."""
        entry = self._get_reauth_entry()
        errors: dict[str, str] = {}
        if user_input is not None:
            data, errors = await self._validate({**entry.data, **user_input})
            if data:
                return self.async_update_reload_and_abort(entry, data=data)
        schema = vol.Schema({
            vol.Required(CONF_USERNAME, default=entry.data.get(CONF_USERNAME, "")): str,
            vol.Required(CONF_PASSWORD): str,
        })
        return self.async_show_form(
            step_id="reauth_confirm", data_schema=schema, errors=errors,
            description_placeholders={"host": entry.data.get(CONF_HOST, "")})


class TapoOptionsFlow(config_entries.OptionsFlow):
    """Integration options: the sidebar panel on or off."""

    async def async_step_init(self, user_input: dict[str, Any] | None = None):
        if user_input is not None:
            # Keep the other stored options (the poll interval set from the device page).
            return self.async_create_entry(title="", data={**self.config_entry.options, **user_input})
        current = self.config_entry.options.get(OPT_SHOW_PANEL, True)
        return self.async_show_form(
            step_id="init",
            data_schema=vol.Schema({vol.Required(OPT_SHOW_PANEL, default=current): bool}),
        )
