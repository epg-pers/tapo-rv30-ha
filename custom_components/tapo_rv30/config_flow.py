"""Config flow for Tapo RV30: initial setup, reconfigure (new IP / credentials)
and reauth (the robot started rejecting the stored credentials)."""
from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant

from .aes import AesVacuumClient
from .const import CONF_TRANSPORT, DEFAULT_PORT, DOMAIN, TRANSPORT_AES, TRANSPORT_TPAP
from .tpap import AuthError, TapoVacuumClient

_LOGGER = logging.getLogger(__name__)


def _schema(defaults: Mapping[str, Any] | None = None) -> vol.Schema:
    d = defaults or {}
    return vol.Schema({
        vol.Required(CONF_HOST, default=d.get(CONF_HOST, "")): str,
        vol.Required(CONF_USERNAME, default=d.get(CONF_USERNAME, "")): str,
        vol.Required(CONF_PASSWORD, default=""): str,
    })


async def _test_connection(
    hass: HomeAssistant, host: str, user: str, pw: str
) -> tuple[str | None, str | None]:
    """Try TPAP, then AES. Returns (transport, error_key); error_key is None on success.

    A confirmed wrong password on TPAP is final: the same credentials would
    fail on AES too, so it is not tried.
    """
    def _try_tpap():
        TapoVacuumClient(host, user, pw, DEFAULT_PORT).authenticate()

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
    except Exception as exc:
        _LOGGER.info("Could not connect to %s: TPAP: %r; AES: %r", host, tpap_exc, exc)
        return None, "cannot_connect"


class TapoRV30ConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

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
            await self.async_set_unique_id(user_input[CONF_HOST].strip())
            self._abort_if_unique_id_configured()
            data, errors = await self._validate(user_input)
            if data:
                return self.async_create_entry(title=f"Tapo RV30 ({data[CONF_HOST]})", data=data)
        return self.async_show_form(step_id="user", data_schema=_schema(user_input), errors=errors)

    async def async_step_reconfigure(self, user_input: dict[str, Any] | None = None):
        """Change IP address or credentials of an existing entry."""
        entry = self._get_reconfigure_entry()
        errors: dict[str, str] = {}
        if user_input is not None:
            data, errors = await self._validate(user_input)
            if data:
                return self.async_update_reload_and_abort(
                    entry, data=data, title=f"Tapo RV30 ({data[CONF_HOST]})", unique_id=data[CONF_HOST])
        return self.async_show_form(
            step_id="reconfigure", data_schema=_schema(user_input or entry.data), errors=errors)

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
