"""Config flow for Tapo RV30."""
from __future__ import annotations

import logging

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant

from .aes import AesVacuumClient
from .const import CONF_TRANSPORT, DEFAULT_PORT, DOMAIN, TRANSPORT_AES, TRANSPORT_TPAP
from .tpap import AuthError, TapoVacuumClient

_LOGGER = logging.getLogger(__name__)

STEP_SCHEMA = vol.Schema({
    vol.Required(CONF_HOST): str,
    vol.Required(CONF_USERNAME, default=""): str,
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
        _LOGGER.debug("Neither transport worked for %s: TPAP %r, AES %r", host, tpap_exc, exc)
        return None, "cannot_connect"


class TapoRV30ConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user(self, user_input=None):
        errors: dict[str, str] = {}
        if user_input is not None:
            host = user_input[CONF_HOST].strip()
            user = user_input[CONF_USERNAME].strip()
            pw   = user_input[CONF_PASSWORD]

            await self.async_set_unique_id(host)
            self._abort_if_unique_id_configured()

            transport, err = await _test_connection(self.hass, host, user, pw)
            if err:
                errors["base"] = err
            else:
                return self.async_create_entry(
                    title=f"Tapo RV30 ({host})",
                    data={CONF_HOST: host, CONF_USERNAME: user, CONF_PASSWORD: pw,
                          CONF_TRANSPORT: transport},
                )

        return self.async_show_form(
            step_id="user",
            data_schema=STEP_SCHEMA,
            errors=errors,
        )
