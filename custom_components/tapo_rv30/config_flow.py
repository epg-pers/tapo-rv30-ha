"""Config flow for Tapo RV30."""
from __future__ import annotations

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant

from .const import DEFAULT_PORT, DOMAIN
from .tpap import AuthError, TapoVacuumClient

STEP_SCHEMA = vol.Schema({
    vol.Required(CONF_HOST): str,
    vol.Required(CONF_USERNAME, default=""): str,
    vol.Required(CONF_PASSWORD, default=""): str,
})


async def _test_connection(hass: HomeAssistant, host: str, user: str, pw: str) -> str | None:
    """Return None on success, error key string on failure."""
    def _try():
        c = TapoVacuumClient(host, user, pw, DEFAULT_PORT)
        c.authenticate()
    try:
        await hass.async_add_executor_job(_try)
        return None
    except AuthError:
        return "invalid_auth"
    except Exception:
        return "cannot_connect"


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

            err = await _test_connection(self.hass, host, user, pw)
            if err:
                errors["base"] = err
            else:
                return self.async_create_entry(
                    title=f"Tapo RV30 ({host})",
                    data={CONF_HOST: host, CONF_USERNAME: user, CONF_PASSWORD: pw},
                )

        return self.async_show_form(
            step_id="user",
            data_schema=STEP_SCHEMA,
            errors=errors,
        )
