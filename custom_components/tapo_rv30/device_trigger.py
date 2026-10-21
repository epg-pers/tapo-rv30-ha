"""Device triggers: the integration's events as entries in the automation editor
("Clean started", "Clean finished", "Error reported") instead of raw event triggers."""
from __future__ import annotations

import voluptuous as vol

from homeassistant.components.device_automation import DEVICE_TRIGGER_BASE_SCHEMA
from homeassistant.components.homeassistant.triggers import event as event_trigger
from homeassistant.const import CONF_DEVICE_ID, CONF_DOMAIN, CONF_PLATFORM, CONF_TYPE
from homeassistant.core import CALLBACK_TYPE, HomeAssistant
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.trigger import TriggerActionType, TriggerInfo
from homeassistant.helpers.typing import ConfigType

from .const import DOMAIN, EVENT_CLEAN_FINISHED, EVENT_CLEAN_STARTED, EVENT_ERROR

TRIGGER_TYPES = {
    "clean_started": EVENT_CLEAN_STARTED,
    "clean_finished": EVENT_CLEAN_FINISHED,
    "error": EVENT_ERROR,
}

TRIGGER_SCHEMA = DEVICE_TRIGGER_BASE_SCHEMA.extend({vol.Required(CONF_TYPE): vol.In(TRIGGER_TYPES)})


async def async_get_triggers(hass: HomeAssistant, device_id: str) -> list[dict]:
    device = dr.async_get(hass).async_get(device_id)
    if device is None or not any(ident[0] == DOMAIN for ident in device.identifiers):
        return []
    return [{CONF_PLATFORM: "device", CONF_DOMAIN: DOMAIN, CONF_DEVICE_ID: device_id, CONF_TYPE: t}
            for t in TRIGGER_TYPES]


async def async_attach_trigger(hass: HomeAssistant, config: ConfigType, action: TriggerActionType,
                               trigger_info: TriggerInfo) -> CALLBACK_TYPE:
    config = TRIGGER_SCHEMA(config)
    event_config = event_trigger.TRIGGER_SCHEMA({
        event_trigger.CONF_PLATFORM: "event",
        event_trigger.CONF_EVENT_TYPE: TRIGGER_TYPES[config[CONF_TYPE]],
        event_trigger.CONF_EVENT_DATA: {"device_id": config[CONF_DEVICE_ID]},
    })
    return await event_trigger.async_attach_trigger(hass, event_config, action, trigger_info, platform_type="device")
