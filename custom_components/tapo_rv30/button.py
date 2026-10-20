"""Buttons for Tapo RV30 — empty bin, reset consumable timers."""
from __future__ import annotations

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .entity import TapoEntity

# resetConsumablesTime keys, as the app sends them (the mop cloth has no reset in the app)
RESETTABLE = {
    "roll_brush": "Main Brush", "edge_brush": "Side Brush", "filter": "Filter",
    "sensor": "Sensor", "charge_contact": "Charge Contacts", "main_brush_lid": "Main Brush Lid",
}


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry,
                            async_add_entities: AddEntitiesCallback) -> None:
    c = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([TapoEmptyBinButton(c, entry, "empty_bin", "Empty Bin")]
                       + [TapoResetButton(c, entry, part, label) for part, label in RESETTABLE.items()])


class TapoEmptyBinButton(TapoEntity, ButtonEntity):
    _attr_icon = "mdi:delete-empty"

    async def async_press(self) -> None:
        await self.hass.async_add_executor_job(self.coordinator.client.empty_bin)
        await self.coordinator.async_request_refresh()


class TapoResetButton(TapoEntity, ButtonEntity):
    _attr_icon = "mdi:restore"
    _attr_entity_category = EntityCategory.CONFIG

    def __init__(self, coordinator, entry, part: str, label: str) -> None:
        super().__init__(coordinator, entry, f"reset_{part}", f"Reset {label}")
        self._part = part

    async def async_press(self) -> None:
        await self.hass.async_add_executor_job(self.coordinator.client.reset_consumable, self._part)
        await self.coordinator.async_request_refresh()
