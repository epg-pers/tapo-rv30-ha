"""Buttons for Tapo RV30: run a preset, empty bin, reset consumable timers."""
from __future__ import annotations

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import ServiceValidationError
from homeassistant.helpers import entity_registry as er
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .entity import TapoEntity, remove_missing_parts

# resetConsumablesTime keys, as the app sends them (the mop cloth has no reset in the app)
RESETTABLE = {
    "roll_brush": "Main Brush", "edge_brush": "Side Brush", "filter": "Filter",
    "sensor": "Sensor", "charge_contact": "Charge Contacts", "main_brush_lid": "Main Brush Lid",
    "rag": "Mop Cloth",
}


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry,
                            async_add_entities: AddEntitiesCallback) -> None:
    c = hass.data[DOMAIN][entry.entry_id]
    entities: list[ButtonEntity] = []
    if c.has("dust_bucket") and "dust" in c.settings:
        entities.append(TapoEmptyBinButton(c, entry, "empty_bin", "Empty Bin"))
    entities += [TapoResetButton(c, entry, part, label) for part, label in RESETTABLE.items()
                 if c.has_part(f"{part}_time")]
    remove_missing_parts(hass, c, entry, "button",
                         [f"reset_{part}" for part in RESETTABLE if not c.has_part(f"{part}_time")])
    entities += [TapoDockActionButton(c, entry, key) for key in c.dock_actions if key in DOCK_LABELS]
    if c.has("matter") and "matter_status" in c.settings:
        entities.append(TapoMatterPairingButton(c, entry, "matter_pairing", "Open Matter Pairing Window"))
    async_add_entities(entities)

    # One button per preset; presets added in the app later appear on the next refresh.
    known: dict[int, int | None] = {}     # preset id -> the map its button was made for

    @callback
    def _sync_presets() -> None:
        reg = er.async_get(hass)
        prefix = f"{entry.entry_id}_preset_"
        if c.presets_read:
            # A preset deleted in the app takes its button with it. The robot reuses preset ids,
            # and an old button (pressed by an automation) must not come back running a different
            # preset. A preset never changes map, so the same id on another map is another preset:
            # its old button goes, and the new one gets its own on the next update.
            maps = {p["id"]: p.get("map_id") for p in c.presets}
            for ent in er.async_entries_for_config_entry(reg, entry.entry_id):
                rid = ent.unique_id[len(prefix):] if ent.unique_id.startswith(prefix) else None
                if rid is None or not rid.isdigit():
                    continue
                rid = int(rid)
                if rid not in maps or (rid in known and known[rid] != maps[rid]):
                    reg.async_remove(ent.entity_id)
                    known.pop(rid, None)
                    maps.pop(rid, None)
            fresh = [p for p in c.presets if p["id"] in maps and p["id"] not in known]
        else:
            fresh = [p for p in c.presets if p["id"] not in known]
        if fresh:
            known.update({p["id"]: p.get("map_id") for p in fresh})
            async_add_entities(TapoPresetButton(c, entry, p["id"], p.get("map_id")) for p in fresh)

    _sync_presets()
    entry.async_on_unload(c.async_add_listener(_sync_presets))


DOCK_LABELS = {"wash_mop": ("Wash Mop", "mdi:washing-machine"), "dry_mop": ("Dry Mop", "mdi:hair-dryer"),
               "remove_hair": ("Remove Hair", "mdi:content-cut")}


class TapoDockActionButton(TapoEntity, ButtonEntity):
    """Omni-dock actions; only created when the robot answers the matching getter."""

    def __init__(self, coordinator, entry, key: str) -> None:
        name, icon = DOCK_LABELS[key]
        super().__init__(coordinator, entry, f"dock_{key}", name)
        self._attr_icon = icon
        self._key = key

    async def async_press(self) -> None:
        await self._call(self.coordinator.client.dock_action, self._key)
        await self.coordinator.async_refresh_soon()


class TapoMatterPairingButton(TapoEntity, ButtonEntity):
    """startCommission: opens the robot's Matter pairing window for a few minutes so
    another ecosystem (Home Assistant's Matter integration, Apple Home, Google Home)
    can add it with the setup code from the Matter sensor."""
    _attr_entity_category = EntityCategory.DIAGNOSTIC
    _attr_icon = "mdi:link-plus"

    async def async_press(self) -> None:
        await self._call(self.coordinator.client.start_matter_commissioning)
        await self.coordinator.async_settings_changed()
        await self.coordinator.async_settings_changed_later(5)


class TapoEmptyBinButton(TapoEntity, ButtonEntity):
    _attr_icon = "mdi:delete-empty"

    async def async_press(self) -> None:
        await self._call(self.coordinator.client.empty_bin)
        await self.coordinator.async_request_refresh()


class TapoResetButton(TapoEntity, ButtonEntity):
    _attr_icon = "mdi:restore"
    _attr_entity_category = EntityCategory.CONFIG

    def __init__(self, coordinator, entry, part: str, label: str) -> None:
        super().__init__(coordinator, entry, f"reset_{part}", f"Reset {label}")
        self._part = part

    async def async_press(self) -> None:
        await self._call(self.coordinator.client.reset_consumable, self._part)
        await self.coordinator.async_request_refresh()


class TapoPresetButton(TapoEntity, ButtonEntity):
    """Starts a Tapo-app preset (clean_mode 5), switching map first if needed."""
    _attr_icon = "mdi:play-box-multiple"

    def __init__(self, coordinator, entry, rule_id: int, map_id: int | None = None) -> None:
        super().__init__(coordinator, entry, f"preset_{rule_id}", None)
        self._rule_id = rule_id
        self._map_id = map_id

    @property
    def _preset(self) -> dict | None:
        # Only the preset this button was made for: an id reused on another map is not it.
        return next((p for p in self.coordinator.presets if p["id"] == self._rule_id
                     and (self._map_id is None or p.get("map_id") == self._map_id)), None)

    @property
    def name(self) -> str:
        p = self._preset
        return f"Preset {p['name']}" if p else f"Preset {self._rule_id}"

    @property
    def available(self) -> bool:
        return super().available and self._preset is not None

    @property
    def extra_state_attributes(self) -> dict:
        p = self._preset or {}
        return {"preset_id": p.get("id"), "preset_name": p.get("name"),
                **{k: p.get(k) for k in ("map_id", "map_name", "rooms", "room_settings", "clean_order")}}

    async def async_press(self) -> None:
        p = self._preset
        if p is None:
            return
        if why := self.coordinator.start_refused():
            raise ServiceValidationError(f"{self.coordinator.device_name} {why}")
        await self._call(self.coordinator.client.run_preset, p["id"], p["map_id"], p.get("clean_order", True))
        await self.coordinator.async_refresh_soon()
