"""DataUpdateCoordinator for Tapo RV30."""
from __future__ import annotations

import asyncio
import logging
from datetime import timedelta
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from PIL import Image, ImageDraw

from .const import (
    CLEANING_CODES, CONF_POLL_INTERVAL, DOMAIN, FAST_INTERVAL, MAP_INTERVAL, MAX_POLL_INTERVAL,
    MIN_POLL_INTERVAL, PAUSED_CODES,
)
from .mapdata import b64name, decode_preset, decode_schedule, fold, resolve_rooms, room_at_vac
from .maprender import _dot, _grid_px, _jpeg, render_map
from .tpap import AuthError, TapoVacuumClient

_LOGGER = logging.getLogger(__name__)

STATUS_RETRIES = 3          # attempts per poll before the entities go unavailable
STATUS_RETRY_DELAY = 1.5    # seconds, doubled each retry


# ---------------------------------------------------------------------------
# Coordinator
# ---------------------------------------------------------------------------
class TapoCoordinator(DataUpdateCoordinator):
    """Polls the vacuum for status, keeps the map image and settings current."""

    def __init__(self, hass: HomeAssistant, client: TapoVacuumClient, entry: ConfigEntry | None = None) -> None:
        interval = FAST_INTERVAL
        if entry is not None:
            interval = int(entry.options.get(CONF_POLL_INTERVAL, FAST_INTERVAL))
        interval = max(MIN_POLL_INTERVAL, min(MAX_POLL_INTERVAL, interval))
        super().__init__(hass, _LOGGER, name=DOMAIN, update_interval=timedelta(seconds=interval))
        self.client = client
        self.entry = entry
        self.poll_interval = interval
        self._map_tick = 0
        self.map_image_bytes: bytes | None = None
        self._map_base: Image.Image | None = None     # rendered map without the vacuum marker
        self.room_geometry: list[dict] = []
        self.map_geometry: dict = {}
        self.rooms: list[dict] = []        # current map's rooms (area_list, type == room)
        self.map_id: int | None = None
        self.map_name: str | None = None
        self.device_name: str = "Tapo RV30"
        self.device_model: str = "RV30"
        self.fw_version: str | None = None
        self._info_fetched = False
        self.settings: dict = {}           # get_settings(), refreshed with the map
        self.schedules: list[dict] = []
        self.components: dict[str, int] = {}       # getComponentList, read once
        self.bool_settings_supported: list[str] = []   # probed once
        self.bool_settings: dict[str, bool] = {}
        self.presets: list[dict] = []
        self._caps_fetched = False
        self.vac_pos: list | None = None
        self.current_room: str | None = None

    # ---- shared entity metadata ------------------------------------------------
    @property
    def device_info(self) -> DeviceInfo:
        ident = self.entry.entry_id if self.entry else self.client.host
        return DeviceInfo(
            identifiers={(DOMAIN, ident)},
            name=self.device_name,
            manufacturer="TP-Link",
            model=f"Tapo {self.device_model}",
            sw_version=self.fw_version,
        )

    def has(self, component: str) -> bool:
        """True if the robot lists this component (or the list was unavailable)."""
        return component in self.components if self.components else True

    @property
    def status_code(self) -> int | None:
        return (self.data or {}).get("status_code")

    @property
    def busy(self) -> str | None:
        """'cleaning' / 'paused' when a new clean would be refused, else None."""
        code = self.status_code
        if code in CLEANING_CODES:
            return "cleaning"
        if code in PAUSED_CODES:
            return "paused"
        return None

    @property
    def _map_cycles(self) -> int:
        return max(1, MAP_INTERVAL // self.poll_interval)

    async def async_set_poll_interval(self, seconds: int) -> None:
        seconds = max(MIN_POLL_INTERVAL, min(MAX_POLL_INTERVAL, int(seconds)))
        self.poll_interval = seconds
        self.update_interval = timedelta(seconds=seconds)
        if self.entry is not None:
            self.hass.config_entries.async_update_entry(
                self.entry, options={**self.entry.options, CONF_POLL_INTERVAL: seconds})
        self.async_update_listeners()

    # ---- polling -----------------------------------------------------------------
    async def _async_update_data(self) -> dict[str, Any]:
        if not self._info_fetched:
            try:
                info = await self.hass.async_add_executor_job(self.client.get_device_info)
                self.device_name = info["name"]
                self.device_model = info["model"]
                self.fw_version = info.get("fw_ver")
                self._info_fetched = True
            except AuthError as exc:
                raise ConfigEntryAuthFailed(str(exc)) from exc
            except Exception as exc:
                _LOGGER.debug("Device info fetch failed: %s", exc)

        if not self._caps_fetched:
            await self._fetch_capabilities()

        data = await self._fetch_status()

        # Full map render + settings on first load and every MAP_INTERVAL; in
        # between, re-read the map data so position and current room track.
        self._map_tick += 1
        if self._map_base is None or self._map_tick >= self._map_cycles:
            self._map_tick = 0
            try:
                await self.hass.async_add_executor_job(self._refresh_map)
            except Exception as exc:
                # The robot refuses map data while manoeuvring (-3016); with a
                # map already rendered that is routine, so keep it out of the log.
                if self._map_base is None:
                    _LOGGER.warning("Map refresh failed: %s", exc)
                else:
                    _LOGGER.debug("Map refresh skipped: %s", exc)
                    self._map_tick = self._map_cycles - 1   # try again next poll
            await self._refresh_settings()
        elif self.map_id is not None:
            try:
                await self.hass.async_add_executor_job(self._refresh_position)
            except Exception as exc:
                _LOGGER.debug("Position refresh failed: %s", exc)

        data["settings"] = self.settings
        data["schedules"] = self.schedules
        data["bool_settings"] = self.bool_settings
        data["presets"] = self.presets
        data["current_room"] = self.current_room
        data["position_mm"] = self.vac_pos
        data["charging"] = data.get("status_code") == 5
        return data

    async def _fetch_capabilities(self) -> None:
        """Component list and which optional settings answer: read once."""
        try:
            self.components = await self.hass.async_add_executor_job(self.client.get_components)
        except AuthError as exc:
            raise ConfigEntryAuthFailed(str(exc)) from exc
        except Exception as exc:
            _LOGGER.debug("getComponentList failed: %s", exc)
        try:
            probed = await self.hass.async_add_executor_job(self.client.probe_bool_settings)
            self.bool_settings_supported = list(probed)
            self.bool_settings = probed
        except Exception as exc:
            _LOGGER.debug("Settings probe failed: %s", exc)
        self._caps_fetched = True

    async def _refresh_settings(self) -> None:
        self.settings = await self.hass.async_add_executor_job(self.client.get_settings)
        self._decode_schedules()
        if self.bool_settings_supported:
            self.bool_settings = await self.hass.async_add_executor_job(
                self.client.get_bool_settings, self.bool_settings_supported)
        try:
            self.presets = await self.hass.async_add_executor_job(self._read_presets)
        except Exception as exc:
            _LOGGER.debug("Preset read failed: %s", exc)

    def _read_presets(self) -> list[dict]:
        rules = self.client.get_presets()
        if not rules:
            return []
        names = self.map_names()
        out = []
        for rule in rules:
            map_id = rule.get("map_id")
            try:
                detail = self.client.get_preset_detail(map_id, rule["rule_id"])
            except Exception as exc:
                _LOGGER.debug("Preset %s detail failed: %s", rule.get("rule_id"), exc)
                detail = None
            room_names = ({r["id"]: b64name(r.get("name", "")) for r in self.rooms}
                          if map_id == self.map_id else self._room_names_for(map_id))
            out.append(decode_preset(rule, detail, room_names, names.get(map_id)))
        return out

    _room_name_cache: dict[int, dict[int, str]] = {}

    def _room_names_for(self, map_id: int) -> dict[int, str]:
        if map_id not in self._room_name_cache:
            try:
                md = self.client.get_map_data(map_id)
                self._room_name_cache[map_id] = {a["id"]: b64name(a.get("name", ""))
                                                 for a in md.get("area_list", []) if a.get("type") == "room"}
            except Exception:
                return {}
        return self._room_name_cache[map_id]

    def find_preset(self, ref) -> dict | None:
        """Preset by id, or by name (accent-insensitive, exact then partial)."""
        try:
            rid = int(ref)
            for p in self.presets:
                if p["id"] == rid:
                    return p
        except (TypeError, ValueError):
            pass
        wanted = fold(str(ref).strip())
        exact = [p for p in self.presets if fold(p["name"]) == wanted]
        partial = [p for p in self.presets if wanted and wanted in fold(p["name"])]
        hits = exact or partial
        return hits[0] if len(hits) == 1 else None

    async def _fetch_status(self) -> dict[str, Any]:
        """get_status with a short retry so one dropped packet doesn't flip
        every entity to unavailable."""
        delay = STATUS_RETRY_DELAY
        for attempt in range(1, STATUS_RETRIES + 1):
            try:
                return await self.hass.async_add_executor_job(self.client.get_status)
            except AuthError as exc:
                raise ConfigEntryAuthFailed(str(exc)) from exc
            except Exception as exc:
                if attempt == STATUS_RETRIES:
                    raise UpdateFailed(f"Failed to fetch vacuum status: {exc}") from exc
                _LOGGER.debug("Status fetch failed (attempt %d/%d): %s", attempt, STATUS_RETRIES, exc)
                await asyncio.sleep(delay)
                delay *= 2
        raise UpdateFailed("unreachable")   # pragma: no cover

    async def async_refresh_soon(self) -> None:
        """Re-poll at 2, 5 and 10 s after a command.

        The robot takes a few seconds to report its new status and the normal poll
        is 30 s, so without this every UI shows the old state for up to 30 s.
        """
        async def _poll() -> None:
            for delay in (2, 3, 5):
                await asyncio.sleep(delay)
                await self.async_refresh()
        self.hass.async_create_task(_poll())

    @callback
    def set_bool_setting_local(self, key: str, value: bool) -> None:
        """Reflect a successful write immediately, before the re-read confirms it."""
        self.bool_settings[key] = value
        if self.data is not None:
            self.data["bool_settings"] = self.bool_settings
        self.async_update_listeners()

    async def async_settings_changed_later(self, delay: float = 2.0) -> None:
        async def _later() -> None:
            await asyncio.sleep(delay)
            await self.async_settings_changed()
        self.hass.async_create_task(_later())

    async def async_settings_changed(self) -> None:
        """Re-read settings right after a write so switches don't wait for the slow cycle."""
        await self._refresh_settings()
        if self.data is not None:
            self.data["settings"] = self.settings
            self.data["schedules"] = self.schedules
            self.data["bool_settings"] = self.bool_settings
            self.data["presets"] = self.presets
        self.async_update_listeners()

    def _decode_schedules(self) -> None:
        names = {r["id"]: b64name(r.get("name", "")) for r in self.rooms}
        rules = (self.settings.get("schedules") or {}).get("rule_list") or []
        self.schedules = [decode_schedule(r, names) for r in rules]

    # ---- map ---------------------------------------------------------------------
    def _refresh_position(self) -> None:
        map_data = self.client.get_map_data(self.map_id)
        self._apply_position(map_data)

    def _apply_position(self, map_data: dict) -> None:
        self.vac_pos = map_data.get("real_vac_coor")
        self.current_room = room_at_vac(map_data)
        if self._map_base is not None:
            img = self._map_base.copy()
            vac = map_data.get("vac_coor")
            if vac:
                _dot(ImageDraw.Draw(img), *_grid_px(vac[0], vac[1], map_data["height"]), (0, 180, 255))
            self.map_image_bytes = _jpeg(img)

    def _refresh_map(self) -> None:
        current_id, _ = self.client.get_map_info()
        map_data = self.client.get_map_data(current_id)
        self.map_id = current_id
        self.map_name = b64name(map_data.get("map_name", ""))
        self.rooms = [a for a in map_data.get("area_list", []) if a.get("type") == "room"]
        self._map_base, self.room_geometry, self.map_geometry = render_map(map_data)
        self._apply_position(map_data)
        _LOGGER.debug("Map rendered: %d bytes, %d rooms", len(self.map_image_bytes or b""), len(self.rooms))

    def map_names(self) -> dict[int, str]:
        """{map_id: name} for every map stored on the vacuum."""
        _, map_list = self.client.get_map_info()
        return {m["map_id"]: b64name(m.get("map_name", "")) for m in map_list}

    def list_rooms_all_maps(self) -> list[tuple[int, str, list[tuple[int, str]]]]:
        """[(map_id, map_name, [(room_id, room_name), ...]), ...] read live."""
        out = []
        for map_id, map_name in self.map_names().items():
            map_data = self.client.get_map_data(map_id)
            rooms = [(a["id"], b64name(a.get("name", "")))
                     for a in map_data.get("area_list", []) if a.get("type") == "room"]
            out.append((map_id, map_name, rooms))
        return out

    def resolve_rooms_live(
        self, name_patterns: list[str], map_name: str | None = None
    ) -> tuple[list[int], int]:
        """Resolve room names against the vacuum's live map list -> (room_ids, map_id)."""
        current_map_id, map_list = self.client.get_map_info()
        return resolve_rooms(current_map_id, map_list, self.client.get_map_data,
                             name_patterns, map_name)
