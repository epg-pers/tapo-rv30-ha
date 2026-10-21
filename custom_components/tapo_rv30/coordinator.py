"""DataUpdateCoordinator for Tapo RV30."""
from __future__ import annotations

import asyncio
import logging
import time
from datetime import timedelta
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.storage import Store
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from PIL import Image, ImageDraw

from .const import (
    ACTIVE_POLL_INTERVAL,
    CLEANING_CODES,
    CONF_POLL_INTERVAL,
    CONSUMABLE_LABELS,
    CONSUMABLE_LIMITS_H,
    DOMAIN,
    ERROR_CODES,
    EVENT_CLEAN_FINISHED,
    EVENT_CLEAN_STARTED,
    EVENT_ERROR,
    FAST_INTERVAL,
    ISSUE_UNREACHABLE,
    MAP_INTERVAL,
    MAX_POLL_INTERVAL,
    MIN_POLL_INTERVAL,
    PAUSED_CODES,
    UNREACHABLE_AFTER,
)
from .mapdata import (
    b64name,
    clean_transition,
    decode_clean_record,
    decode_path,
    decode_preset,
    decode_schedule,
    fold,
    grid_pixels,
    resolve_rooms,
    room_at_vac,
    room_coverage,
)
from .maprender import _dot, _grid_px, _png, _px_transform, render_map, render_record, room_mask_png
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
        self.last_clean_image_bytes: bytes | None = None   # render of the newest clean record
        self.last_clean_hash: str = "0"
        self._live_map: dict | None = None                 # current map (header + pixels) for coverage maths
        self._live_pixels: bytes | None = None
        self.rooms_last_cleaned: dict[str, dict] = {}      # "map_id:room_id" -> {last_cleaned, coverage, name}
        self._freshness_store = Store(hass, 1, f"{DOMAIN}.{entry.entry_id}.rooms") if entry else None
        self._freshness_loaded = False
        self._processed_records: set[int] = set()          # record timestamps already folded in
        self.last_clean_info: dict = {}
        self._record_rendered_ts: int | None = None
        self._map_base: Image.Image | None = None     # rendered map without the vacuum marker
        self.room_geometry: list[dict] = []
        self.map_geometry: dict = {}
        self.room_mask: bytes | None = None    # PNG, pixel = room id (for the card)
        self.map_hash: str | None = None
        self.rooms: list[dict] = []        # current map's rooms (area_list, type == room)
        self.map_id: int | None = None
        self.map_name: str | None = None
        self.device_name: str = "Tapo RV30"
        self.device_model: str = "RV30"
        self.fw_version: str | None = None
        self.device_mac: str | None = None
        self._info_fetched = False
        self.settings: dict = {}           # get_settings(), refreshed with the map
        self.settings_read_at: float | None = None
        self.schedules: list[dict] = []
        self.components: dict[str, int] = {}       # getComponentList, read once
        self.bool_settings_supported: list[str] = []   # probed once
        self.dock_actions: list[str] = []              # probed once (Omni docks)
        self.bool_settings: dict[str, bool] = {}
        self.presets: list[dict] = []
        self._caps_fetched = False
        self._last_record_ts: int | None = None   # newest getCleanRecords timestamp seen
        self.maps: list[dict] = []                 # [{id, name, current}] refreshed with the map
        self.path_points: list[tuple[int, int]] = []   # mm, current or last run
        self._path_id: int | None = None
        self._last_ok: float | None = None         # monotonic time of the last good poll
        self._first_fail: float | None = None
        self._issue_open = False
        self.vac_pos: list | None = None
        self.current_room: str | None = None

    # ---- shared entity metadata ------------------------------------------------
    @property
    def device_info(self) -> DeviceInfo:
        ident = self.entry.entry_id if self.entry else self.client.host
        mac = (self.settings.get("device") or {}).get("mac") or self.device_mac
        return DeviceInfo(
            identifiers={(DOMAIN, ident)},
            connections={(dr.CONNECTION_NETWORK_MAC, dr.format_mac(mac))} if mac else set(),
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
                self.device_mac = info.get("mac") or self.device_mac
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
        data["settings_read_at"] = self.settings_read_at
        data["schedules"] = self.schedules
        await self._maybe_render_last_clean(data.get("status_code"))
        data["bool_settings"] = self.bool_settings
        data["presets"] = self.presets
        data["current_room"] = self.current_room
        data["position_mm"] = self.vac_pos
        data["path_points"] = len(self.path_points)
        data["charging"] = data.get("status_code") == 5
        dev = self.settings.get("device") or {}
        data["rssi"] = dev.get("rssi")
        data["signal_level"] = dev.get("signal_level")
        data["firmware"] = self.settings.get("firmware") or {}
        await self._fire_events(self.data, data)
        return data

    # ---- events ------------------------------------------------------------------
    def _event_base(self) -> dict:
        device_id = None
        if self.entry:
            dev = dr.async_get(self.hass).async_get_device(identifiers={(DOMAIN, self.entry.entry_id)})
            device_id = dev.id if dev else None
        return {"entry_id": self.entry.entry_id if self.entry else None, "device_id": device_id,
                "device": self.device_name, "model": self.device_model}

    async def _fire_events(self, prev: dict | None, new: dict) -> None:
        """Fire HA events on clean start/finish and on a new error."""
        if prev is None:
            self._note_latest_record()
            return
        change = clean_transition(prev.get("status_code"), new.get("status_code"), CLEANING_CODES, PAUSED_CODES)
        if change == "started":
            self.hass.bus.async_fire(EVENT_CLEAN_STARTED, {**self._event_base(), "status_code": new.get("status_code"),
                                                           "current_room": self.current_room})
        elif change == "finished":
            record = await self._fetch_new_record()
            self.hass.bus.async_fire(EVENT_CLEAN_FINISHED, {**self._event_base(), "status_code": new.get("status_code"),
                                                            **({"record": record} if record else {})})
        prev_err = (prev.get("error_codes") or [0])[0]
        new_err = (new.get("error_codes") or [0])[0]
        if new_err and new_err != prev_err:
            self.hass.bus.async_fire(EVENT_ERROR, {**self._event_base(), "code": new_err,
                                                   "error": ERROR_CODES.get(new_err, f"Code({new_err})"),
                                                   "current_room": self.current_room})

    async def _load_freshness(self) -> None:
        if self._freshness_loaded or self._freshness_store is None:
            return
        self._freshness_loaded = True
        try:
            data = await self._freshness_store.async_load() or {}
            self.rooms_last_cleaned = dict(data.get("rooms") or {})
            self._processed_records = set(int(t) for t in data.get("processed") or [])
        except Exception as exc:
            _LOGGER.debug("Room freshness store unreadable: %s", exc)

    def _fold_coverage(self, record: dict, detail: dict) -> None:
        """Per-room coverage of one finished run into rooms_last_cleaned."""
        if self._live_map is None or self._live_pixels is None or detail.get("map_id") != self.map_id:
            return
        names = {r["id"]: b64name(r.get("name", "")) for r in self.rooms}
        ts = int(record.get("timestamp") or 0)
        for rid, (done, total) in room_coverage(detail, self._live_map, self._live_pixels).items():
            if total == 0 or done == 0:
                continue
            pct = round(100 * done / total)
            if pct < 20:            # the robot only crossed the room; not a clean
                continue
            key = f"{self.map_id}:{rid}"
            cur = self.rooms_last_cleaned.get(key)
            if cur is None or ts >= int(cur.get("last_cleaned") or 0):
                self.rooms_last_cleaned[key] = {"last_cleaned": ts, "coverage": pct, "name": names.get(rid, f"Room {rid}")}

    async def _maybe_render_last_clean(self, status_code) -> None:
        """Render the newest clean record's map once it exists and the robot is not
        working, and fold every unseen record into the per-room freshness table
        (a few records per poll, so a long history is backfilled gently)."""
        await self._load_freshness()
        recs = (self.settings.get("records") or {}).get("record_list") or []
        if not recs or status_code in CLEANING_CODES or status_code in PAUSED_CODES or status_code == 4:
            return
        newest = max(recs, key=lambda r: r.get("timestamp", 0))
        ts = newest.get("timestamp", 0)
        pending = sorted((r for r in recs if int(r.get("timestamp") or 0) not in self._processed_records),
                         key=lambda r: r.get("timestamp", 0))
        if ts == self._record_rendered_ts and not pending:
            return
        changed = False
        todo = pending[:3]
        render_only = ts != self._record_rendered_ts and all(int(r.get("timestamp") or 0) != ts for r in todo)
        if render_only:
            todo = todo + [newest]      # already folded in (e.g. after a restart): just redraw it
        for rec in todo:
            rts = int(rec.get("timestamp") or 0)
            already = rts in self._processed_records
            try:
                detail = await self.hass.async_add_executor_job(
                    self.client.get_clean_record_detail, rec.get("record_index", 0))
                if not already:
                    await self.hass.async_add_executor_job(self._fold_coverage, rec, detail)
                if rts == ts:
                    img = await self.hass.async_add_executor_job(render_record, detail)
                    self.last_clean_image_bytes = _png(img)
                    self.last_clean_hash = str(rts)
                    self.last_clean_info = {**decode_clean_record(rec),
                                            "map_name": b64name(detail.get("map_name", "")),
                                            "map_id": detail.get("map_id")}
                    self._record_rendered_ts = ts
            except Exception as exc:
                _LOGGER.debug("Clean record %s failed: %s", rec.get("record_index"), exc)
                if rts == ts:
                    self._record_rendered_ts = ts     # do not retry every poll on a bad record
            if not already:
                self._processed_records.add(rts)
                changed = True
        if changed and self._freshness_store is not None:
            keep = sorted(self._processed_records)[-200:]
            self._processed_records = set(keep)
            await self._freshness_store.async_save({"rooms": self.rooms_last_cleaned, "processed": keep})

    def room_freshness(self) -> dict[str, dict]:
        """{room name: {last_cleaned, coverage}} for the current map."""
        out = {}
        for key, v in self.rooms_last_cleaned.items():
            if key.startswith(f"{self.map_id}:"):
                out[v.get("name") or key] = {"last_cleaned": v.get("last_cleaned"), "coverage": v.get("coverage")}
        return out

    def consumables_percent(self) -> dict[str, int]:
        """Remaining life per consumable as a percentage, by label."""
        raw = (self.data or {}).get("consumables") or {}
        out = {}
        for key, limit_h in CONSUMABLE_LIMITS_H.items():
            mins = raw.get(key)
            if mins is None:
                continue
            out[CONSUMABLE_LABELS[key]] = max(0, min(100, round(100 * (1 - mins / 60 / limit_h))))
        return out

    def _note_latest_record(self) -> None:
        recs = (self.settings.get("records") or {}).get("record_list") or []
        if recs:
            self._last_record_ts = max(r.get("timestamp", 0) for r in recs)

    async def _fetch_new_record(self) -> dict | None:
        """The clean record the robot just wrote, if it is newer than any seen."""
        try:
            raw = await self.hass.async_add_executor_job(self.client.get_clean_records)
        except Exception as exc:
            _LOGGER.debug("Records fetch after clean failed: %s", exc)
            return None
        self.settings["records"] = raw
        recs = raw.get("record_list") or []
        if not recs:
            return None
        newest = max(recs, key=lambda r: r.get("timestamp", 0))
        ts = newest.get("timestamp", 0)
        if self._last_record_ts is not None and ts <= self._last_record_ts:
            return None
        self._last_record_ts = ts
        return decode_clean_record(newest)

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
        try:
            self.dock_actions = await self.hass.async_add_executor_job(self.client.probe_dock_actions)
        except Exception as exc:
            _LOGGER.debug("Dock probe failed: %s", exc)
        self._caps_fetched = True

    async def _refresh_settings(self) -> None:
        self.settings = await self.hass.async_add_executor_job(self.client.get_settings)
        self.settings_read_at = time.time()
        self._decode_schedules()
        if self._last_record_ts is None:
            self._note_latest_record()
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
        every entity to unavailable. Tracks reachability for the repair issue
        and adapts the poll interval to what the robot is doing."""
        delay = STATUS_RETRY_DELAY
        for attempt in range(1, STATUS_RETRIES + 1):
            try:
                data = await self.hass.async_add_executor_job(self.client.get_status)
            except AuthError as exc:
                raise ConfigEntryAuthFailed(str(exc)) from exc
            except Exception as exc:
                if attempt == STATUS_RETRIES:
                    self._note_failure()
                    raise UpdateFailed(f"Failed to fetch vacuum status: {exc}") from exc
                _LOGGER.debug("Status fetch failed (attempt %d/%d): %s", attempt, STATUS_RETRIES, exc)
                await asyncio.sleep(delay)
                delay *= 2
                continue
            self._note_success()
            self._adapt_interval(data.get("status_code"))
            return data
        raise UpdateFailed("unreachable")   # pragma: no cover

    def _adapt_interval(self, status_code) -> None:
        active = status_code in CLEANING_CODES or status_code == 4
        seconds = min(self.poll_interval, ACTIVE_POLL_INTERVAL) if active else self.poll_interval
        if self.update_interval != timedelta(seconds=seconds):
            self.update_interval = timedelta(seconds=seconds)

    def _note_success(self) -> None:
        self._last_ok = self.hass.loop.time()
        self._first_fail = None
        if self._issue_open:
            ir.async_delete_issue(self.hass, DOMAIN, f"{ISSUE_UNREACHABLE}_{self.entry.entry_id if self.entry else self.client.host}")
            self._issue_open = False

    def _note_failure(self) -> None:
        """After UNREACHABLE_AFTER seconds of failures on a robot that used to
        answer, raise a repair pointing at the known firmware regression."""
        now = self.hass.loop.time()
        if self._last_ok is None:
            return
        if self._first_fail is None:
            self._first_fail = now
            return
        if now - self._first_fail >= UNREACHABLE_AFTER and not self._issue_open:
            ir.async_create_issue(
                self.hass, DOMAIN, f"{ISSUE_UNREACHABLE}_{self.entry.entry_id if self.entry else self.client.host}",
                is_fixable=False, severity=ir.IssueSeverity.WARNING, translation_key=ISSUE_UNREACHABLE,
                translation_placeholders={"name": self.device_name, "host": self.client.host},
                learn_more_url="https://github.com/epg-pers/tapo-rv30-ha#known-issue-firmware-updates-and-local-access",
            )
            self._issue_open = True

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
        self.schedules = [decode_schedule(r, names, self.settings.get("dnd")) for r in rules]

    # ---- map ---------------------------------------------------------------------
    def _refresh_position(self) -> None:
        map_data = self.client.get_map_data(self.map_id)
        self._apply_position(map_data)

    def _apply_position(self, map_data: dict) -> None:
        self.vac_pos = map_data.get("real_vac_coor")
        self.current_room = room_at_vac(map_data)
        self._update_path(map_data)
        if self._map_base is not None:
            img = self._map_base.copy()
            draw = ImageDraw.Draw(img)
            if len(self.path_points) > 1:
                to_px = _px_transform(map_data)
                draw.line([to_px(x, y) for x, y in self.path_points], fill=(0, 140, 220, 200), width=2, joint="curve")
            vac = map_data.get("vac_coor")
            if vac:
                _dot(draw, *_grid_px(vac[0], vac[1], map_data["height"]), (0, 180, 255))
            self.map_image_bytes = _png(img)

    def _update_path(self, map_data: dict) -> None:
        """Read the run's path while the robot is active (new path_id = new run)."""
        path_id = map_data.get("path_id")
        code = self.status_code
        active = code in CLEANING_CODES or code in PAUSED_CODES or code == 4
        if path_id is None or not active:
            return
        if path_id != self._path_id:
            self._path_id = path_id
            self.path_points = []
        try:
            r = self.client.get_path(path_id, 0)
            if r.get("pos_array") and r.get("pos_len"):
                self.path_points = decode_path(r["pos_array"], int(r["pos_len"]))
        except Exception as exc:
            _LOGGER.debug("Path fetch failed: %s", exc)

    async def async_request_map_refresh(self) -> None:
        """Re-render the map on the next poll (after set_map)."""
        self._map_tick = self._map_cycles
        await self.async_refresh_soon()

    def _refresh_map(self) -> None:
        current_id, map_list = self.client.get_map_info()
        self.maps = [{"id": m["map_id"], "name": b64name(m.get("map_name", "")), "current": m["map_id"] == current_id}
                     for m in map_list]
        map_data = self.client.get_map_data(current_id)
        self.map_id = current_id
        self.map_name = b64name(map_data.get("map_name", ""))
        self.rooms = [a for a in map_data.get("area_list", []) if a.get("type") == "room"]
        self._map_base, self.room_geometry, self.map_geometry = render_map(map_data)
        self._live_map = {k: map_data.get(k) for k in ("width", "height", "pix_len", "map_data", "resolution", "real_origin_coor", "area_list", "map_id")}
        try:
            self._live_pixels = grid_pixels(map_data)
        except Exception:
            self._live_pixels = None
        self.room_mask = room_mask_png(map_data)
        self.map_hash = str(map_data.get("map_hash") or len(self.room_mask))
        self._apply_position(map_data)
        _LOGGER.debug("Map rendered: %d bytes, %d rooms", len(self.map_image_bytes or b""), len(self.rooms))

    def rooms_named(self) -> list[dict]:
        """Rooms of the current map with the decoded name under name_text."""
        return [{**r, "name_text": b64name(r.get("name", ""))} for r in self.rooms]

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
