"""DataUpdateCoordinator for Tapo RV30."""
from __future__ import annotations

import asyncio
import logging
import os
import time
from collections import OrderedDict
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
from homeassistant.util import dt as dt_util
from PIL import Image, ImageDraw

from . import cleanhistory, mapsnapshot
from .const import (
    ACTIVE_POLL_INTERVAL,
    CLEANING_CODES,
    CONF_POLL_INTERVAL,
    CONSUMABLE_LABELS,
    CONSUMABLE_LIMITS_H,
    DOCKED_CODES,
    DOMAIN,
    ERROR_CODES,
    EVENT_CLEAN_FINISHED,
    EVENT_CLEAN_STARTED,
    EVENT_ERROR,
    EVENT_PROMPT,
    FAST_INTERVAL,
    ISSUE_UNREACHABLE,
    MAP_INTERVAL,
    MAX_POLL_INTERVAL,
    MIN_POLL_INTERVAL,
    OPT_HISTORY_KEEP,
    OPT_HISTORY_LIMIT,
    PAUSED_CODES,
    UNREACHABLE_AFTER,
)
from .mapdata import (
    b64name,
    decode_clean_record,
    decode_path,
    decode_preset,
    decode_schedule,
    direction_texture,
    fold,
    grid_pixels,
    new_prompts,
    preset_ref_id,
    resolve_rooms,
    room_areas,
    room_at_vac,
    room_coverage,
    texture_direction,
)
from .maprender import _dot, _png, _px_transform, render_map, render_record, room_mask_png, rotation_of
from .setup_apply import robot_key
from .tpap import AuthError, TapoVacuumClient, WrongDevice, _is_dropout, _opt_int

_LOGGER = logging.getLogger(__name__)

STATUS_RETRIES = 3          # attempts per poll before the entities go unavailable
STATUS_RETRY_DELAY = 1.5    # seconds, doubled each retry
_FRESHNESS_ALGO = 3         # per-room coverage logic; bump to re-fold saved history after a change


# ---------------------------------------------------------------------------
# Coordinator
# ---------------------------------------------------------------------------
# Settings whose presence at setup decides whether an entity exists.
_ENTITY_SETTINGS = frozenset({"dust", "dnd", "volume", "auto_update", "matter_status", "matter_setup"})


# Run tracking, see _track_run. Only a real clean opens a run: a drive home, a go-to or a
# remote drive write no record and are not runs.
RUN_CODES = frozenset({1, 2, 13})           # cleaning, mapping, exploring
RUN_PAUSED = frozenset({7, 10, 14})         # one of those paused (12 is a paused go-to)
WASH_CODES = frozenset({15, 17, 18})        # washing / attaching / removing the mop at the dock
RECHARGE_PROMPTS = frozenset({7, 31})       # "returning to recharge" / "paused to recharge"
RECHARGE_ERROR = 22                         # "Low Battery, Recharging"
RUN_GRACE = 15 * 60         # after a run, map writes wait this long for its record
RUN_OPEN_MAX = 8 * 3600     # docked part way through a run for longer than this: taken as over


def _ts(record: dict) -> int:
    """A clean record's timestamp as an int (0 when missing or not a number)."""
    try:
        return int(record.get("timestamp") or 0)
    except (TypeError, ValueError, OverflowError):
        return 0


def _records(raw) -> list[dict]:
    """getCleanRecords' record_list, keeping only real records."""
    recs = raw.get("record_list") if isinstance(raw, dict) else None
    return [r for r in recs if isinstance(r, dict)] if isinstance(recs, list) else []


class TapoCoordinator(DataUpdateCoordinator):
    """Polls the vacuum for status, keeps the map image and settings current."""

    _path_map_id: int | None = None     # the map the trail was recorded on (see shown_path)

    def __init__(self, hass: HomeAssistant, client: TapoVacuumClient, entry: ConfigEntry | None = None) -> None:
        interval = FAST_INTERVAL
        if entry is not None:
            interval = int(entry.options.get(CONF_POLL_INTERVAL, FAST_INTERVAL))
        interval = max(MIN_POLL_INTERVAL, min(MAX_POLL_INTERVAL, interval))
        super().__init__(hass, _LOGGER, name=DOMAIN, update_interval=timedelta(seconds=interval))
        self.client = client
        self.entry = entry
        self.poll_interval = interval
        self._map_read_at: float | None = None
        self._frame_key: tuple | None = None
        self._run: dict | None = None                   # {phase, at, recharge, checked}, see _track_run
        self.presets_read = False                       # presets were read at least once
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
        self._history: cleanhistory.CleanHistory | None = None   # kept clean maps, see history()
        self._history_pruned_at = 0.0
        self._history_png: OrderedDict[int, tuple] = OrderedDict()   # the last few drawn: (map, turn, png)
        self._map_base: Image.Image | None = None     # rendered map without the vacuum marker
        self.room_geometry: list[dict] = []
        self.map_geometry: dict = {}
        self.room_mask: bytes | None = None    # PNG, pixel = room id (for the card)
        self.map_hash: str | None = None
        self.rooms: list[dict] = []        # current map's rooms (area_list, type == room)
        self.map_id: int | None = None
        self.map_name: str | None = None
        self.map_rotation = 0                # the current map's rotate_angle (0, 90, 180, 270)
        self.rotation_supported = False      # the robot reports rotate_angle for its maps
        self.rotation_known = False          # a map list was read, so rotation_supported is an answer
        self._rotation_at_setup = False      # what the select platform saw at setup
        self.lock_supported = False          # the robot lists map_lock and reports map_locked
        self.device_name: str = "Tapo RV30"
        self.device_model: str = "RV30"
        self.fw_version: str | None = None
        self.device_mac: str | None = None
        self._info_fetched = False
        self.settings: dict = {}           # get_settings(), refreshed with the map
        self.settings_read_at: float | None = None
        self._bool_written: dict[str, float] = {}     # bool setting -> when we last wrote it
        self.schedule_lock = asyncio.Lock()  # one schedule edit (read, change, write back) at a time
        self.map_lock = asyncio.Lock()      # held while a map write (setup apply, editor) switches maps
        self._map_warned = False                       # "Map refresh failed" logged since the last good read
        self.schedules: list[dict] = []
        self.components: dict[str, int] = {}       # getComponentList, read once
        self.bool_settings_supported: list[str] = []   # probed once
        self.dock_actions: list[str] = []              # probed once (Omni docks)
        self.bool_settings: dict[str, bool] = {}
        self.presets: list[dict] = []
        self._presets_raw: list[dict] | None = None    # getCustomizationRuleData bodies; None = last read failed
        self._map_layers: dict | None = None           # {map_id, map_name, area_list, furniture_list}
        self._snapshot_hash: dict[int, str] = {}       # map_id -> content hash last written
        self.pending_restore: dict | None = None       # lost-map restore waiting to be saved in the app
        self.snapshot_hold: dict[int, float] = {}      # map_id -> when a restore onto it began (saved setup kept)
        self._restore_store = Store(hass, 1, f"{DOMAIN}.{entry.entry_id}.restore") if entry else None
        self._restore_loaded = False
        self._update_lock = asyncio.Lock()             # one poll at a time (refresh_soon overlaps the timer)
        self._map_retry = False                        # map read failed: retry the map alone next poll
        self._record_failures: dict[int, int] = {}     # record timestamp -> failed detail reads
        self._setting_keys: set[str] | None = None     # settings keys the entities were set up with
        self._reload_asked = False
        self._room_name_cache: dict[int, dict[int, str]] = {}
        self._robot_region: str | None = None
        self._robot_tz = None                          # the robot's own time zone, when it says
        self._finishing = False
        self._caps_fetched = False
        self._caps_attempts = 0
        self._last_record_ts: int | None = None   # newest getCleanRecords timestamp seen
        self.maps: list[dict] = []                 # [{id, name, current}] refreshed with the map
        self._snapshot_lock = asyncio.Lock()       # one map setup snapshot write at a time
        self._last_tidy: dict | None = None        # {map_id, out}: the last restore tidy-up and what it did
        self.path_points: list[tuple[int, int]] = []   # mm, current or last run
        self._path_id: int | None = None
        self._path_map_id: int | None = None       # the map path_points was drawn on
        self._last_ok: float | None = None         # monotonic time of the last good poll
        self._first_fail: float | None = None
        self._issue_open = True     # unknown after a reload: the first good poll clears any old repair
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
    def clean_direction_supported(self) -> bool:
        """A cleaning direction per room (the app's isSupportCleanDirection: clean_angle 1 or later).
        False while the component list is unknown: a room write is not risked on a guess."""
        try:
            return int(self.components.get("clean_angle", 0)) >= 1
        except (TypeError, ValueError, AttributeError):
            return False

    def has_part(self, field: str) -> bool:
        """True if getConsumablesInfo reports this part's time (or it was not read): a robot
        without a mop gets no mop cloth entities."""
        parts = (self.data or {}).get("consumables") or {}
        return field in parts if parts else True

    @property
    def status_code(self) -> int | None:
        return (self.data or {}).get("status_code")

    def robot_now(self):
        """Now on the robot's own clock: its schedules and Do Not Disturb are kept in its
        region, which need not be Home Assistant's."""
        return dt_util.now(self._robot_tz) if self._robot_tz else dt_util.now()

    @property
    def map_busy(self) -> str | None:
        """Like busy, but for writes to the robot's maps: also refused while it drives home, and
        for a short while after a run, until the robot has recorded it."""
        if self.busy or self.status_code == 4:
            return self.busy or "returning"
        if self._run_phase() == "over":
            return "finishing a clean (it has not recorded the run yet)"
        return None

    @property
    def busy(self) -> str | None:
        """Why a new clean would be refused: cleaning, paused, or docked part way through a
        run (recharging, washing the mop). None when the robot is free."""
        code = self.status_code
        if code in CLEANING_CODES:
            return "cleaning"
        if code in PAUSED_CODES:
            return "paused"
        if code in DOCKED_CODES:
            return {"recharge": "recharging to finish its clean",
                    "wash": "washing its mop part way through a clean"}.get(self._run_phase())
        return None

    def start_refused(self) -> str | None:
        """Why a clean must not start now, for every start path (services, vacuum entity, voice,
        buttons): a map write is switching maps, or the robot is docked part way through a run
        that it carries on by itself."""
        if self.map_lock.locked():
            return "is having its map written (map setup or editor); try again shortly"
        if self.status_code in DOCKED_CODES and (why := self.busy):
            return f"is {why} and carries on by itself; press Stop first to start a different clean"
        return None

    async def async_forget_run(self) -> None:
        """Stop pressed while docked part way through a run: the user is done with it, so it no
        longer holds back other cleans (the robot may still finish it by itself)."""
        async with self._update_lock:       # a poll must not move the run on in between
            if self._run_phase() in ("recharge", "wash"):
                await self._end_run(self.data or {})

    def _run_phase(self) -> str | None:
        """The run's phase: 'active', docked part way through it ('recharge' / 'wash'), or
        'over' (its record not seen yet). None when there is no run, or it timed out."""
        run = self._run
        if not run:
            return None
        limit = {"active": None, "over": RUN_GRACE}.get(run["phase"], RUN_OPEN_MAX)
        if limit and time.monotonic() - run["at"] >= limit:
            return None
        return run["phase"]

    def _run_open(self) -> bool:
        return self._run_phase() is not None

    async def _track_run(self, prev: dict | None, new: dict) -> None:
        """Follow the robot's run; one clean_started and one clean_finished per run.

        Only a real clean (RUN_CODES) opens a run; returning and the paused codes keep it going.
        Docked part way through, to recharge (prompt 7/31, error 22) or to wash its mop (an
        Omni dock), it is still on and busy says so. Docked otherwise, or stopped, its clean is
        over: clean_finished fires and map writes wait for its record, RUN_GRACE at most. A
        record newer than the newest seen when it opened closes it at any point."""
        code = new.get("status_code")
        now = time.monotonic()
        sign = (bool(set(new.get("prompts") or []) & RECHARGE_PROMPTS)
                or RECHARGE_ERROR in (new.get("error_codes") or []))
        active = code in CLEANING_CODES or code in PAUSED_CODES or code == 4
        phase = self._run_phase()
        if phase is None:
            self._run = None
        run = self._run
        if phase in ("recharge", "wash") and code in RUN_CODES:
            # Setting off again, unless the robot recorded the run meanwhile (it was ended at
            # the dock): then this is a new clean.
            record = await self._fetch_new_record()
            if record is None:
                run.update(phase="active", at=now, recharge=sign, resumed=False)
                return
            self._fire_finished(new, record)
            phase = run = self._run = None
        if phase in (None, "over"):
            # After a restart, pick up a run already under way (or docked to recharge).
            resumed = prev is None and (code in RUN_PAUSED or ((code in DOCKED_CODES or code == 4) and sign))
            if code in RUN_CODES or resumed:
                await self._read_records()      # the baseline: every record written so far
                newest = max((_ts(r) for r in _records(self.settings.get("records"))), default=0)
                self._last_record_ts = max(self._last_record_ts or 0, newest)
                self._run = {"phase": "recharge" if code in DOCKED_CODES else "active", "at": now,
                             "recharge": sign, "resumed": prev is None and code not in RUN_CODES}
                if prev is not None:
                    self.hass.bus.async_fire(EVENT_CLEAN_STARTED, {
                        **self._event_base(), "status_code": code, "current_room": self.current_room})
                return
        elif phase == "active":
            run["recharge"] = run["recharge"] or sign
            if code in CLEANING_CODES or code in PAUSED_CODES:
                return
            if code == 4 and (run["recharge"] or "wash_mop" in self.dock_actions):
                return      # heading home: finished or not is known once it is docked
            if code in DOCKED_CODES and (run["recharge"] or code in WASH_CODES):
                run.update(phase="recharge" if run["recharge"] else "wash", at=now)
            else:
                await self._end_run(new)
                return
        elif active:
            run.update(phase="active", at=now, resumed=False)      # left the dock again
            return
        elif code not in DOCKED_CODES:
            await self._end_run(new)                # stopped at the dock
            return
        elif phase == "wash" and code not in WASH_CODES:
            if not (sign or run["recharge"]):
                await self._end_run(new)            # washed, not setting off again: done
                return
            run.update(phase="recharge", at=now)
        elif run.get("resumed") and code == 6 and not sign:
            # Picked up after a restart on a recharge sign, now charged and not setting off: there
            # was no run to finish (a stale notice), so it must not hold off other cleans.
            self._run = None
            return
        # Docked or idle with the run not closed: its record closes it, looked for each minute.
        run = self._run
        if run and not active:
            if now - run.get("checked", 0) >= 60:
                run["checked"] = now
                await self._read_records()
            record = self._new_record()
            if record is not None:
                if run["phase"] != "over":
                    self._fire_finished(new, record)
                self._run = None

    async def _end_run(self, new: dict) -> None:
        """The run's clean is over: clean_finished, with its record if the robot wrote one.
        Home without a record yet, map writes wait for it (RUN_GRACE at most)."""
        record = await self._fetch_new_record()
        self._fire_finished(new, record)
        code, now = new.get("status_code"), time.monotonic()
        home = code == 4 or code in DOCKED_CODES
        self._run = {"phase": "over", "at": now, "checked": now} if home and record is None else None

    def _fire_finished(self, new: dict, record: dict | None) -> None:
        self.hass.bus.async_fire(EVENT_CLEAN_FINISHED, {**self._event_base(), "status_code": new.get("status_code"),
                                                        **({"record": record} if record else {})})

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
        # async_refresh_soon refreshes alongside the timer; two polls at once would both see
        # the same previous state and fire the same clean_finished event twice.
        async with self._update_lock:
            return await self._update_once()

    async def _update_once(self) -> dict[str, Any]:
        await self._load_restore()
        unreachable = False
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
                unreachable = _is_dropout(exc)
                _LOGGER.debug("Device info fetch failed: %s", exc)

        # An unreachable robot (offline at a Home Assistant start, say) is not probed: each
        # getter would wait out its own connect timeout before the status read fails. The
        # probe waits until the status read shows the robot answering, on this poll or later.
        deferred = False
        if not self._caps_fetched:
            deferred = unreachable or not await self._fetch_capabilities()

        data = await self._fetch_status()
        if deferred and not self._caps_fetched:
            # The robot answers status, so a failed component list here is not the robot
            # being away (a reply it cannot read, say): probe anyway and count the attempt,
            # so CAPS_ATTEMPTS still ends the probing.
            await self._fetch_capabilities(skip_unreachable=False)

        # Full map render + settings on first load and every MAP_INTERVAL; in
        # between, re-read the map data so position and current room track.
        # With no map yet (a new robot, or one between maps) the map is tried every poll, but
        # settings keep their own cycle and the failure is logged once, not every poll.
        # Timed, not counted: the poll interval shortens while cleaning, and a count of polls
        # would then re-read everything every 100 s instead of every MAP_INTERVAL.
        now = time.monotonic()
        cycle = self._map_read_at is None or now - self._map_read_at >= MAP_INTERVAL
        full = self._map_base is None or cycle
        if full or self._map_retry:
            if cycle:
                self._map_read_at = now
            map_ok = False
            try:
                await self.hass.async_add_executor_job(self._refresh_map)
                map_ok, self._map_retry, self._map_warned = True, False, False
            except Exception as exc:
                # The robot refuses map data while manoeuvring (-3016); with a
                # map already rendered that is routine, so keep it out of the log.
                if self._map_base is None and not self._map_warned:
                    _LOGGER.warning("Map refresh failed: %s", exc)
                    self._map_warned = True
                else:
                    _LOGGER.debug("Map refresh skipped: %s", exc)
                    if self._map_base is not None:
                        self._map_retry = True   # retry the map alone next poll; settings keep their own cycle
            self._note_rotation()
            if cycle or self.settings_read_at is None:
                try:
                    await self._refresh_settings()
                except AuthError as exc:
                    raise ConfigEntryAuthFailed(str(exc)) from exc
                except Exception as exc:    # the robot dropped out part way: keep the last values
                    _LOGGER.debug("Settings read failed: %s", exc)
                    if self._setting_keys is None and self.data is None:
                        # Setup sees no settings: start from none, so the entities of the ones
                        # that answer later are still added (by a reload) instead of never.
                        self._setting_keys = set()
            if full or map_ok:
                self._check_pending_restore()
                try:
                    await self._auto_snapshot()
                except Exception as exc:   # never let snapshotting break polling
                    _LOGGER.debug("Map snapshot failed: %s", exc)
        elif self.map_id is not None:
            try:
                await self.hass.async_add_executor_job(self._refresh_position)
            except Exception as exc:
                _LOGGER.debug("Position refresh failed: %s", exc)

        data["settings"] = self.settings
        data["settings_read_at"] = self.settings_read_at
        data["schedules"] = self.schedules
        data["bool_settings"] = self.bool_settings
        data["presets"] = self.presets
        data["current_room"] = self.current_room
        data["position_mm"] = self.vac_pos
        data["path_points"] = len(self.shown_path())
        data["charging"] = data.get("status_code") == 5
        dev = self.settings.get("device") or {}
        data["rssi"] = dev.get("rssi")
        data["signal_level"] = dev.get("signal_level")
        data["firmware"] = self.settings.get("firmware") or {}
        await self._fire_events(self.data, data)
        # After the events: a run ending this poll reads the record it left (_end_run), which
        # is then folded into room freshness before listeners (the planner) see the dock.
        await self._maybe_render_last_clean(data.get("status_code"))
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
        """Fire HA events on clean start/finish (see _track_run) and on a new error or prompt."""
        if prev is None:
            self._note_latest_record()
        await self._track_run(prev, new)
        if prev is None:
            return
        prev_err = (prev.get("error_codes") or [0])[0]
        new_err = (new.get("error_codes") or [0])[0]
        if new_err and new_err != prev_err:
            self.hass.bus.async_fire(EVENT_ERROR, {**self._event_base(), "code": new_err,
                                                   "error": ERROR_CODES.get(new_err, f"Code({new_err})"),
                                                   "current_room": self.current_room})
        for prompt in new_prompts(prev, new):
            self.hass.bus.async_fire(EVENT_PROMPT, {**self._event_base(), **prompt,
                                                    "current_room": self.current_room})

    async def _load_freshness(self) -> None:
        if self._freshness_loaded or self._freshness_store is None:
            return
        self._freshness_loaded = True
        try:
            data = await self._freshness_store.async_load() or {}
            if data and data.get("algo") != _FRESHNESS_ALGO:
                # The per-room coverage logic has changed; drop the saved table and the
                # processed set so the history is re-folded with the new logic.
                self.rooms_last_cleaned = {}
                self._processed_records = set()
            else:
                self.rooms_last_cleaned = dict(data.get("rooms") or {})
                self._processed_records = set(int(t) for t in data.get("processed") or [])
        except Exception as exc:
            _LOGGER.debug("Room freshness store unreadable: %s", exc)

    def _fold_coverage(self, record: dict, detail: dict) -> bool:
        """Per-room coverage of one finished run into rooms_last_cleaned. False when the
        current map is not loaded yet, so the record is tried again later."""
        if self._live_map is None or self._live_pixels is None:
            return False
        if detail.get("map_id") != self.map_id:
            return True
        names = {r["id"]: b64name(r.get("name", "")) for r in self.rooms}
        ts = _ts(record)
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
        return True

    async def _maybe_render_last_clean(self, status_code) -> None:
        """Render the newest clean record's map once it exists and the robot is not
        working, and fold every unseen record into the per-room freshness table
        (a few records per poll, so a long history is backfilled gently)."""
        await self._load_freshness()
        await self._prune_history()
        recs = _records(self.settings.get("records"))
        if not recs or status_code in CLEANING_CODES or status_code in PAUSED_CODES or status_code == 4:
            return
        newest = max(recs, key=_ts)
        ts = _ts(newest)
        # Records are folded into the active map's rooms. Runs on another map wait (unmarked)
        # until that map is active again, and nothing is folded while no map is loaded, so
        # their details are not downloaded again on every poll.
        pending = sorted((r for r in recs if _ts(r) not in self._processed_records
                          and r.get("map_id") in (None, self.map_id)), key=_ts)
        if self._live_pixels is None:
            pending = []
        if ts == self._record_rendered_ts and not pending:
            return
        changed = False
        todo = pending[:3]
        render_only = ts != self._record_rendered_ts and all(_ts(r) != ts for r in todo)
        if render_only:
            todo = todo + [newest]      # already folded in (e.g. after a restart): just redraw it
        for rec in todo:
            rts = _ts(rec)
            already = rts in self._processed_records
            done = False        # folded in (or not foldable): do not try this record again
            try:
                detail = await self.hass.async_add_executor_job(
                    self.client.get_clean_record_detail, rec.get("record_index", 0))
                # Only records picked as pending are folded; the newest one added just to redraw it
                # may be another floor's run, to be counted when that floor is active again.
                if not already and rec in pending:
                    done = await self.hass.async_add_executor_job(self._fold_coverage, rec, detail)
                await self._keep_run(rec, detail)
                if rts == ts:
                    # Drawing and PNG encoding are both CPU-heavy: keep them off the event loop.
                    self.last_clean_image_bytes = await self.hass.async_add_executor_job(
                        lambda d=detail: _png(render_record(d, self.rotation_for(d.get("map_id")))))
                    # The rotation is part of it, so the card fetches the turned picture.
                    self.last_clean_hash = f"{rts}-{self.rotation_for(detail.get('map_id'))}"
                    self.last_clean_info = {**decode_clean_record(rec),
                                            "map_name": b64name(detail.get("map_name", "")),
                                            "map_id": detail.get("map_id")}
                    self._record_rendered_ts = ts
            except Exception as exc:
                _LOGGER.debug("Clean record %s failed: %s", rec.get("record_index"), exc)
                if rts == ts:
                    self._record_rendered_ts = ts     # do not retry every poll on a bad record
                # a transient failure is retried on later polls; a record that keeps failing is given up
                self._record_failures[rts] = self._record_failures.get(rts, 0) + 1
                done = self._record_failures[rts] >= 3
            if not already and done and rec in pending:
                self._processed_records.add(rts)
                self._record_failures.pop(rts, None)
                changed = True
        if changed and self._freshness_store is not None:
            keep = sorted(self._processed_records)[-200:]
            self._processed_records = set(keep)
            await self._freshness_store.async_save(
                {"algo": _FRESHNESS_ALGO, "rooms": self.rooms_last_cleaned, "processed": keep})

    # ---- clean map history ----------------------------------------------------------------
    @property
    def history_retention(self) -> str:
        value = self.entry.options.get(OPT_HISTORY_KEEP) if self.entry else None
        return value if value in cleanhistory.RETENTION_DAYS else cleanhistory.DEFAULT_RETENTION

    @property
    def history_limit(self) -> int:
        try:
            value = int(self.entry.options.get(OPT_HISTORY_LIMIT, cleanhistory.DEFAULT_LIMIT)) if self.entry \
                else cleanhistory.DEFAULT_LIMIT
        except (TypeError, ValueError):
            value = cleanhistory.DEFAULT_LIMIT
        return max(cleanhistory.MIN_LIMIT, min(cleanhistory.MAX_LIMIT, value))

    def history(self) -> cleanhistory.CleanHistory | None:
        """This robot's kept clean maps, in a folder named like its map backups (by MAC, so
        re-adding the integration finds them again)."""
        if self.entry is None:
            return None
        folder = os.path.join(self.hass.config.path(DOMAIN, "clean_history"), robot_key(self))
        if self._history is None or self._history.folder != folder:
            self._history = cleanhistory.CleanHistory(folder)
        return self._history

    async def _keep_run(self, rec: dict, detail: dict, auto: bool = True) -> None:
        """Keep a finished run's map, from the record already read (no extra robot call).
        Kept automatically (`auto`), a run forgotten on the History tab is left forgotten."""
        hist = self.history()
        if hist is None or cleanhistory.retention_days(self.history_retention) == 0 or not _ts(rec):
            return
        meta = {**decode_clean_record(rec), "map_name": b64name(detail.get("map_name", "")) or None}
        try:
            if await self.hass.async_add_executor_job(hist.add, _ts(rec), meta, detail, auto):
                await self._prune_history(force=True)
        except Exception as exc:
            _LOGGER.warning("Could not keep the map of the clean at %s: %s", _ts(rec), exc)

    async def _prune_history(self, force: bool = False) -> None:
        """Apply the retention settings: at most hourly, and whenever they or the runs change."""
        now = time.time()
        if not force and now - self._history_pruned_at < 3600:
            return
        self._history_pruned_at = now
        hist = self.history()
        if hist is None:
            return
        try:
            removed = await self.hass.async_add_executor_job(
                hist.prune, now, cleanhistory.retention_days(self.history_retention), self.history_limit)
        except Exception as exc:
            _LOGGER.debug("Clean map history prune failed: %s", exc)
            return
        if removed:
            self._history_png.clear()

    async def async_set_history(self, retention: str | None = None, limit: int | None = None) -> None:
        """Change how long (and how many) clean maps are kept; applied at once."""
        if self.entry is None:
            return
        opts = dict(self.entry.options)
        if retention is not None:
            if retention not in cleanhistory.RETENTION_DAYS:
                raise ValueError(f"unknown retention {retention!r}")
            opts[OPT_HISTORY_KEEP] = retention
        if limit is not None:
            opts[OPT_HISTORY_LIMIT] = max(cleanhistory.MIN_LIMIT, min(cleanhistory.MAX_LIMIT, int(limit)))
        self.hass.config_entries.async_update_entry(self.entry, options=opts)
        await self._prune_history(force=True)
        self.async_update_listeners()

    async def async_history_list(self) -> dict:
        """Kept runs and the runs still on the robot, newest first, with the settings and the
        space used. A run that is only on the robot can still be drawn (read on demand)."""
        hist = self.history()
        kept = await self.hass.async_add_executor_job(hist.entries) if hist else []
        usage = await self.hass.async_add_executor_job(hist.usage) if hist else {"runs": 0, "bytes": 0}
        robot = {_ts(r): r for r in _records(self.settings.get("records")) if _ts(r)}
        runs = [{**m, "kept": True, "on_robot": m.get("started") in robot} for m in kept]
        seen = {m.get("started") for m in kept}
        runs += [{**decode_clean_record(r), "kept": False, "on_robot": True}
                 for ts, r in robot.items() if ts not in seen]
        runs.sort(key=lambda m: m.get("started") or 0, reverse=True)
        return {"runs": runs, "retention": self.history_retention, "limit": self.history_limit,
                "retention_options": list(cleanhistory.RETENTION_DAYS), "usage": usage}

    async def async_history_image(self, started: int) -> bytes:
        """One run's map as a PNG: from the kept copy if there is one, else read from the robot
        (and kept, if history is on). The last few drawn are held in memory."""
        started = int(started)
        hit = self._history_png.get(started)
        if hit and hit[1] == self.rotation_for(hit[0]):      # drawn this way round already
            self._history_png.move_to_end(started)
            return hit[2]
        hist = self.history()
        detail = await self.hass.async_add_executor_job(hist.get, started) if hist else None
        if detail is None:
            rec = next((r for r in _records(self.settings.get("records")) if _ts(r) == started), None)
            if rec is None:
                raise cleanhistory.HistoryError("that clean was not kept and the robot no longer has it")
            code = self.status_code
            if code in CLEANING_CODES or code in PAUSED_CODES or code == 4 or self.map_lock.locked():
                raise cleanhistory.HistoryError(f"{self.device_name} is busy; this clean was not kept, so its "
                                                "map is read from the robot once it is docked")
            detail = await self.hass.async_add_executor_job(
                self.client.get_clean_record_detail, rec.get("record_index", 0))
            await self._keep_run(rec, detail, auto=False)
        map_id = detail.get("map_id")
        rotation = self.rotation_for(map_id)
        png = await self.hass.async_add_executor_job(lambda: _png(render_record(detail, rotation)))
        self._history_png[started] = (map_id, rotation, png)
        while len(self._history_png) > 6:
            self._history_png.popitem(last=False)
        return png

    async def async_history_delete(self, started: int) -> bool:
        hist = self.history()
        self._history_png.pop(int(started), None)
        return bool(hist and await self.hass.async_add_executor_job(hist.delete, int(started)))

    def room_freshness_by_id(self) -> dict[int, dict]:
        """{room id: {last_cleaned, coverage}} for the current map (ids, unlike names, are unique)."""
        out = {}
        for key, v in self.rooms_last_cleaned.items():
            mid, _, rid = key.partition(":")
            if mid == str(self.map_id) and rid.isdigit():
                out[int(rid)] = {"last_cleaned": v.get("last_cleaned"), "coverage": v.get("coverage")}
        return out

    def room_freshness(self) -> dict[str, dict]:
        """{room name: {last_cleaned, coverage}} for the current map."""
        out = {}
        for key, v in self.rooms_last_cleaned.items():
            if key.startswith(f"{self.map_id}:"):
                out[v.get("name") or key] = {"last_cleaned": v.get("last_cleaned"), "coverage": v.get("coverage")}
        return out

    # ---- finishing a lost-map restore ----------------------------------------------------
    async def _robot_working(self) -> bool:
        """Ask the robot itself: the finish can start before this poll's status is stored
        (on the first poll after a restart there is none), and it must never switch maps
        under a robot that is cleaning or driving home."""
        try:
            code = await self.hass.async_add_executor_job(self.client._status)
        except Exception:
            return True
        return code in CLEANING_CODES or code in PAUSED_CODES or code == 4 or self._run_open()

    def _ask_reload(self, why: str, keys) -> None:
        """Entities are created once, at setup: reload the entry (once) so ones for
        settings or dock actions that only answered later get created."""
        if self._reload_asked or self.entry is None:
            return
        # Once per setting per Home Assistant run: a getter that answers only now and then must
        # not reload the entry every time it comes back, but a different one still gets its entity.
        seen = self.hass.data.setdefault(f"{DOMAIN}_reloaded", {}).setdefault(self.entry.entry_id, set())
        if not set(keys) - seen:
            return
        seen |= set(keys)
        self._reload_asked = True
        _LOGGER.info("%s: %s; reloading to add their entities", self.device_name, why)
        self.hass.config_entries.async_schedule_reload(self.entry.entry_id)

    def _note_setting_keys(self) -> None:
        # Only settings an entity is created for; others (records, clock...) add nothing.
        keys = {k for k, v in self.settings.items() if k in _ENTITY_SETTINGS and v not in (None, {}, [])}
        if self._setting_keys is None:
            if self.data is None:       # first read, during setup: what the platforms will see
                self._setting_keys = keys
            return
        if keys - self._setting_keys:
            self._ask_reload("settings that did not answer at setup now do", keys - self._setting_keys)

    def _note_rotation(self) -> None:
        """The rotation select is made at setup only: when the first map read failed or listed
        no maps, rotation is learnt later, so reload then to add it."""
        if self.data is None:       # setup: what the select platform will see
            self._rotation_at_setup = self.rotation_supported
        elif self.rotation_supported and not self._rotation_at_setup:
            self._ask_reload("the robot now reports map rotation", {"map_rotation"})

    async def _load_restore(self) -> None:
        if self._restore_loaded or self._restore_store is None:
            return
        self._restore_loaded = True
        try:
            stored = await self._restore_store.async_load() or {}
            self.pending_restore = stored.get("pending") or None
            self.snapshot_hold = {int(k): float(v) for k, v in (stored.get("hold") or {}).items()}
            self._prune_holds()
        except Exception as exc:
            _LOGGER.debug("Pending restore unreadable: %s", exc)

    def _save_restore(self) -> None:
        if self._restore_store is not None:
            self.hass.async_create_task(self._restore_store.async_save(
                {"pending": self.pending_restore, "hold": {str(k): v for k, v in self.snapshot_hold.items()}}))

    # A map restored over itself keeps its saved setup until apply_map_setup or save_map_setup
    # runs on it, or for this long at most.
    SNAPSHOT_HOLD_S = 7 * 86400

    def hold_snapshot(self, map_id: int) -> bool:
        """A backup is about to be restored over map_id: until apply_map_setup or save_map_setup
        runs on it, the polls must not replace its saved setup with the restored map's (which may
        lack zones or furniture the backup does not carry). False if it was already held.
        Kept across restarts."""
        if self.snapshot_held(map_id):
            return False
        self.snapshot_hold[map_id] = time.time()
        self._save_restore()
        return True

    def release_snapshot(self, map_id: int) -> None:
        """Let the polls keep map_id's saved setup in step again (from the next poll)."""
        if self.snapshot_hold.pop(map_id, None) is not None:
            self._snapshot_hash.pop(map_id, None)
            self._save_restore()

    def release_after_apply(self, map_id: int, snap: dict | None, result: dict | None) -> None:
        """Release map_id's hold once its own saved setup went back on in full (nothing skipped)."""
        if snap and result and snap.get("map_id") == map_id and not result.get("skipped"):
            self.release_snapshot(map_id)

    def _prune_holds(self) -> None:
        now = time.time()
        for map_id, since in list(self.snapshot_hold.items()):
            if now - since > self.SNAPSHOT_HOLD_S:
                self.release_snapshot(map_id)

    def snapshot_held(self, map_id: int) -> bool:
        self._prune_holds()
        return map_id in self.snapshot_hold

    # A restored map that has not shown up by then is not coming (longer than the backup stays
    # served after the service stops watching, plus time to apply it).
    RESTORE_GIVE_UP_S = 1800
    # A robot that still reads "applying" after this is stuck, not applying.
    RESTORE_APPLYING_S = 1800
    # A carrier that still cannot be put back after this is left (with a notification).
    RESTORE_ABANDON_S = 86400

    def expect_restore(self, map_id: int, name: str | None, carrier: int, before: dict | None = None,
                       tail: dict | None = None, copy: bool = False, carry: dict | None = None) -> None:
        """A backup is being restored onto a carrier map and comes back as a new, unsaved map.
        before is the carrier's rooms and furniture, which the robot overwrites with the
        backup's: put back (with the restored map saved and given the backup's names) as soon
        as the map shows up, by the service or, if it stopped watching, by a later poll; if the
        map never shows up, the carrier is still put back. A lost map is then finished once
        saved. carry: the presets (and schedules) a copy takes with it (mapsnapshot.carry_setup).
        Kept across restarts."""
        old = self.pending_restore
        if old and old.get("tidied", True) and not old.get("copy") and old.get("map_id") != map_id:
            _LOGGER.warning("%s: the restored map %s was never saved in the app, so its setup was not put "
                            "back; a new restore replaces that wait", self.device_name, old.get("map_id"))
        self.pending_restore = {"map_id": map_id, "name": name, "carrier": carrier, "before": before,
                                "tail": tail, "copy": copy, "tidied": before is None, "started": time.time(),
                                "done": {}}
        if carry and (carry.get("presets") or carry.get("schedules")):
            self.pending_restore["carry"] = carry
        self._last_tidy = None      # a tidy result never outlives the restore it belongs to
        self._save_restore()

    MAP_JOB_EVENT = f"{DOMAIN}_map_job"

    def map_job(self, job: str, stage: str, percent: float, *, done: bool = False, error: str | None = None) -> None:
        """Tell the sidebar page how a long map job (copy, restore) is getting on: a stage and
        0-100 overall. Fired on the event bus (admin pages subscribe; both jobs are admin only)."""
        from homeassistant.helpers import entity_registry as er
        entity_id = (er.async_get(self.hass).async_get_entity_id("vacuum", DOMAIN, f"{self.entry.entry_id}_vacuum")
                     if self.entry else None)
        self.hass.bus.async_fire(self.MAP_JOB_EVENT, {
            "entity_id": entity_id, "job": job, "stage": stage, "percent": max(0, min(100, round(percent))),
            "done": done, "error": error})

    def last_tidy(self, map_id: int) -> dict | None:
        """What the last tidy-up of the restore of map_id did (mapcopy.tidy's result), if any."""
        last = self._last_tidy
        return last["out"] if last and last["map_id"] == map_id else None

    def restore_unfinished(self) -> dict | None:
        """A restore whose carrier has not been put back yet. Copy, restore and delete wait for it;
        edits and apply_map_setup refuse only its carrier and restored map."""
        pend = self.pending_restore
        return pend if pend and not pend.get("tidied", True) else None

    def _drop_restore(self, pend: dict) -> None:
        """Clear the pending restore it finished, unless a newer restore replaced it meanwhile."""
        if self.pending_restore is pend:
            self.pending_restore = None
            self._save_restore()

    def _check_pending_restore(self) -> None:
        pend = self.pending_restore
        if not pend or self._finishing:
            return
        m = next((x for x in self.maps if x["id"] == pend["map_id"]), None)
        if not pend.get("tidied", True):
            given_up = m is None and (pend.get("failed")
                                      or time.time() - (pend.get("started") or 0) > self.RESTORE_GIVE_UP_S)
            if m is not None or given_up:
                self._finishing = True
                self._background(self._tidy_in_background(pend), "tidy restore")
            return
        if m is None:
            return
        if pend.get("copy"):
            self._drop_restore(pend)
        elif m.get("saved"):
            self._finishing = True
            self._background(self.async_finish_restore(), "finish restore")

    async def _tidy_in_background(self, pend: dict) -> None:
        from homeassistant.components import persistent_notification
        try:
            if self.map_busy or self.map_lock.locked() or await self._robot_working():
                return      # a later poll tries again, once docked
            async with self.map_lock:
                if self.pending_restore is not pend or pend.get("tidied", True):
                    return  # finished (or replaced) while this waited
                out = await self.async_tidy_restore(pend)
            if out is None or not pend.get("tidied"):
                return
            carrier = next((x["name"] for x in self.maps if x["id"] == pend["carrier"]), None) or f"map {pend['carrier']}"
            problems = f" Not everything went to plan: {'; '.join(out['errors'])}." if out["errors"] else ""
            if not pend["done"].get("finished"):
                msg, title = (f"The restore did not complete: the restored map never appeared. \"{carrier}\" "
                              f"was put back as it was.{problems}"), "map restore did not complete"
            elif pend.get("copy"):
                from .mapcopy import carried_text
                msg = (f"The copy \"{pend.get('name')}\" is saved{carried_text(out.get('carried'))}" if out["saved"] else
                       f"The copy came back as map {pend['map_id']} but is not saved; save it in the Tapo app")
                msg += f", and \"{carrier}\" was put back as it was.{problems}"
                title = "map copied"
            else:
                return      # a lost map: finished (and notified) once saved
            persistent_notification.async_create(self.hass, msg, title=f"{self.device_name}: {title}",
                                                 notification_id=f"{DOMAIN}_restore_{pend['map_id']}")
        finally:
            self._finishing = False

    async def async_tidy_restore(self, pend: dict) -> dict | None:
        """Run mapcopy.tidy for a pending restore (map lock held by the caller), unless the
        robot is still applying a backup (it may not have written to the carrier yet). Once the
        carrier is put back and the restored map has had its steps, or it is given up on, the
        restore is tidied; a copy, or a restore that never landed, is then done. Returns the
        tidy result, or None to try again on a later poll."""
        from . import mapcopy
        try:
            br = await self.hass.async_add_executor_job(self.client.get_map_br_process)
            age = time.time() - (pend.get("started") or 0)
            if _opt_int(br.get("type")) == 2 and _opt_int(br.get("status")) == 2 and age < self.RESTORE_APPLYING_S:
                return None
            out = await self.hass.async_add_executor_job(mapcopy.tidy, self.client, pend)
            self._last_tidy = {"map_id": pend.get("map_id"), "out": out}
        except Exception as exc:
            _LOGGER.warning("%s: tidying up after the restore of map %s failed (%s); trying again later",
                            self.device_name, pend.get("map_id"), exc)
            return None
        if out["errors"]:
            _LOGGER.warning("%s: after the restore of map %s: %s", self.device_name, pend.get("map_id"),
                            "; ".join(out["errors"]))
        if self.pending_restore is pend:
            landed = pend["done"].get("finished")
            given_up = not landed and (pend.get("failed")
                                       or time.time() - (pend.get("started") or 0) > self.RESTORE_GIVE_UP_S)
            if out["carrier_ok"] and (landed or given_up):
                pend["tidied"] = True
                pend.pop("before", None)
                if pend.get("copy") or given_up:
                    self._drop_restore(pend)
                else:
                    self._save_restore()
            elif time.time() - (pend.get("started") or 0) > self.RESTORE_ABANDON_S:
                # Never block map writes for good: tell the user what is left to do and stop.
                from homeassistant.components import persistent_notification
                persistent_notification.async_create(
                    self.hass, f"Home Assistant could not put map {pend['carrier']} back after the restore of map "
                    f"{pend['map_id']} ({'; '.join(out['errors']) or 'no answer'}). Its room names or furniture may "
                    "show the backup's: run apply_map_setup on it to put its own back.",
                    title=f"{self.device_name}: map restore not tidied up",
                    notification_id=f"{DOMAIN}_restore_{pend['map_id']}")
                self._drop_restore(pend)
            else:
                self._save_restore()    # keep what worked, so a retry only redoes the rest
        await self.async_request_map_refresh()
        return out

    async def async_finish_restore(self) -> dict | None:
        """Put the restored map's layers back from its saved setup, then tell the user."""
        from homeassistant.components import persistent_notification

        from . import setup_apply
        pend = self.pending_restore
        if not pend or not pend.get("tidied", True):
            self._finishing = False
            return None
        name = pend.get("name") or f"map {pend['map_id']}"
        carrier = next((x["name"] for x in self.maps if x["id"] == pend["carrier"]), None)
        result = None
        try:
            snap = await self.hass.async_add_executor_job(
                setup_apply.find_snapshot, setup_apply.snapshot_folders(self.hass, self), pend["map_id"], None)
            if snap is None:
                msg = (f"{name} is restored and saved. There was no saved map setup for it, so put room names "
                       "and zones back by hand.")
            elif self.map_busy or self.map_lock.locked() or await self._robot_working():
                return None   # try again on a later poll, once docked
            else:
                try:
                    result = await setup_apply.apply_setup(self.hass, self, pend["map_id"], snap)
                except setup_apply.MapBusy:
                    return None   # nothing written: another map write or a clean started meanwhile
                self.release_after_apply(pend["map_id"], snap, result)
                plan = result["plan"]
                done = [f"{len(plan['room_names'])} room names" if plan["room_names"] else "",
                        ", ".join(f"{v} {k.replace('_', ' ')}" for k, v in plan["zones"].items()),
                        f"{plan['furniture']} furniture" if plan["furniture"] else "",
                        ("presets: " + ", ".join(plan["presets"])) if plan["presets"] else "",
                        f"{len(plan['schedules'])} schedule(s)" if plan["schedules"] else ""]
                done = [d for d in done if d]
                msg = (f"{name} is restored. Put back: {'; '.join(done) or 'nothing was missing'}."
                       + (f" Skipped: {'; '.join(result['skipped'])}." if result.get("skipped") else ""))
            if carrier and pend["carrier"] != pend["map_id"]:
                msg += (f" \"{carrier}\" carried the restore and was put back as it was; "
                        "if it was only made for this, you can delete it now.")
            self._drop_restore(pend)
        except setup_apply.ApplyError as exc:
            msg = f"{name} is restored, but putting its setup back failed: {exc}. Run apply_map_setup to retry."
            self._drop_restore(pend)
        except Exception as exc:     # a read failed (robot busy or offline): still pending, try again later
            _LOGGER.warning("%s: finishing the restore of %s failed (%s); trying again later",
                            self.device_name, name, exc)
            return None
        finally:
            self._finishing = False
        persistent_notification.async_create(self.hass, msg, title=f"{self.device_name}: map restored",
                                             notification_id=f"{DOMAIN}_restore_{pend['map_id']}")
        return result

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
        recs = _records(self.settings.get("records"))
        if recs:
            self._last_record_ts = max(_ts(r) for r in recs)

    async def _read_records(self) -> None:
        """Re-read getCleanRecords into settings (kept as they were when the read fails)."""
        try:
            self.settings["records"] = await self.hass.async_add_executor_job(self.client.get_clean_records)
        except Exception as exc:
            _LOGGER.debug("Records fetch failed: %s", exc)

    def _new_record(self) -> dict | None:
        """The newest known record if it is newer than any seen (it then counts as seen)."""
        recs = _records(self.settings.get("records"))
        if not recs:
            return None
        newest = max(recs, key=_ts)
        ts = _ts(newest)
        if self._last_record_ts is not None and ts <= self._last_record_ts:
            return None
        self._last_record_ts = ts
        return decode_clean_record(newest)

    async def _fetch_new_record(self) -> dict | None:
        """The clean record the robot just wrote, if it is newer than any seen."""
        await self._read_records()
        return self._new_record()

    CAPS_ATTEMPTS = 5

    async def _fetch_capabilities(self, skip_unreachable: bool = True) -> bool:
        """Component list and which optional settings and dock actions answer. Read
        once, but a probe that ended in a transport error (the robot's Wi-Fi still
        waking after a Home Assistant restart, say) is inconclusive and is repeated on
        a later poll, up to CAPS_ATTEMPTS, so an entity is not missing until the next
        restart just because one request timed out. With skip_unreachable, returns False,
        without counting an attempt, when the robot does not answer the component list at
        all: probing an unreachable robot would only wait out a connect timeout per getter."""
        complete = True
        before_bool, before_dock = set(self.bool_settings_supported), set(self.dock_actions)
        try:
            self.components = await self.hass.async_add_executor_job(self.client.get_components)
        except AuthError as exc:
            raise ConfigEntryAuthFailed(str(exc)) from exc
        except Exception as exc:
            _LOGGER.debug("getComponentList failed: %s", exc)
            if skip_unreachable and _is_dropout(exc):
                return False
            complete = False
        try:
            probed, ok = await self.hass.async_add_executor_job(self.client.probe_bool_settings)
            complete = complete and ok
            # keep anything found on an earlier attempt
            merged = {**self.bool_settings, **probed}
            self.bool_settings_supported = list(merged)
            self.bool_settings = merged
        except Exception as exc:
            complete = False
            _LOGGER.debug("Settings probe failed: %s", exc)
        try:
            actions, ok = await self.hass.async_add_executor_job(self.client.probe_dock_actions)
            complete = complete and ok
            self.dock_actions = sorted(set(self.dock_actions) | set(actions))
        except Exception as exc:
            complete = False
            _LOGGER.debug("Dock probe failed: %s", exc)
        self._caps_attempts += 1
        found = (set(self.bool_settings_supported) - before_bool) | (set(self.dock_actions) - before_dock)
        if self.data is not None and found:     # entities already set up without these
            self._ask_reload("a later capability probe found more settings or dock actions", found)
        if complete or self._caps_attempts >= self.CAPS_ATTEMPTS:
            if not complete:
                _LOGGER.info("%s: capability probe still inconclusive after %d attempts; "
                             "using what answered (restart to probe again)", self.device_name, self._caps_attempts)
            self._caps_fetched = True
        else:
            _LOGGER.debug("%s: capability probe inconclusive, trying again next poll", self.device_name)
        return True

    async def _refresh_settings(self) -> None:
        # A getter that failed this time is simply missing from the reply: keep its last
        # value rather than dropping it (Do Not Disturb going missing let the planner start).
        new = await self.hass.async_add_executor_job(self.client.get_settings)
        self.settings = {**self.settings, **new}
        self.settings_read_at = time.time()
        fw = (self.settings.get("device") or {}).get("fw_ver")
        if fw:
            self.fw_version = fw
        region = (self.settings.get("clock") or {}).get("region")
        if region and region != self._robot_region:
            self._robot_region = region
            try:
                self._robot_tz = await dt_util.async_get_time_zone(region)
            except (ValueError, TypeError) as exc:     # a name zoneinfo rejects outright
                _LOGGER.debug("Robot time zone %r not usable: %s", region, exc)
                self._robot_tz = None
        self._note_setting_keys()
        other_maps = await self.hass.async_add_executor_job(self._schedule_map_names)
        self._decode_schedules(other_maps)
        if self._last_record_ts is None:
            self._note_latest_record()
        if self.bool_settings_supported:
            started = time.monotonic()
            read = await self.hass.async_add_executor_job(self.client.get_bool_settings, self.bool_settings_supported)
            # A switch flipped while this read was under way: the read may predate it.
            read = {k: v for k, v in read.items() if self._bool_written.get(k, 0) < started}
            self.bool_settings = {**self.bool_settings, **read}
        try:
            self.presets = await self.hass.async_add_executor_job(self._read_presets)
            self.presets_read = True
        except Exception as exc:
            _LOGGER.debug("Preset read failed: %s", exc)

    def _read_presets(self) -> list[dict]:
        self._presets_raw = None
        rules = self.client.get_presets()
        if not rules:
            self._presets_raw = []
            return []
        names = self.map_names()
        out, raw, complete = [], [], True
        for rule in rules:
            if not isinstance(rule, dict) or rule.get("rule_id") is None:
                continue
            map_id = rule.get("map_id")
            try:
                detail = self.client.get_preset_detail(map_id, rule["rule_id"])
                raw.append({**detail, "rule_id": rule["rule_id"], "map_id": map_id})
            except Exception as exc:
                _LOGGER.debug("Preset %s detail failed: %s", rule.get("rule_id"), exc)
                detail = None
                # Only this map's presets go into its setup snapshot; another map's preset
                # failing to read must not stop that snapshot.
                if map_id == self.map_id:
                    complete = False
            room_names = ({r["id"]: b64name(r.get("name", "")) for r in self.rooms}
                          if map_id == self.map_id else self._room_names_for(map_id))
            out.append(decode_preset(rule, detail, room_names, names.get(map_id)))
        self._presets_raw = raw if complete else None
        return out

    async def _auto_snapshot(self) -> None:
        # A poll and a settings write can both get here; one snapshot write at a time.
        async with self._snapshot_lock:
            await self._auto_snapshot_now()

    async def _auto_snapshot_now(self) -> None:
        """Keep config/tapo_rv30/map_setups/<map_id>.json in step with the map's layers,
        presets and schedules, from data already polled (no extra robot calls). A snapshot that
        looks like a lost or freshly restored map (no rooms, or fewer named rooms) never
        replaces a good one, nor does any while a restore over the map holds it (hold_snapshot);
        every distinct snapshot is also kept in map_setups/history."""
        layers = self._map_layers
        if not layers or self._presets_raw is None or layers.get("map_id") != self.map_id:
            return
        pend = self.pending_restore
        if pend and (pend.get("map_id") == layers.get("map_id")
                     or (not pend.get("tidied", True) and pend.get("carrier") == layers.get("map_id"))):
            return      # the restored map, or the map it was restored onto, is still being finished
        rules = (self.settings.get("schedules") or {}).get("rule_list")
        if rules is None:
            return
        snap = mapsnapshot.build(layers["map_id"], layers.get("map_name"), layers["area_list"],
                                 layers["furniture_list"], self._presets_raw, rules,
                                 time.strftime("%Y-%m-%dT%H:%M:%S"))
        digest = mapsnapshot.content_hash(snap)
        if self._snapshot_hash.get(snap["map_id"]) == digest:
            return
        from . import setup_apply
        folder = setup_apply.snapshots_folder(self.hass, self)
        # Restored over itself: history only, until apply_map_setup or save_map_setup.
        held = self.snapshot_held(snap["map_id"])

        def _write() -> str:
            import json
            import os
            os.makedirs(os.path.join(folder, "history"), exist_ok=True)
            latest = os.path.join(folder, f"{snap['map_id']}.json")
            old = None
            # Before 0.28 setups lived in the shared folder; that copy still guards against
            # a degraded snapshot replacing a good one.
            for path in (latest, os.path.join(os.path.dirname(folder), f"{snap['map_id']}.json")):
                if old is None and os.path.exists(path):
                    try:
                        with open(path) as fh:
                            old = json.load(fh)
                    except (OSError, ValueError):
                        old = None
            if old is not None and mapsnapshot.content_hash(old) == digest:
                return "unchanged"
            stamp = time.strftime("%Y%m%d-%H%M%S")
            with open(os.path.join(folder, "history", f"{snap['map_id']}_{stamp}.json"), "w") as fh:
                json.dump(snap, fh)
            hist = sorted(f for f in os.listdir(os.path.join(folder, "history"))
                          if f.startswith(f"{snap['map_id']}_"))
            for f in hist[:-30]:
                os.remove(os.path.join(folder, "history", f))
            if held:
                return "held"
            if mapsnapshot.is_degraded(old, snap):
                return "degraded"
            setup_apply.write_json(latest, snap)
            return "written"

        try:
            outcome = await self.hass.async_add_executor_job(_write)
        except OSError as exc:
            _LOGGER.debug("Map snapshot not written: %s", exc)
            return
        self._snapshot_hash[snap["map_id"]] = digest
        if outcome == "degraded":
            _LOGGER.warning("%s: map %s looks degraded (rooms missing or unnamed); kept the previous "
                            "map setup snapshot. Run apply_map_setup to put the layers back.",
                            self.device_name, snap["map_id"])

    def _room_names_for(self, map_id: int) -> dict[int, str]:
        if map_id not in self._room_name_cache:
            try:
                md = self.client.get_map_data(map_id)
                self._room_name_cache[map_id] = {a["id"]: b64name(a.get("name", ""))
                                                 for a in md.get("area_list", []) if a.get("type") == "room"}
            except Exception:
                return {}
        return self._room_name_cache[map_id]

    def find_preset(self, ref, map_id: int | None = None) -> dict | None:
        """Preset by id, or by name (accent-insensitive, exact then partial); only on map_id when
        given (the robot keeps presets per map, so an id or name can be on more than one).
        A number (6 or "6") that is no preset's id matches a name only exactly: a preset made in
        the app since the last read must not land on an older one called "Kids 6+"."""
        presets = [p for p in self.presets if map_id is None or p["map_id"] == map_id]
        rid = preset_ref_id(ref)
        if rid is not None:
            hits = [p for p in presets if p["id"] == rid]
            if hits:
                return hits[0] if len(hits) == 1 else None     # on two maps: say which
        wanted = fold(str(ref).strip())
        exact = [p for p in presets if fold(p["name"]) == wanted]
        partial = [p for p in presets if wanted and wanted in fold(p["name"])] if rid is None else []
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
            except WrongDevice as exc:
                # Another robot at this address: retrying will not change that, and it is not
                # the robot dropping out, so no "unreachable" repair either.
                raise UpdateFailed(str(exc)) from exc
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
                learn_more_url="https://github.com/epg-pers/tapo-rv30-ha#two-things-to-know",
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
        self._background(_poll(), "refresh soon")

    def _background(self, coro, name: str) -> None:
        """A follow-up task tied to the config entry, so unloading cancels it instead of
        letting it poll a closed client."""
        if self.entry is not None:
            self.entry.async_create_background_task(self.hass, coro, f"{DOMAIN} {name}")
        else:
            self.hass.async_create_task(coro)

    @callback
    def set_bool_setting_local(self, key: str, value: bool) -> None:
        """Reflect a successful write immediately, before the re-read confirms it."""
        self.bool_settings[key] = value
        self._bool_written[key] = time.monotonic()
        if self.data is not None:
            self.data["bool_settings"] = self.bool_settings
        self.async_update_listeners()

    async def async_settings_changed_later(self, delay: float = 2.0) -> None:
        async def _later() -> None:
            await asyncio.sleep(delay)
            await self.async_settings_changed()
        self._background(_later(), "settings re-read")

    async def async_settings_changed(self) -> None:
        """Re-read settings right after a write so switches don't wait for the slow cycle."""
        try:
            await self._refresh_settings()
        except Exception as exc:    # the write itself worked; the next full read catches up
            _LOGGER.debug("Settings re-read after a write failed: %s", exc)
            return
        if self.data is not None:
            self.data["settings"] = self.settings
            self.data["schedules"] = self.schedules
            self.data["bool_settings"] = self.bool_settings
            self.data["presets"] = self.presets
        self.async_update_listeners()
        # A preset or schedule just changed: the map's setup snapshot follows now, not next cycle.
        try:
            await self._auto_snapshot()
        except Exception as exc:
            _LOGGER.debug("Map snapshot after a settings change failed: %s", exc)

    def _schedule_map_names(self) -> dict[int, dict[int, str]]:
        """Room names of the other maps schedules point at (blocking, cached per map)."""
        rules = (self.settings.get("schedules") or {}).get("rule_list") or []
        maps = {(r.get("clean_attr") or {}).get("map_id") for r in rules} - {None, self.map_id}
        return {m: self._room_names_for(m) for m in maps}

    def _decode_schedules(self, other_maps: dict[int, dict[int, str]] | None = None) -> None:
        """Each schedule's rooms are named from the map it cleans, not the active one."""
        current = {r["id"]: b64name(r.get("name", "")) for r in self.rooms}
        rules = (self.settings.get("schedules") or {}).get("rule_list") or []
        self.schedules = [
            decode_schedule(r, (other_maps or {}).get((r.get("clean_attr") or {}).get("map_id"), current),
                            self.settings.get("dnd"))
            for r in rules]

    # ---- map ---------------------------------------------------------------------
    def _refresh_position(self) -> None:
        map_data = self.client.get_map_data(self.map_id)
        self._apply_position(map_data)

    def _apply_position(self, map_data: dict) -> None:
        self.vac_pos = map_data.get("real_vac_coor")
        self.current_room = room_at_vac(map_data)
        self._update_path(map_data)
        if self._map_base is not None:
            # Docked, nothing moves: drawing and encoding the same frame every poll is wasted CPU.
            vac = map_data.get("real_vac_coor")
            path = self.shown_path()
            key = (id(self._map_base), tuple(vac or ()), len(path))
            if key == self._frame_key and self.map_image_bytes is not None:
                return
            self._frame_key = key
            img = self._map_base.copy()
            draw = ImageDraw.Draw(img)
            # In the frame of the map the base image was drawn from: the robot's grid size and
            # origin change from one read to the next, and this poll's would put the dot elsewhere.
            to_px = _px_transform(self._live_map or map_data, self.map_rotation)
            if len(path) > 1:
                draw.line([to_px(x, y) for x, y in path], fill=(0, 140, 220, 200), width=2, joint="curve")
            if vac and len(vac) >= 2:
                _dot(draw, *map(int, to_px(vac[0], vac[1])), (0, 180, 255))
            self.map_image_bytes = _png(img, fast=True)

    def _update_path(self, map_data: dict) -> None:
        """Read the run's path while the robot is active (new path_id = new run)."""
        path_id = map_data.get("path_id")
        code = self.status_code
        active = code in CLEANING_CODES or code in PAUSED_CODES or code == 4
        if path_id is None or not active:
            return
        # Tagged with the map the position data came from. A run started from the app or a schedule
        # can be on a map not read yet, so a new run reads the map on the next poll, and the trail
        # is tagged again then.
        if path_id != self._path_id:
            self._path_id = path_id
            self.path_points = []
            self._path_map_id = self.map_id
            self._map_read_at = None
        try:
            r = self.client.get_path(path_id, 0)
            if r.get("pos_array") and r.get("pos_len"):
                self.path_points = decode_path(r["pos_array"], int(r["pos_len"]))
                self._path_map_id = self.map_id
        except Exception as exc:
            _LOGGER.debug("Path fetch failed: %s", exc)

    def shown_path(self) -> list[tuple[int, int]]:
        """The last run's trail, only while its own map is the current one. Kept rather than
        cleared on a map switch: map edits and copies switch away and back, and the trail is
        still right when they do."""
        return self.path_points if self._path_map_id == self.map_id else []

    async def async_request_map_refresh(self) -> None:
        """Re-render the map on the next poll (after set_map)."""
        self._map_read_at = None
        await self.async_refresh_soon()

    def _refresh_map(self) -> None:
        current_id, map_list = self.client.get_map_info()
        self._room_name_cache = {}      # names may have changed in the app
        if any("map_locked" in m for m in map_list) and self.has("map_lock"):
            self.lock_supported = True
        maps = [{"id": m["map_id"], "name": b64name(m.get("map_name", "")), "current": m["map_id"] == current_id,
                 "saved": m.get("is_saved", True) is not False,
                 "rotation": rotation_of(m.get("rotate_angle")),
                 # map_locked: 1 locked in the app (or here), 2 locked by the robot itself
                 **({"locked": _opt_int(m.get("map_locked")) in (1, 2),
                     "auto_locked": _opt_int(m.get("map_locked")) == 2} if self.lock_supported else {})}
                for m in map_list]
        if any("rotate_angle" in m for m in map_list):
            self.rotation_supported = True
        if map_list:        # an empty list (no map yet) says nothing about rotation
            self.rotation_known = True
        rotation = next((m["rotation"] for m in maps if m["id"] == current_id), 0)
        # Nothing is published until the map is redrawn: a refused map read (routine while the
        # robot manoeuvres) must not leave a new angle showing over the old picture.
        map_data = self.client.get_map_data(current_id)
        self._map_base, self.room_geometry, self.map_geometry = render_map(map_data, rotation)
        last_map = self.last_clean_info.get("map_id")
        if next((m["rotation"] for m in maps if m["id"] == last_map), 0) != self.rotation_for(last_map):
            self._record_rendered_ts = None     # redraw the last clean turned the new way
        self.maps, self.map_rotation = maps, rotation
        self.map_id = current_id
        self.map_name = b64name(map_data.get("map_name", ""))
        self.rooms = [a for a in map_data.get("area_list", []) if a.get("type") == "room"]
        self._map_layers = {"map_id": current_id, "map_name": self.map_name,
                            "area_list": list(map_data.get("area_list") or []),
                            "furniture_list": list(map_data.get("furniture_list") or [])}
        self._live_map = {k: map_data.get(k) for k in ("width", "height", "pix_len", "map_data", "resolution", "real_origin_coor", "area_list", "map_id")}
        try:
            self._live_pixels = grid_pixels(map_data)
        except Exception:
            self._live_pixels = None
        self.room_mask = room_mask_png(map_data, self.map_rotation)
        # The rotation is part of it, so the card fetches the turned mask instead of a cached one.
        self.map_hash = f"{map_data.get('map_hash') or len(self.room_mask)}-{self.map_rotation}"
        self._apply_position(map_data)
        _LOGGER.debug("Map rendered: %d bytes, %d rooms", len(self.map_image_bytes or b""), len(self.rooms))

    async def async_set_map_rotation(self, map_id: int, rotation: int) -> None:
        """Turn a map's display on the robot (rotate_angle), so the Tapo app and Home Assistant
        agree. Display only: nothing on the map itself changes."""
        if rotation not in (0, 90, 180, 270):
            raise ValueError(f"rotation must be 0, 90, 180 or 270, not {rotation!r}")
        if self.map_lock.locked():
            raise ValueError("its map is being written; try again shortly")
        if self.status_code in (2, 10):
            raise ValueError("it is building a map; turn it once the map is saved")
        async with self.map_lock:
            # From a fresh read: the map must be on the robot and saved (a map still being built
            # is not touched), and the robot must report the new angle back.
            _, map_list = await self.hass.async_add_executor_job(self.client.get_map_info)
            entry = next((m for m in map_list if m.get("map_id") == int(map_id)), None)
            if entry is None:
                raise ValueError(f"map {map_id} is not on the robot")
            if entry.get("is_saved") is not True:
                raise ValueError("that map is not saved yet; save it in the Tapo app first")
            await self.hass.async_add_executor_job(self.client.set_map_rotation, int(map_id), int(rotation))
            try:
                _, after = await self.hass.async_add_executor_job(self.client.get_map_info)
            finally:
                await self.async_request_map_refresh()
        got = next((m.get("rotate_angle") for m in after if m.get("map_id") == int(map_id)), None)
        if rotation_of(got) != rotation:
            raise ValueError(f"the robot accepted the rotation but still reports {got}")

    async def async_set_map_locked(self, map_id: int, locked: bool) -> None:
        """Lock or unlock a map on the robot. Locked, the robot keeps the map as it is instead of
        updating it from later cleans; the editable layers can still be changed."""
        if self.map_lock.locked():
            raise ValueError("its map is being written; try again shortly")
        async with self.map_lock:
            _, map_list = await self.hass.async_add_executor_job(self.client.get_map_info)
            entry = next((m for m in map_list if m.get("map_id") == int(map_id)), None)
            if entry is None:
                raise ValueError(f"map {map_id} is not on the robot")
            if entry.get("is_saved") is not True:
                raise ValueError("that map is not saved yet; save it in the Tapo app first")
            await self.hass.async_add_executor_job(self.client.set_map_locked, int(map_id), bool(locked))
            try:
                _, after = await self.hass.async_add_executor_job(self.client.get_map_info)
            finally:
                await self.async_request_map_refresh()
        got = next((_opt_int(m.get("map_locked")) for m in after if m.get("map_id") == int(map_id)), None)
        if (got in (1, 2)) != bool(locked):
            raise ValueError(f"the robot accepted the change but still reports map_locked {got}")

    async def async_set_room_directions(self, map_id: int, room_ids: list[int], direction: str) -> list[dict]:
        """Set the cleaning direction (default, horizontal, vertical as the map is shown here) of
        rooms on a saved map, the editor's way: every room written back as just read, with only
        their floor_texture changed. Returns each room with its old and new direction; ValueError
        when refused before anything was written."""
        if not self.clean_direction_supported:
            raise ValueError("has no per-room cleaning direction")
        direction_texture(direction)        # a bad name is refused before anything else
        if why := self.map_busy:
            raise ValueError(f"is {why}; change the map once it is docked and idle")
        if self.map_lock.locked():
            raise ValueError("is having its map written; try again shortly")
        async with self.map_lock:
            # As the editor: tidying a restore writes the carrier (and the restored map) back.
            if (pend := self.restore_unfinished()) is not None and map_id in (pend.get("carrier"), pend.get("map_id")):
                raise ValueError("has this map in a restore that is still being tidied up; try again once "
                                 "the restore has finished")
            _, map_list = await self.hass.async_add_executor_job(self.client.get_map_info)
            entry = next((m for m in map_list if m.get("map_id") == int(map_id)), None)
            if entry is None:
                raise ValueError(f"has no map {map_id}")
            if entry.get("is_saved") is not True:
                raise ValueError("has not saved that map yet; save it in the Tapo app first")
            if await self._robot_working():
                raise ValueError("is working; change the map once it is docked and idle")
            # Horizontal and vertical as the map is shown, from the angle just read.
            turn = rotation_of(entry.get("rotate_angle"))
            texture = direction_texture(direction, turn)
            data = await self.hass.async_add_executor_job(self.client.get_map_data, int(map_id))
            rooms = {a.get("id"): a for a in data.get("area_list") or [] if a.get("type") == "room"}
            if not rooms:
                raise ValueError("returned no rooms for that map, so nothing was written; try again")
            if missing := [r for r in room_ids if r not in rooms]:
                raise ValueError(f"has no room {missing} on that map")
            areas = room_areas(data.get("area_list"), {r: {"floor_texture": texture} for r in room_ids})
            out = [{"id": r, "name": b64name(rooms[r].get("name", "")),
                    "old": texture_direction(rooms[r].get("floor_texture"), turn), "new": str(direction).strip().lower(),
                    "old_floor_texture": rooms[r].get("floor_texture"), "floor_texture": texture} for r in room_ids]
            try:
                if any(o["old_floor_texture"] != texture for o in out):
                    code = await self.hass.async_add_executor_job(self.client.set_areas, int(map_id), "room", areas)
                    if code:
                        raise RuntimeError(f"the robot refused the change (error {code})")
                    after = await self.hass.async_add_executor_job(self.client.get_map_data, int(map_id))
                    now = {a.get("id"): a for a in after.get("area_list") or [] if a.get("type") == "room"}
                    if wrong := [r for r in room_ids if (now.get(r) or {}).get("floor_texture") != texture]:
                        raise RuntimeError(f"the robot accepted the change but rooms {wrong} still have their "
                                           "old direction")
                    # Nothing else may have moved: the same rooms, names and colours as before.
                    keys = ("name", "color")
                    if set(now) != set(rooms) or any(
                            [now[r].get(k) for k in keys] != [rooms[r].get(k) for k in keys] for r in rooms):
                        raise RuntimeError("the robot took the change but now reports different rooms, names or "
                                           "colours than before; check the map in the Tapo app (run "
                                           "tapo_rv30.apply_map_setup to put the saved setup back)")
            finally:
                await self.async_request_map_refresh()
        return out

    def rotation_for(self, map_id) -> int:
        """A map's rotate_angle as last read (0 for a map not on the robot any more)."""
        return next((m.get("rotation", 0) for m in self.maps if m.get("id") == map_id), 0)

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

    def segment_index(self) -> tuple[int, dict[int, set[int]], dict[int, str]]:
        """(active map id, {map_id: room ids}, {map_id: name}) read live, for clean_area."""
        current_id, map_list = self.client.get_map_info()
        known, names = {}, {}
        for m in map_list:
            map_id = m["map_id"]
            names[map_id] = b64name(m.get("map_name", ""))
            try:
                data = self.client.get_map_data(map_id)
            except Exception as exc:
                # One unreadable map (the robot refuses reads while moving) must not stop a
                # clean of rooms on another; its rooms are simply not offered this time.
                if map_id == current_id:
                    raise
                _LOGGER.debug("Map %s unreadable for clean_area: %s", map_id, exc)
                continue
            known[map_id] = {a["id"] for a in data.get("area_list", []) if a.get("type") == "room"}
        return current_id, known, names

    def resolve_rooms_live(
        self, name_patterns: list[str], map_name: str | None = None,
        map_id: int | None = None, room_ids: list[int] | None = None,
    ) -> tuple[list[int], int]:
        """Resolve room names (or check room ids) against the vacuum's live maps ->
        (room_ids, map_id)."""
        current_map_id, map_list = self.client.get_map_info()
        return resolve_rooms(current_map_id, map_list, self.client.get_map_data,
                             name_patterns, map_name, map_id, room_ids)
