"""Smart cleaning planner: the decisions, with no Home Assistant imports.

planner.py gathers a Snapshot of the house and the robot each minute (or when something it
watches changes) and asks decide() what to do. Everything here is plain data in, plain data
out, so every rule has a unit test.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta

DAY = 86400.0
DAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
TARGET_CHOICES = (0, 1, 2, 3, 4, 5, 7, 14)          # 0 = leave this room out

_TIME = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")


class PlannerError(Exception):
    """A planner request that cannot be done (shown to the user as is)."""


DEFAULT_CONFIG: dict = {
    "enabled": False,            # off until the user turns it on
    "preview": True,             # log what it would do, never start the robot
    "default_target_days": 2,
    "rooms": {},                 # "map_id:room_id" -> {target_days, add_sensors, remove_sensors, ignore_occupancy}
    "windows": {"weekdays": ["09:00", "17:00"], "weekends": ["10:00", "16:00"]},
    "require_away": True,
    "people": None,              # None = every person entity; else the chosen ones
    "skip_in_use": True,
    "clear_minutes": 10,         # a motion sensor counts as in use until it has been off this long
    "min_battery": 40,
    "avoid_schedules": True,     # hold off when one of the robot's own schedules starts within the hour
    "on_return": "finish_room",  # someone comes home mid-run: "finish_room" (then dock) or "keep_going"
}


def merged_config(stored: dict | None) -> dict:
    """Stored config over the defaults, nested dicts merged one level deep."""
    cfg = {k: (dict(v) if isinstance(v, dict) else v) for k, v in DEFAULT_CONFIG.items()}
    for key, value in (stored or {}).items():
        if key in cfg and isinstance(cfg[key], dict) and isinstance(value, dict):
            cfg[key].update(value)
        elif key in cfg:
            cfg[key] = value
    return cfg


def hhmm(value: str) -> int:
    h, m = str(value).split(":")[:2]
    return int(h) * 60 + int(m)


def fmt_hhmm(minutes: int) -> str:
    return f"{minutes // 60 % 24:02d}:{minutes % 60:02d}"


def room_target(cfg: dict, key: str) -> int:
    return int((cfg["rooms"].get(key) or {}).get("target_days", cfg["default_target_days"]))


def room_score(last_cleaned: float | None, target_days: int, now_ts: float) -> float | None:
    """Days since cleaned divided by the target; 1 or more means due. None = left out."""
    if not target_days:
        return None
    if not last_cleaned:
        return 99.0                      # never cleaned since the map was made
    return max(0.0, (now_ts - last_cleaned) / DAY) / target_days


def room_status(last_cleaned: float | None, target_days: int, now_ts: float) -> str:
    if not target_days:
        return "Left out"
    if not last_cleaned:
        return "Overdue"
    since = max(0.0, (now_ts - last_cleaned) / DAY)
    if since >= target_days:
        return "Overdue" if since - target_days >= 1 else "Due today"
    if since < 1:
        return "Fresh"
    left = math.ceil(target_days - since)
    return "In 1 day" if left == 1 else f"In {left} days"


def due_chip(name: str, last_cleaned: float | None, target_days: int, now_ts: float) -> str:
    if not last_cleaned:
        return f"{name} not cleaned yet"
    over = (now_ts - last_cleaned) / DAY - target_days
    if over >= 1:
        n = int(over)
        return f"{name} {n} day{'s' if n != 1 else ''} overdue"
    return f"{name} due today"


def window_for(day: datetime, cfg: dict) -> tuple[int, int]:
    kind = "weekends" if day.weekday() >= 5 else "weekdays"
    start, end = cfg["windows"][kind]
    return hhmm(start), hhmm(end)


def in_window(now: datetime, cfg: dict) -> bool:
    start, end = window_for(now, cfg)
    m = now.hour * 60 + now.minute
    return start <= m < end if start < end else False


def next_window_start(now: datetime, cfg: dict) -> datetime:
    """The next time a window opens (today if it has not opened yet, else a later day)."""
    for offset in range(8):
        day = now + timedelta(days=offset)
        start, end = window_for(day, cfg)
        if start >= end:
            continue
        opens = day.replace(hour=start // 60, minute=start % 60, second=0, microsecond=0)
        if opens > now:
            return opens
    return now + timedelta(days=1)


def window_key(now: datetime) -> str:
    """One run per window: the window is identified by its date."""
    return now.strftime("%Y-%m-%d")


def schedule_soon(now: datetime, schedules: list[dict], minutes: int = 60) -> dict | None:
    """An enabled robot schedule starting within `minutes` (that the robot will really run),
    including one just after midnight. now is the robot's own local time."""
    m_now = now.hour * 60 + now.minute
    today, tomorrow = DAYS[now.weekday()], DAYS[(now.weekday() + 1) % 7]
    for s in schedules or []:
        if not s.get("enabled") or s.get("blocked_by_dnd"):
            continue
        try:
            start = hhmm(s.get("time", ""))
        except (ValueError, AttributeError):
            continue
        days = s.get("days") or []
        if (today in days and 0 <= start - m_now <= minutes) or \
                (tomorrow in days and 0 <= start + 1440 - m_now <= minutes):
            return s
    return None


def dnd_until(dnd: dict | None, now: datetime) -> str | None:
    """The end time of the robot's Do Not Disturb if it covers now, else None."""
    if not dnd or not dnd.get("do_not_disturb"):
        return None
    start, end = int(dnd.get("s_min", 0)), int(dnd.get("e_min", 0))
    m = now.hour * 60 + now.minute
    inside = (start == end) or (start <= m < end if start < end else (m >= start or m < end))
    return fmt_hhmm(end) if inside else None


def sensors_in_use(readings: list[tuple[str, bool, float | None]], now_ts: float,
                   clear_minutes: int) -> list[str]:
    """Names of the sensors that make a room in use: on now, or off for less than clear_minutes.
    readings: (name, is_on, last_changed_ts)."""
    out = []
    for name, is_on, changed in readings:
        if is_on or (changed is not None and now_ts - changed < clear_minutes * 60):
            out.append(name)
    return out


@dataclass
class RoomState:
    key: str
    name: str
    last_cleaned: float | None
    target_days: int
    in_use_by: list[str] = field(default_factory=list)
    skipped_today: bool = False


@dataclass
class Snapshot:
    now: datetime
    robot_docked: bool
    robot_busy: str | None
    robot_error: bool
    battery: int | None
    dnd: dict | None
    people_home: list[str]
    schedules: list[dict]
    skip_today: bool
    ran_window: str | None
    rooms: list[RoomState]
    robot_now: datetime | None = None    # the robot's own clock (its region); DND and schedules use it


@dataclass
class Decision:
    action: str                       # "clean", "wait" or "idle"
    status: str                       # one line for the page and the sensor
    rooms: list[str] = field(default_factory=list)      # room keys, most overdue first
    names: list[str] = field(default_factory=list)
    chips: list[str] = field(default_factory=list)       # why these rooms
    waiting_for: str | None = None    # short code: off, nothing_due, skipped, window, ran, busy, error, dnd, battery, people, schedule, in_use


def _names(names: list[str]) -> str:
    return names[0] if len(names) == 1 else ", ".join(names[:-1]) + " and " + names[-1]


def decide(snap: Snapshot, cfg: dict) -> Decision:
    if not cfg.get("enabled"):
        return Decision("idle", "Planner is off", waiting_for="off")
    now_ts = snap.now.timestamp()
    scored = []
    for r in snap.rooms:
        score = room_score(r.last_cleaned, r.target_days, now_ts)
        if score is not None and score >= 1 and not r.skipped_today:
            scored.append((score, r))
    scored.sort(key=lambda t: -t[0])
    due = [r for _, r in scored]
    chips = [due_chip(r.name, r.last_cleaned, r.target_days, now_ts) for r in due]
    keys, names = [r.key for r in due], [r.name for r in due]

    def wait(status: str, code: str) -> Decision:
        return Decision("wait", status, keys, names, chips, code)

    if not due:
        return Decision("idle", "Nothing is due", waiting_for="nothing_due")
    if snap.skip_today:
        return wait("Skipped for today", "skipped")
    if not in_window(snap.now, cfg):
        opens = next_window_start(snap.now, cfg)
        when = opens.strftime("%H:%M") if opens.date() == snap.now.date() else opens.strftime("%a %H:%M")
        return wait(f"Waiting for the cleaning window at {when}", "window")
    if snap.ran_window == window_key(snap.now):
        return wait("Already cleaned in today's window", "ran")
    if snap.robot_error:
        return wait("The robot reports a problem", "error")
    if snap.robot_busy or not snap.robot_docked:
        return wait("The robot is busy", "busy")
    until = dnd_until(snap.dnd, snap.robot_now or snap.now)
    if until:
        return wait(f"Do Not Disturb until {until}", "dnd")
    if snap.battery is not None and snap.battery < int(cfg.get("min_battery", 0)):
        return wait(f"Battery at {snap.battery}%, waiting for {cfg['min_battery']}%", "battery")
    if cfg.get("require_away") and snap.people_home:
        n = len(snap.people_home)
        return wait(f"Waiting: {_names(snap.people_home)} {'is' if n == 1 else 'are'} home", "people")
    if cfg.get("avoid_schedules"):
        soon = schedule_soon(snap.robot_now or snap.now, snap.schedules)
        if soon:
            return wait(f"A schedule on the robot runs at {soon.get('time')}", "schedule")
    if cfg.get("skip_in_use"):
        free = [r for r in due if not r.in_use_by]
        if not free:
            busy = "; ".join(f"{r.name} ({', '.join(r.in_use_by)})" for r in due)
            return wait(f"Due rooms are in use: {busy}", "in_use")
        due = free
    names = [r.name for r in due]
    verb = "Would clean" if cfg.get("preview") else "Cleaning"
    return Decision("clean", f"{verb} {_names(names)}", [r.key for r in due], names, chips)


def validate_changes(changes: dict, current: dict) -> dict:
    """Check a partial config from the page; unknown keys and bad values are refused."""
    out: dict = {}
    for key, value in (changes or {}).items():
        if key not in DEFAULT_CONFIG:
            raise PlannerError(f"Unknown planner setting '{key}'")
        if key in ("enabled", "preview", "require_away", "skip_in_use", "avoid_schedules"):
            out[key] = bool(value)
        elif key == "default_target_days":
            if int(value) not in TARGET_CHOICES:
                raise PlannerError("Pick a target from the list")
            out[key] = int(value)
        elif key == "min_battery":
            out[key] = max(0, min(100, int(value)))
        elif key == "clear_minutes":
            out[key] = max(0, min(240, int(value)))
        elif key == "on_return":
            if value not in ("finish_room", "keep_going"):
                raise PlannerError("on_return must be finish_room or keep_going")
            out[key] = value
        elif key == "people":
            out[key] = None if value is None else [str(v) for v in value if str(v).startswith("person.")]
        elif key == "windows":
            windows = dict(current["windows"])
            for kind, pair in (value or {}).items():
                if kind not in ("weekdays", "weekends") or len(pair) != 2 or not all(_TIME.match(str(t)) for t in pair):
                    raise PlannerError("Windows are HH:MM to HH:MM for weekdays and weekends")
                if pair[0] >= pair[1]:
                    raise PlannerError("A window has to end after it starts")
                windows[kind] = [str(pair[0]), str(pair[1])]
            out[key] = windows
        elif key == "rooms":
            rooms = {k: dict(v) for k, v in current["rooms"].items()}
            for room_key, rc in (value or {}).items():
                merged = rooms.get(room_key, {})
                for field_name, field_value in (rc or {}).items():
                    if field_name == "target_days":
                        if int(field_value) not in TARGET_CHOICES:
                            raise PlannerError("Pick a target from the list")
                        merged[field_name] = int(field_value)
                    elif field_name in ("add_sensors", "remove_sensors"):
                        merged[field_name] = sorted({str(s) for s in field_value or [] if str(s).startswith("binary_sensor.")})
                    elif field_name == "ignore_occupancy":
                        merged[field_name] = bool(field_value)
                    else:
                        raise PlannerError(f"Unknown room setting '{field_name}'")
                rooms[room_key] = merged
            out[key] = rooms
    return out
