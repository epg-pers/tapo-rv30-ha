"""Pure helpers for map, room and schedule data. No Home Assistant imports, so
they can be unit-tested without a running HA."""
from __future__ import annotations

import base64
import unicodedata
from typing import Any, Callable


class MapNotFound(ValueError):
    """The requested map could not be resolved on the vacuum."""


class RoomNotFound(ValueError):
    """A requested room could not be resolved on the chosen map."""


class MapValidationError(ValueError):
    """Device-supplied map data is malformed or implausibly large."""


MAX_MAP_SIDE = 2048            # cells; real maps are a few hundred
MAX_MAP_CELLS = 4_200_000
MAX_ROOMS = 64


def validate_map(map_data: dict) -> None:
    """Reject map fields that would make rendering allocate or loop excessively.
    The fields are device-supplied, so treat them as untrusted."""
    try:
        width, height, pix_len = int(map_data["width"]), int(map_data["height"]), int(map_data["pix_len"])
    except (KeyError, TypeError, ValueError) as exc:
        raise MapValidationError(f"map header missing or invalid: {exc}") from exc
    if not (0 < width <= MAX_MAP_SIDE and 0 < height <= MAX_MAP_SIDE):
        raise MapValidationError(f"map size {width}x{height} out of range")
    if pix_len != width * height or pix_len > MAX_MAP_CELLS:
        raise MapValidationError(f"pix_len {pix_len} does not match {width}x{height}")
    rooms = [a for a in map_data.get("area_list") or [] if isinstance(a, dict) and a.get("type") == "room"]
    if len(rooms) > MAX_ROOMS:
        raise MapValidationError(f"{len(rooms)} rooms is implausible")
    if not isinstance(map_data.get("map_data"), str):
        raise MapValidationError("map_data missing")



def lz4_block_decompress(data: bytes, uncompressed_size: int) -> bytes:
    """Pure-Python LZ4 block decompressor, bounds-checked on every copy so a
    malformed block raises MapValidationError instead of corrupting or growing
    the output."""
    out = bytearray(uncompressed_size)
    src = 0
    dst = 0
    n = len(data)
    while src < n:
        token = data[src]; src += 1
        lit_len = token >> 4
        if lit_len == 15:
            while True:
                if src >= n:
                    raise MapValidationError("lz4: truncated literal length")
                extra = data[src]; src += 1
                lit_len += extra
                if extra != 255:
                    break
        if src + lit_len > n or dst + lit_len > uncompressed_size:
            raise MapValidationError("lz4: literal run exceeds buffer")
        out[dst:dst + lit_len] = data[src:src + lit_len]
        src += lit_len
        dst += lit_len
        if src >= n:
            break
        if src + 2 > n:
            raise MapValidationError("lz4: truncated match offset")
        offset = data[src] | (data[src + 1] << 8); src += 2
        match_len = (token & 0xF) + 4
        if match_len == 19:
            while True:
                if src >= n:
                    raise MapValidationError("lz4: truncated match length")
                extra = data[src]; src += 1
                match_len += extra
                if extra != 255:
                    break
        match_pos = dst - offset
        if offset == 0 or match_pos < 0 or dst + match_len > uncompressed_size:
            raise MapValidationError("lz4: match outside buffer")
        for i in range(match_len):
            out[dst + i] = out[match_pos + i]
        dst += match_len
    if dst != uncompressed_size:
        raise MapValidationError(f"lz4: produced {dst} of {uncompressed_size} bytes")
    return bytes(out)


def b64name(s: str) -> str:
    try:
        return base64.b64decode(s).decode(errors="replace").strip()
    except Exception:
        return s


def norm(value: Any) -> str:
    """Normalise a user-supplied map/room name.

    Templates and scripts often leave surrounding whitespace or a stray pair of
    quotes around the value; strip both so they still match.
    """
    text = str(value).strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        text = text[1:-1].strip()
    return text


# Bit n of week_day = that weekday; bit 0 is Sunday (Tapo app convention).
_WEEKDAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]


def fold(text: str) -> str:
    """Lower-case and strip accents, so 'kupelna' matches 'Kúpeľňa'."""
    return "".join(c for c in unicodedata.normalize("NFKD", text) if not unicodedata.combining(c)).lower()


def mm_to_grid(map_data: dict, x_mm: float, y_mm: float) -> tuple[float, float]:
    """Real-world mm (the frame of real_vac_coor, area vertexs, zones) -> map grid cell."""
    ox, oy = map_data["real_origin_coor"][:2]
    res = map_data.get("resolution") or 50
    return (x_mm - ox) / res, (y_mm - oy) / res


def dnd_active(dnd: dict | None, now_minutes: int) -> bool:
    """Is Do Not Disturb in effect at now_minutes (minutes after midnight)?
    Windows may cross midnight (22:00 -> 08:00)."""
    if not dnd or not dnd.get("do_not_disturb"):
        return False
    start, end = int(dnd.get("s_min", 0)), int(dnd.get("e_min", 0))
    if start == end:
        return True
    if start < end:
        return start <= now_minutes < end
    return now_minutes >= start or now_minutes < end


def clean_transition(prev_code, new_code, cleaning: set, paused: set) -> str | None:
    """'started' when a clean begins, 'finished' when a running or paused clean
    ends (stopped, docked, idle), else None. Pause/resume is not a transition."""
    if prev_code is None or new_code is None or prev_code == new_code:
        return None
    prev_active = prev_code in cleaning or prev_code in paused
    new_active = new_code in cleaning or new_code in paused
    if not prev_active and new_code in cleaning:
        return "started"
    if prev_active and not new_active:
        return "finished"
    return None


def decode_path(pos_array: str, pos_len: int, max_jump_mm: int = 1500) -> list[tuple[int, int]]:
    """getPathData pos_array -> [(x_mm, y_mm), ...] in the map frame.

    The LZ4 block holds an 8-byte header then big-endian int16 pairs. A lone
    sample further than max_jump_mm from both neighbours is a marker, not a
    position, and is dropped.
    """
    import struct
    raw = lz4_block_decompress(base64.b64decode(pos_array), pos_len)
    body = raw[8:]
    pts = [tuple(struct.unpack(">hh", body[i:i + 4])) for i in range(0, len(body) - 3, 4)]
    if len(pts) < 3:
        return pts
    far = lambda a, b: abs(a[0] - b[0]) + abs(a[1] - b[1]) > max_jump_mm
    # interior markers: far from both neighbours
    out = [p for i, p in enumerate(pts)
           if not (0 < i < len(pts) - 1 and far(pts[i - 1], p) and far(pts[i + 1], p))]
    # then the ends, against the cleaned sequence
    if len(out) > 1 and far(out[0], out[1]):
        out = out[1:]
    if len(out) > 1 and far(out[-1], out[-2]):
        out = out[:-1]
    return out


def decode_clean_record(rec: dict) -> dict:
    """One getCleanRecords entry, readable."""
    return {
        "started":      rec.get("timestamp"),
        "minutes":      rec.get("clean_time"),
        "area":         rec.get("clean_area"),
        "emptied_bin":  rec.get("dust_collection"),
        "error":        rec.get("error", 0),
        "map_id":       rec.get("map_id"),
        "start_type":   rec.get("start_type"),
        "rule_name":    b64name(rec.get("rule_name", "")) or None,
    }


def decode_preset(rule: dict, detail: dict | None, room_names: dict[int, str], map_name: str | None) -> dict:
    """One Tapo-app preset ("customisation rule") as a readable summary."""
    areas = (detail or {}).get("area_list") or []
    rooms = [a for a in areas if a.get("type") == "room"]
    return {
        "id":        rule.get("rule_id"),
        "name":      b64name(rule.get("rule_name", "")) or f"Preset {rule.get('rule_id')}",
        "map_id":    rule.get("map_id"),
        "map_name":  map_name,
        "mode":      rule.get("mode"),
        "valid":     not rule.get("invalid"),
        "rooms":     [room_names.get(a.get("id"), f"Room {a.get('id')}") for a in rooms],
        "room_settings": [{"room": room_names.get(a.get("id"), f"Room {a.get('id')}"),
                           "suction": a.get("suction"), "water_level": a.get("cistern"),
                           "passes": a.get("clean_number")} for a in rooms],
        "clean_order": (detail or {}).get("clean_order", True),
    }


def decode_weekdays(mask: int) -> list[str]:
    return [name for i, name in enumerate(_WEEKDAYS) if mask & (1 << i)]


_DAY_ALIASES = {"daily": 127, "everyday": 127, "every day": 127, "weekdays": 62, "weekend": 65, "weekends": 65}


def encode_weekdays(days) -> int:
    """Day names ("Mon", "monday"), aliases ("daily", "weekdays", "weekend") or a
    ready mask -> the robot's bitmask (Sun=1 ... Sat=64). Empty -> 0 (one-off)."""
    if days is None:
        return 0
    if isinstance(days, int):
        return days & 127
    if isinstance(days, str):
        days = [d for d in days.replace(",", " ").split()]
    mask = 0
    for d in days:
        key = str(d).strip().lower()
        if key in _DAY_ALIASES:
            mask |= _DAY_ALIASES[key]; continue
        try:
            mask |= 1 << [w.lower() for w in _WEEKDAYS].index(key[:3])
        except ValueError:
            raise ValueError(f"unknown day {d!r}; use Mon..Sun, daily, weekdays or weekend")
    return mask


def parse_hhmm(value) -> int:
    """'HH:MM' (or a time object) -> minutes after midnight."""
    if hasattr(value, "hour"):
        return value.hour * 60 + value.minute
    try:
        h, m = str(value).strip().split(":")[:2]
        h, m = int(h), int(m)
    except (ValueError, AttributeError):
        raise ValueError(f"time {value!r} is not HH:MM")
    if not (0 <= h < 24 and 0 <= m < 60):
        raise ValueError(f"time {value!r} is out of range")
    return h * 60 + m


def build_schedule_rule(minutes: int, week_mask: int, clean_attr: dict, enabled: bool = True,
                        once_date=None, rule_id: str | None = None) -> dict:
    """The addScheduleRule / editScheduleRule body (ScheduleRule in the Tapo app).
    s_min is minutes after midnight in the robot's own region. A one-off rule
    (no days) carries the date in year / month / day and mode "once"."""
    rule = {
        "enable": bool(enabled),
        "mode": "repeat" if week_mask else "once",
        "week_day": int(week_mask),
        "s_min": int(minutes),
        "start_remind": False,
        "alarm_min": 0,
        "clean_attr": clean_attr,
    }
    if not week_mask and once_date is not None:
        rule.update({"year": once_date.year, "month": once_date.month, "day": once_date.day})
    if rule_id is not None:
        rule["id"] = rule_id
    return rule


def decode_schedule(rule: dict, room_names: dict[int, str]) -> dict:
    """One get_schedule_rules entry as a readable summary (raw rule kept under 'raw')."""
    attr = rule.get("clean_attr") or {}
    room_ids = attr.get("room_list") or []
    s_min = rule.get("s_min", 0)
    return {
        "id":            rule.get("id"),
        "enabled":       rule.get("enable", False),
        "time":          f"{s_min // 60:02d}:{s_min % 60:02d}",
        "days":          decode_weekdays(rule.get("week_day", 0)),
        "repeat":        rule.get("mode") == "repeat",
        "rooms":         [room_names.get(rid, f"Room {rid}") for rid in room_ids],
        "room_ids":      room_ids,
        "preset_id":     attr.get("custom_rule_id"),
        "suction":       attr.get("suction"),
        "water_level":   attr.get("cistern"),
        "clean_passes":  attr.get("clean_number"),
        "map_id":        attr.get("map_id"),
        "raw":           rule,
    }


def room_at_vac(map_data: dict) -> str | None:
    """Name of the room the vacuum is in, from vac_coor against the room-id
    pixel grid getMapData already carries. None off-map or on a non-room pixel."""
    vac = map_data.get("vac_coor")
    if not vac:
        return None
    validate_map(map_data)
    width, height = map_data["width"], map_data["height"]
    gx, gy = int(vac[0]), int(vac[1])
    if not (0 <= gx < width and 0 <= gy < height):
        return None
    pixels = lz4_block_decompress(base64.b64decode(map_data["map_data"]), map_data["pix_len"])
    room_id = pixels[gy * width + gx]
    for a in map_data.get("area_list", []):
        if a.get("type") == "room" and a.get("id") == room_id:
            return b64name(a.get("name", ""))
    return None



def resolve_rooms(
    current_map_id: int,
    map_list: list[dict],
    get_map_data: Callable[[int], dict],
    name_patterns: list[str],
    map_name: str | None = None,
) -> tuple[list[int], int]:
    """Resolve room names -> (room_ids, map_id).

    Uses map_name (exact, then partial match) if given, otherwise the current
    map. Names are normalised with norm() first. Raises MapNotFound /
    RoomNotFound (both ValueError) with the available names in the message.
    """
    map_names = {m["map_id"]: b64name(m.get("map_name", "")) for m in map_list}

    if map_name is not None:
        wanted = norm(map_name)
        if not wanted:
            raise MapNotFound(
                "'map' was given but is empty after trimming; omit it to use the "
                f"current map. Available maps: {sorted(map_names.values())}"
            )
        exact = [mid for mid, n in map_names.items() if fold(n) == fold(wanted)]
        partial = [mid for mid, n in map_names.items() if fold(wanted) in fold(n)]
        hits = exact or partial
        if not hits:
            raise MapNotFound(
                f"Map '{wanted}' not found on the vacuum. "
                f"Available maps: {sorted(map_names.values())}"
            )
        if len(hits) > 1:
            raise MapNotFound(
                f"Map '{wanted}' is ambiguous, matches: "
                f"{sorted(map_names[m] for m in hits)}"
            )
        target_id = hits[0]
    else:
        target_id = current_map_id

    map_data = get_map_data(target_id)
    rooms = [a for a in map_data.get("area_list", []) if a.get("type") == "room"]
    decoded = [b64name(r.get("name", "")) for r in rooms]
    target_name = map_names.get(target_id, str(target_id))

    matched: list[int] = []
    seen: set[int] = set()
    for raw in name_patterns:
        pat = norm(raw)
        if not pat:
            raise RoomNotFound(
                f"Empty room name in 'rooms' on map '{target_name}'. "
                f"Available rooms: {decoded}"
            )
        exact = [r for r, n in zip(rooms, decoded) if fold(n) == fold(pat)]
        hits = exact or [r for r, n in zip(rooms, decoded) if fold(pat) in fold(n)]
        if not hits:
            raise RoomNotFound(
                f"No room matching '{pat}' on map '{target_name}'. "
                f"Available rooms: {decoded}"
            )
        for r in hits:
            if r["id"] not in seen:
                seen.add(r["id"]); matched.append(r["id"])

    return matched, target_id


MATTER_UNBOUND, MATTER_COMMISSIONING, MATTER_BOUND = 0, 1, 2   # getCommissionedStatus.status (app constants)


def matter_state(status: dict | None, read_at: float | None, now: float) -> dict:
    """Readable Matter state from getCommissionedStatus. expired_time is the
    seconds the pairing window had left when the robot answered, so the
    remaining time is projected from the read time instead of polling."""
    if not status:
        return {"state": None, "fabrics": [], "window_seconds_left": None}
    fabrics = [{"label": f.get("label") or "", "vendor_id": f.get("vendor_id"),
                "fabric_index": f.get("fabric_index"), "fabric_id": f.get("fabric_id")}
               for f in status.get("bind_fabrics") or [] if isinstance(f, dict)]
    code = status.get("status", MATTER_UNBOUND)
    left = None
    if code == MATTER_COMMISSIONING:
        left = int(status.get("expired_time") or 0)
        if read_at is not None:
            left = max(0, left - int(now - read_at))
    if code == MATTER_COMMISSIONING and left:
        state = "Pairing window open"
    elif code == MATTER_BOUND or fabrics:
        state = "Paired"
    else:
        state = "Not paired"
    return {"state": state, "fabrics": fabrics, "window_seconds_left": left}
