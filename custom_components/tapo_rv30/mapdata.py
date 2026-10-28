"""Pure helpers for map, room and schedule data. No Home Assistant imports, so
they can be unit-tested without a running HA."""
from __future__ import annotations

import base64
import functools
import math
import re
import unicodedata
from typing import Any, Callable

from .const import PROMPT_CODES


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



@functools.lru_cache(maxsize=8)
def lz4_block_decompress(data: bytes, uncompressed_size: int) -> bytes:
    """Pure-Python LZ4 block decompressor, bounds-checked on every copy so a
    malformed block raises MapValidationError instead of corrupting or growing
    the output. Cached on the input, since one poll decodes the same map blob for
    the position, the current room and the render."""
    # LZ4 expands at most ~255x; a claimed size beyond that (or beyond any real map) is a
    # bad or hostile reply, refused before allocating it.
    if not 0 <= uncompressed_size <= min(MAX_MAP_CELLS, 255 * len(data) + 16):
        raise MapValidationError(f"implausible uncompressed size {uncompressed_size}")
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
    """Decode a base64 name; anything else (None, a number) is no name."""
    if not isinstance(s, str) or not s:
        return ""
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
    start, end = minutes_of(dnd.get("s_min")), minutes_of(dnd.get("e_min"))
    if start == end:
        return True
    if start < end:
        return start <= now_minutes < end
    return now_minutes >= start or now_minutes < end


def dnd_window(dnd: dict | None) -> dict | None:
    """The DND window as the UI shows it: {"enabled", "start": "22:00", "end": "08:00"}."""
    if not dnd:
        return None
    hhmm = lambda m: f"{minutes_of(m) // 60:02d}:{minutes_of(m) % 60:02d}"
    return {"enabled": bool(dnd.get("do_not_disturb")), "start": hhmm(dnd.get("s_min")),
            "end": hhmm(dnd.get("e_min"))}


def minutes_of(value) -> int:
    """Minutes after midnight from a robot field (int, float or numeric string; anything
    else is 0), kept within one day."""
    try:
        return int(float(value)) % 1440
    except (TypeError, ValueError, OverflowError):
        return 0


def as_int(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return default


def int_list(value, default: list | None = None) -> list[int]:
    """A robot list field (err_status, prompt, ...) as ints; a bare number becomes a list,
    anything unusable is dropped."""
    if isinstance(value, (int, float, str)) and not isinstance(value, bool):
        value = [value]
    if not isinstance(value, (list, tuple)):
        return list(default or [])
    out = [as_int(v, None) for v in value]
    out = [v for v in out if v is not None]
    return out or list(default or [])


def decode_path(pos_array: str, pos_len: int, max_jump_mm: int = 1500) -> list[tuple[int, int]]:
    """getPathData pos_array -> [(x_mm, y_mm), ...] in the map frame.

    The LZ4 block holds an 8-byte header then big-endian int16 pairs. A lone
    sample further than max_jump_mm from both neighbours is a marker, not a
    position, and is dropped.
    """
    import struct
    try:
        pos_len = int(pos_len)
    except (TypeError, ValueError, OverflowError):
        return []
    raw = lz4_block_decompress(base64.b64decode(pos_array or ""), pos_len)
    body = raw[8:]
    pts = [tuple(struct.unpack(">hh", body[i:i + 4])) for i in range(0, len(body) - 3, 4)]
    if len(pts) < 3:
        return pts
    far = lambda a, b: abs(a[0] - b[0]) + abs(a[1] - b[1]) > max_jump_mm
    dist = lambda a, b: abs(a[0] - b[0]) + abs(a[1] - b[1])
    # interior markers: far from both neighbours; or, with the robot itself near (0, 0), a
    # sample at the origin that both neighbours are well away from (real steps are ~60 mm)
    out = [p for i, p in enumerate(pts)
           if not (0 < i < len(pts) - 1 and (
               (far(pts[i - 1], p) and far(pts[i + 1], p))
               or (abs(p[0]) + abs(p[1]) <= 100 and dist(pts[i - 1], p) > 250 and dist(pts[i + 1], p) > 250)))]
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
            raise ValueError(f"unknown day {d!r}; use Mon..Sun, daily, weekdays or weekend") from None
    return mask


def parse_hhmm(value) -> int:
    """'HH:MM' (or a time object) -> minutes after midnight."""
    if hasattr(value, "hour"):
        return value.hour * 60 + value.minute
    try:
        h, m = str(value).strip().split(":")[:2]
        h, m = int(h), int(m)
    except (ValueError, AttributeError):
        raise ValueError(f"time {value!r} is not HH:MM") from None
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


def decode_schedule(rule: dict, room_names: dict[int, str], dnd: dict | None = None) -> dict:
    """One get_schedule_rules entry as a readable summary (raw rule kept under 'raw').
    blocked_by_dnd: the start time falls inside the robot's Do Not Disturb window, so the
    robot will not run it (verified on an RV30 Max Plus: the schedule simply does not
    fire; the Tapo app shows the same warning)."""
    attr = rule.get("clean_attr") or {}
    room_ids = attr.get("room_list") or []
    s_min = minutes_of(rule.get("s_min"))
    once = rule.get("mode") == "once"
    date = None
    if once and rule.get("year"):
        date = f"{as_int(rule.get('year')):04d}-{as_int(rule.get('month')):02d}-{as_int(rule.get('day')):02d}"
    return {
        "id":            rule.get("id"),
        "enabled":       rule.get("enable", False),
        "time":          f"{s_min // 60:02d}:{s_min % 60:02d}",
        "days":          decode_weekdays(as_int(rule.get("week_day"))),
        "repeat":        rule.get("mode") == "repeat",
        "date":          date,      # a one-off schedule's day (robot-local), else None
        "blocked_by_dnd": dnd_active(dnd, s_min),
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
            return b64name(a.get("name", "")) or f"Room {room_id}"   # unnamed after a restore
    return None



def resolve_rooms(
    current_map_id: int,
    map_list: list[dict],
    get_map_data: Callable[[int], dict],
    name_patterns: list[str],
    map_name: str | None = None,
    map_id: int | None = None,
    room_ids: list[int] | None = None,
) -> tuple[list[int], int]:
    """Resolve room names -> (room_ids, map_id).

    Uses map_id if given, else map_name (exact, then partial match), otherwise the
    current map. Names are normalised with norm() first. With room_ids, those ids are
    checked against the map instead of matching names (unnamed or same-named rooms).
    Raises MapNotFound / RoomNotFound (both ValueError) with the available names.
    """
    map_names = {m["map_id"]: b64name(m.get("map_name", "")) for m in map_list}

    if map_id is not None:
        if map_id not in map_names:
            raise MapNotFound(f"Map {map_id} is not on the vacuum. Available maps: {sorted(map_names.values())}")
        target_id = map_id
    elif map_name is not None:
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
    decoded = [b64name(r.get("name", "")) or f"Room {r.get('id')}" for r in rooms]
    target_name = map_names.get(target_id, str(target_id))

    if room_ids is not None:
        have = {r.get("id") for r in rooms}
        bad = [i for i in room_ids if i not in have]
        if bad or not room_ids:
            raise RoomNotFound(f"No room with id {bad or room_ids} on map '{target_name}'. "
                               f"Available rooms: {[(r.get('id'), n) for r, n in zip(rooms, decoded)]}")
        return list(dict.fromkeys(room_ids)), target_id

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
        if not exact and len(hits) > 1:
            # "bed" when there is a Bedroom and a Bedroom 2: say so rather than clean both.
            raise RoomNotFound(
                f"Room '{pat}' is ambiguous on map '{target_name}', matches: "
                f"{[n for r, n in zip(rooms, decoded) if r in hits]}"
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


def split_room_phrase(text: str) -> list[str]:
    """'the kitchen, lounge and the hallway' -> ['kitchen', 'lounge', 'hallway']."""
    parts = re.split(r",|\band\b|&|\bplus\b", text or "", flags=re.I)
    out = []
    for p in parts:
        p = re.sub(r"^\s*(the|my)\s+", "", p.strip(), flags=re.I).strip()
        if p:
            out.append(p)
    return out


def grid_pixels(map_data: dict) -> bytes:
    """The decoded cell grid of a map or record (one byte per cell)."""
    validate_map(map_data)
    return lz4_block_decompress(base64.b64decode(map_data["map_data"]), int(map_data["pix_len"]))


# Half-width, in grid cells, of the swath the robot cleans as it drives (~250 mm at 50 mm/cell).
_PATH_BRUSH = 2


def _painted_cells(record: dict, live: dict) -> set[tuple[int, int]] | None:
    """The live-map grid cells the run's path swept, or None if the record has no usable path.

    The path (pos_array) is in world mm, the same frame as the live map, so each point maps
    straight onto the live grid; a small brush around each point stands for the robot's width.
    """
    pos, plen = record.get("pos_array"), record.get("pos_len")
    if not pos or not plen:
        return None
    try:
        pts = decode_path(pos, int(plen))
    except Exception:
        return None
    if len(pts) < 2:
        return None
    painted: set[tuple[int, int]] = set()
    b = _PATH_BRUSH
    for x_mm, y_mm in pts:
        gx, gy = mm_to_grid(live, x_mm, y_mm)
        cx, cy = math.floor(gx), math.floor(gy)     # the cell the robot puts that point in
        for dx in range(-b, b + 1):
            for dy in range(-b, b + 1):
                painted.add((cx + dx, cy + dy))
    return painted


def room_coverage(record: dict, live: dict, live_pixels: bytes) -> dict[int, tuple[int, int]]:
    """How much of each room a finished run covered: {room_id: (cleaned cells, room cells)}.

    Which cells the robot cleaned is taken from its path (pos_array), painted onto the live
    map's room grid with a brush the robot's width. The path is the one signal reliable across
    every record format: some records carry a 255 'cleaned' mask over the whole floor, others
    only the map's room segmentation (every room shown full size whatever was actually cleaned),
    so counting grid cells over- or under-counts. If a record has no usable path, the 255 mask
    is used as a fallback. Everything is mapped through mm, so differing origins or sizes between
    the record and the live map do not matter."""
    lw, lh = int(live["width"]), int(live["height"])
    totals: dict[int, int] = {}
    for p in live_pixels:
        if 0 < p < 127 or 127 < p < 255:
            totals[p] = totals.get(p, 0) + 1
    cleaned: dict[int, int] = {}
    painted = _painted_cells(record, live)
    if painted is not None:
        for gx, gy in painted:
            if 0 <= gx < lw and 0 <= gy < lh:
                rid = live_pixels[gy * lw + gx]
                if rid in totals:
                    cleaned[rid] = cleaned.get(rid, 0) + 1
    else:
        rec_px = grid_pixels(record)
        rw, rh = int(record["width"]), int(record["height"])
        rox, roy = record["real_origin_coor"][:2]
        rres = record.get("resolution") or 50
        for i, p in enumerate(rec_px):
            if p != 255:
                continue
            gx, gy = i % rw, i // rw
            if gy >= rh:
                break
            x_mm, y_mm = rox + (gx + 0.5) * rres, roy + (gy + 0.5) * rres
            lx, ly = mm_to_grid(live, x_mm, y_mm)
            lx, ly = math.floor(lx), math.floor(ly)
            if 0 <= lx < lw and 0 <= ly < lh:
                rid = live_pixels[ly * lw + lx]
                if rid in totals:
                    cleaned[rid] = cleaned.get(rid, 0) + 1
    return {rid: (cleaned.get(rid, 0), total) for rid, total in totals.items()}


def decode_prompt(code) -> dict:
    """One getVacStatus prompt code as {code, prompt, description}."""
    try:
        code = int(code)
    except (TypeError, ValueError, OverflowError):
        return {"code": code, "prompt": "unknown", "description": f"Prompt {code}"}
    slug, label = PROMPT_CODES.get(code, ("unknown", f"Prompt {code}"))
    return {"code": code, "prompt": slug, "description": label}


def _keys(value) -> list:
    """Prompt instance ids: numbers or strings only (anything else cannot be compared)."""
    if not isinstance(value, (list, tuple)):
        value = [value] if isinstance(value, (int, str)) else []
    return [v for v in value if isinstance(v, (int, str)) and not isinstance(v, bool)]


def new_prompts(prev: dict | None, new: dict) -> list[dict]:
    """Prompts in the new status that were not in the previous one. The robot keeps a
    prompt in the list while it applies; each instance has an id (promptCode_id), so a
    prompt that clears and comes back fires again. Without ids, compare codes."""
    codes = int_list(new.get("prompts"))
    ids = _keys(new.get("prompt_ids"))
    old_codes = set(int_list((prev or {}).get("prompts")))
    old_ids = set(_keys((prev or {}).get("prompt_ids")))
    out = []
    for i, code in enumerate(codes):
        pid = ids[i] if i < len(ids) else None
        seen = (pid in old_ids) if pid is not None and old_ids else (code in old_codes)
        if not seen:
            out.append({**decode_prompt(code), "prompt_id": pid})
    return out


def preset_ref_id(ref) -> int | None:
    """The preset id a ref names when it is a number (an int, or a string of digits), else None.
    A number is matched by id, and by name only exactly: never as part of a longer name."""
    if isinstance(ref, bool):
        return None
    if isinstance(ref, int):
        return ref
    if isinstance(ref, float):
        return int(ref) if ref.is_integer() else None
    text = str(ref).strip() if isinstance(ref, str) else ""
    return int(text) if text.isascii() and text.isdigit() else None


def preset_body(name: str, map_id: int, rooms: list[dict], clean_order: bool = True,
                rule_id: int | None = None) -> dict:
    """The addCustomizationRule body the app sends (create, or edit when rule_id is given).
    rooms: [{id, suction, cistern, clean_number, carpet_strategy?}] in cleaning order."""
    items = []
    for r in rooms:
        item = {"id": int(r["id"]), "type": "room", "suction": int(r["suction"]),
                "cistern": int(r["cistern"]), "clean_number": int(r["clean_number"])}
        if r.get("carpet_strategy") is not None:
            item["carpet_strategy"] = r["carpet_strategy"]
        items.append(item)
    body = {"rule_name": base64.b64encode(str(name).encode()).decode(), "mode": "room",
            "map_id": int(map_id), "clean_order": bool(clean_order), "area_list": items}
    if rule_id is not None:
        body["rule_id"] = int(rule_id)
    return body


def pick_segments(segment_ids: list[str], known: dict[int, set[int]], active: int | None,
                  names: dict[int, str] | None = None) -> tuple[int, list[int], list[str]]:
    """Choose what vacuum.clean_area can clean from Home Assistant's segment ids.

    Home Assistant keeps every "<map_id>:<room_id>" ever mapped to an area, so after a
    remap or a lost map an area can still hold ids the robot no longer has. Those (and
    bare pre-0.4 ids) are dropped. If what is left spans several maps, the active map
    wins; with no active map among them it is an error, as is nothing left at all.
    Returns (map_id, room_ids, dropped_ids); raises ValueError with a readable reason.
    """
    names = names or {}
    by_map: dict[int, list[int]] = {}
    dropped: list[str] = []
    for seg in segment_ids:
        try:
            map_id, room_id = (int(p) for p in str(seg).split(":", 1))
        except ValueError:
            dropped.append(str(seg))
            continue
        if room_id in known.get(map_id, set()):
            if room_id not in by_map.setdefault(map_id, []):
                by_map[map_id].append(room_id)
        else:
            dropped.append(str(seg))
    if not by_map:
        raise ValueError("none of the selected areas match a room on the robot's maps any more; "
                         "redo the area mapping (vacuum settings, Map vacuum segments to areas)")
    if len(by_map) > 1:
        if active not in by_map:
            raise ValueError("the selected areas are on different maps ("
                             + ", ".join(names.get(m, str(m)) for m in by_map)
                             + "); the vacuum can only clean rooms on one map per run")
        dropped += [f"{m}:{r}" for m, rooms in by_map.items() if m != active for r in rooms]
        by_map = {active: by_map[active]}
    (map_id, rooms), = by_map.items()
    return map_id, rooms, dropped


# Per-room cleaning direction (the app's "Cleaning Direction"; component clean_angle 1 or later):
# a room's floor_texture, -1 the robot's own pattern, 0 and 90 the two ways in the robot's map frame.
# One value per room, for vacuuming and mopping alike.
CLEAN_DIRECTIONS = (-1, 0, 90)
DIRECTION_NAMES = ("default", "horizontal", "vertical")
# What setAreaInfo takes back for a room besides type, id and name; no vertexs (rooms are cells in
# the grid), as the editor, setups and restores write them.
ROOM_KEEP = ("color", "define_type", "floor_material", "floor_texture", "carpet_strategy", "label")


def _across(rotation) -> bool:
    """The map is shown turned a quarter (90 or 270): its sides swap on screen."""
    try:
        return (int(rotation) // 90) % 2 == 1
    except (TypeError, ValueError, OverflowError):
        return False


def direction_texture(direction, rotation=0) -> int:
    """default / horizontal / vertical, as the map is shown turned by rotation -> floor_texture.
    As in the app: unturned (or upside down) horizontal is 0; turned a quarter the two swap."""
    d = str(direction or "").strip().lower()
    if d == "default":
        return -1
    if d not in ("horizontal", "vertical"):
        raise ValueError(f"direction must be one of {list(DIRECTION_NAMES)}, not {direction!r}")
    return 0 if (d == "horizontal") != _across(rotation) else 90


def texture_direction(texture, rotation=0) -> str | None:
    """A room's floor_texture as the map is shown: default, horizontal or vertical (None when the
    robot reports something else)."""
    if texture is None or texture == -1:
        return "default"
    if isinstance(texture, bool) or texture not in (0, 90):
        return None
    return "horizontal" if (texture == 0) != _across(rotation) else "vertical"


def valid_texture(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value in CLEAN_DIRECTIONS


def room_areas(area_list, changes: dict | None = None) -> list[dict]:
    """Every room of a map as setAreaInfo takes them back (type_list ["room"] replaces them all),
    each as the robot has it, with changes applied: {room_id: {"name": text, "floor_texture": n}}.
    Rooms not in changes go back exactly as read. ValueError when the read has no rooms or lacks a
    room to change: the write would clear or drop rooms the robot has."""
    changes = changes or {}
    out = []
    for a in area_list or []:
        if not isinstance(a, dict) or a.get("type") != "room" or a.get("id") is None:
            continue
        entry = {"type": "room", "id": a["id"], **{k: a[k] for k in ("name", *ROOM_KEEP) if k in a}}
        change = changes.get(a["id"]) or {}
        if "name" in change:
            entry["name"] = base64.b64encode(str(change["name"]).encode()).decode()
        if "floor_texture" in change:
            entry["floor_texture"] = change["floor_texture"]
        out.append(entry)
    if not out:
        raise ValueError("the map read has no rooms, so nothing was written")
    if missing := sorted(set(changes) - {a["id"] for a in out}, key=str):
        raise ValueError(f"no room {missing} on the map, so nothing was written")
    return out
