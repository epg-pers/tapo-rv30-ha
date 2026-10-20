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



def lz4_block_decompress(data: bytes, uncompressed_size: int) -> bytes:
    """Pure-Python LZ4 block decompressor — no C extension needed."""
    out = bytearray(uncompressed_size)
    src = 0
    dst = 0
    n = len(data)
    while src < n:
        token = data[src]; src += 1
        # Literal run
        lit_len = token >> 4
        if lit_len == 15:
            while src < n:
                extra = data[src]; src += 1
                lit_len += extra
                if extra != 255:
                    break
        out[dst:dst + lit_len] = data[src:src + lit_len]
        src += lit_len
        dst += lit_len
        if src >= n:
            break
        # Match copy
        offset = data[src] | (data[src + 1] << 8); src += 2
        match_len = (token & 0xF) + 4
        if match_len == 19:  # 4 + 15
            while src < n:
                extra = data[src]; src += 1
                match_len += extra
                if extra != 255:
                    break
        match_pos = dst - offset
        for i in range(match_len):
            out[dst + i] = out[match_pos + i]
        dst += match_len
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


def decode_weekdays(mask: int) -> list[str]:
    return [name for i, name in enumerate(_WEEKDAYS) if mask & (1 << i)]


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
