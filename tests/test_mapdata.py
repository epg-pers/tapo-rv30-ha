import base64

import pytest

from custom_components.tapo_rv30.mapdata import (
    MapNotFound, RoomNotFound, b64name, decode_schedule, decode_weekdays,
    lz4_block_decompress, norm, resolve_rooms, room_at_vac,
)


def b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


# ---- lz4 --------------------------------------------------------------------
def test_lz4_literals_only():
    # token: 3 literals, no match
    assert lz4_block_decompress(bytes([0x30]) + b"XYZ", 3) == b"XYZ"


def test_lz4_literal_then_match():
    # 5 literals "ABCDE", then copy 4 bytes from offset 5 -> "ABCDEABCD"
    block = bytes([0x50]) + b"ABCDE" + bytes([0x05, 0x00])
    assert lz4_block_decompress(block, 9) == b"ABCDEABCD"


def test_lz4_overlapping_match_run_length():
    # 1 literal "A", then match offset 1 length 4 -> "AAAAA" (overlap copy)
    block = bytes([0x10]) + b"A" + bytes([0x01, 0x00])
    assert lz4_block_decompress(block, 5) == b"AAAAA"


# ---- names -------------------------------------------------------------------
def test_b64name_decodes_and_falls_back():
    assert b64name(b64("Kitchen ")) == "Kitchen"
    assert b64name("not base64!") == "not base64!"


@pytest.mark.parametrize("raw,expected", [
    ("Hallway", "Hallway"),
    ("  Hallway  ", "Hallway"),
    ('"Hallway"', "Hallway"),
    ("' Hallway '", "Hallway"),
    ('"', '"'),            # a lone quote is not a wrapper
    ("", ""),
    (12, "12"),
])
def test_norm(raw, expected):
    assert norm(raw) == expected


# ---- schedules -----------------------------------------------------------------
def test_decode_weekdays_bit0_is_sunday():
    assert decode_weekdays(0b0000001) == ["Sun"]
    assert decode_weekdays(0b0111110) == ["Mon", "Tue", "Wed", "Thu", "Fri"]
    assert decode_weekdays(0) == []


def test_decode_schedule_rooms_and_preset():
    rule = {"id": 7, "enable": True, "s_min": 9 * 60 + 30, "week_day": 0b1000001, "mode": "repeat",
            "clean_attr": {"room_list": [1, 3], "suction": 2, "cistern": 1, "clean_number": 2,
                           "map_id": 55, "clean_order": True}}
    d = decode_schedule(rule, {1: "Hallway", 3: "Kitchen"})
    assert d["time"] == "09:30" and d["days"] == ["Sun", "Sat"] and d["repeat"] is True
    assert d["rooms"] == ["Hallway", "Kitchen"] and d["room_ids"] == [1, 3]
    assert d["preset_id"] is None and d["map_id"] == 55 and d["raw"] is rule

    preset = decode_schedule({"id": 8, "s_min": 0, "clean_attr": {"custom_rule_id": 42, "room_list": [9]}}, {})
    assert preset["preset_id"] == 42 and preset["rooms"] == ["Room 9"] and preset["time"] == "00:00"


# ---- room at position -------------------------------------------------------------
def _map(width, height, pixels, rooms, vac):
    raw = bytes(pixels)
    block = bytes([len(raw) << 4]) + raw           # literal-only lz4 block (len < 15)
    return {
        "width": width, "height": height, "pix_len": len(raw),
        "map_data": base64.b64encode(block).decode(),
        "area_list": [{"type": "room", "id": rid, "name": b64(name)} for rid, name in rooms.items()],
        "vac_coor": vac,
    }


def test_room_at_vac():
    pixels = [0, 1, 1, 0,
              0, 2, 2, 0,
              255, 255, 255, 255]
    rooms = {1: "Hallway", 2: "Kitchen"}
    assert room_at_vac(_map(4, 3, pixels, rooms, [2, 1])) == "Kitchen"
    assert room_at_vac(_map(4, 3, pixels, rooms, [1, 0])) == "Hallway"
    assert room_at_vac(_map(4, 3, pixels, rooms, [0, 0])) is None      # wall
    assert room_at_vac(_map(4, 3, pixels, rooms, [1, 2])) is None      # floor, no room
    assert room_at_vac(_map(4, 3, pixels, rooms, [9, 9])) is None      # off map
    assert room_at_vac(_map(4, 3, pixels, rooms, None)) is None


# ---- resolve_rooms -----------------------------------------------------------------
MAPS = [{"map_id": 3, "map_name": b64("Downstairs")}, {"map_id": 7, "map_name": b64("Upstairs")}]
ROOMS = {3: ["Hallway", "Lounge", "Dining Room", "Kitchen"], 7: ["Bedroom", "Landing"]}


def get_map_data(mid):
    return {"area_list": [{"type": "room", "id": i + 1, "name": b64(n)} for i, n in enumerate(ROOMS[mid])]}


def R(patterns, map_name=None):
    return resolve_rooms(3, MAPS, get_map_data, patterns, map_name)


def test_resolve_plain_partial_and_messy():
    assert R(["Hallway"]) == ([1], 3)
    assert R(["dining"]) == ([3], 3)
    assert R([' "hallway" ', " 'Kitchen'"]) == ([1, 4], 3)
    assert R(["Hallway", "hallway"]) == ([1], 3)           # de-duplicated


def test_resolve_explicit_map():
    assert R(["Bedroom"], ' "upstairs" ') == ([1], 7)
    assert R(["Landing"], "Up") == ([2], 7)


@pytest.mark.parametrize("args,exc,fragment", [
    ((["Garage"],), RoomNotFound, "Available rooms"),
    (([" "],), RoomNotFound, "Empty room name"),
    ((["Bedroom"],), RoomNotFound, "on map 'Downstairs'"),
    ((["Hallway"], "Attic"), MapNotFound, "Available maps"),
    ((["Hallway"], "   "), MapNotFound, "empty after trimming"),
    ((["Hallway"], '""'), MapNotFound, "empty after trimming"),
    ((["Hallway"], "s"), MapNotFound, "ambiguous"),
])
def test_resolve_errors(args, exc, fragment):
    with pytest.raises(exc, match=fragment):
        R(*args)
