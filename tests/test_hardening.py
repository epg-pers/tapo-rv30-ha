import base64

import pytest

from custom_components.tapo_rv30.mapdata import (
    MapValidationError, decode_preset, lz4_block_decompress, validate_map,
)


def b64(s):
    return base64.b64encode(s.encode()).decode()


def _md(**over):
    md = {"width": 4, "height": 2, "pix_len": 8, "map_data": "AA==", "area_list": []}
    md.update(over)
    return md


def test_validate_map_accepts_sane_map():
    validate_map(_md())


@pytest.mark.parametrize("over,fragment", [
    ({"width": 5000}, "out of range"),
    ({"height": 0}, "out of range"),
    ({"pix_len": 9}, "does not match"),
    ({"area_list": [{"type": "room", "id": i} for i in range(65)]}, "implausible"),
    ({"map_data": None}, "map_data missing"),
    ({"width": "x"}, "invalid"),
])
def test_validate_map_rejects(over, fragment):
    with pytest.raises(MapValidationError, match=fragment):
        validate_map(_md(**over))


@pytest.mark.parametrize("block,size,fragment", [
    (bytes([0x50]) + b"ABC", 5, "literal run exceeds"),                 # claims 5 literals, has 3
    (bytes([0x10]) + b"A" + bytes([0x00, 0x00]), 5, "match outside"),    # offset 0
    (bytes([0x10]) + b"A" + bytes([0x09, 0x00]), 5, "match outside"),    # offset before start
    (bytes([0x10]) + b"A" + bytes([0x01]), 5, "truncated match offset"),
    (bytes([0x1F]) + b"A" + bytes([0x01, 0x00]), 64, "truncated match length"),
    (bytes([0x10]) + b"A" + bytes([0x01, 0x00]), 3, "match outside"),     # 1 + 4 > 3
    (bytes([0x20]) + b"AB", 3, "produced 2 of 3"),
])
def test_lz4_rejects_malformed(block, size, fragment):
    with pytest.raises(MapValidationError, match=fragment):
        lz4_block_decompress(block, size)


def test_lz4_still_decodes_valid():
    assert lz4_block_decompress(bytes([0x50]) + b"ABCDE" + bytes([0x05, 0x00]), 9) == b"ABCDEABCD"


def test_decode_preset():
    rule = {"rule_name": b64("Daytime Vacuum"), "rule_id": 5, "mode": "room", "map_id": 77, "invalid": 0}
    detail = {"area_list": [
        {"clean_number": 2, "id": 1, "cistern": 0, "suction": 4, "type": "room"},
        {"clean_number": 3, "id": 4, "cistern": 0, "suction": 3, "type": "room"},
    ], "clean_order": True}
    p = decode_preset(rule, detail, {1: "Hallway", 4: "Dining Room"}, "Downstairs")
    assert p["id"] == 5 and p["name"] == "Daytime Vacuum" and p["map_name"] == "Downstairs"
    assert p["rooms"] == ["Hallway", "Dining Room"] and p["valid"] is True
    assert p["room_settings"][1] == {"room": "Dining Room", "suction": 3, "water_level": 0, "passes": 3}
    # no detail, unnamed rule
    q = decode_preset({"rule_id": 9, "invalid": 1}, None, {}, None)
    assert q["name"] == "Preset 9" and q["rooms"] == [] and q["valid"] is False
