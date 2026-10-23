"""Decode a .bkmap map backup file into its parts.

A backup downloaded from the cloud (or served by the robot) is a small header, a gzip'd
tar of the map's component files, then a short JSON tail. This reads those parts back out
so a backup can be inspected without the robot.

Layout (little-endian):
    "MZ"                      two-byte magic
    16 bytes                  keyed digest of the payload
    0xAA55                    marker
    uint32                    file-format version (2)
    uint8 len + <len> bytes   the map's 32-char md5 name
    gzip( tar(...) )          the component files, below
    uint32 + <n> JSON bytes   {"real_origin_coor", "area_list", "furniture_list"}

The tar holds the robot's own map files: map.gridmap (the occupancy grid, in the robot's
proprietary packed form), navmap_bound.json (explored extent, metres), charger_pose.json
(dock, metres), area_info.json / area_user.json (rooms), path_map and path_record.
"""
from __future__ import annotations

import io
import json
import tarfile
import zlib
from typing import Any

_GZIP_MAGIC = b"\x1f\x8b\x08"


def parse_bkmap(data: bytes) -> dict[str, Any]:
    """Return {"md5", "members": {name: bytes}, "tail": dict|None}.

    The gzip member is self-terminating, so we decode just it (ignoring the JSON tail that
    follows) and untar the result. Raises ValueError if the file is not a .bkmap.
    """
    if data[:2] != b"MZ":
        raise ValueError("not a .bkmap: bad magic")
    gz = data.find(_GZIP_MAGIC)
    if gz < 0:
        raise ValueError("not a .bkmap: no gzip member")
    # the md5 name is a length-prefixed hex string in the header (a length byte of 16 or 32
    # followed by that many hex ASCII characters)
    md5 = ""
    for i in range(gz):
        n = data[i]
        if n in (16, 32) and i + 1 + n <= gz:
            chunk = data[i + 1:i + 1 + n]
            if all(c in b"0123456789abcdefABCDEF" for c in chunk):
                md5 = chunk.decode("ascii")
                break
    dec = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        raw = dec.decompress(data[gz:]) + dec.flush()
    except zlib.error as exc:
        raise ValueError(f"not a .bkmap: bad gzip ({exc})") from exc
    members: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(raw)) as tf:
        for m in tf.getmembers():
            if m.isfile():
                f = tf.extractfile(m)
                members[m.name.lstrip("./")] = f.read() if f else b""
    tail = None
    tail_start = len(data) - len(dec.unused_data)
    rest = data[tail_start:]
    brace = rest.find(b"{")
    if brace >= 0:
        try:
            tail = json.loads(rest[brace:].rstrip(b"\x00"))
        except ValueError:
            tail = None
    return {"md5": md5, "members": members, "tail": tail}


def _loadjson(members: dict[str, bytes], name: str) -> Any:
    try:
        return json.loads(members[name]) if members.get(name) else None
    except ValueError:
        return None


def facts(data: bytes) -> dict[str, Any]:
    """A JSON-safe description of a .bkmap: explored extent, dock, rooms and components.

    Everything here is decoded from the backup's own files, so it reflects the map as it was
    when the backup was taken, with no robot involved.
    """
    parsed = parse_bkmap(data)
    members = parsed["members"]
    bound = _loadjson(members, "navmap_bound.json") or {}
    charger = _loadjson(members, "charger_pose.json") or {}
    tail = parsed["tail"] or {}
    extent = None
    if bound:
        w = bound.get("navmap_max_x", 0) - bound.get("navmap_min_x", 0)
        h = bound.get("navmap_max_y", 0) - bound.get("navmap_min_y", 0)
        extent = {"width_m": round(w, 2), "height_m": round(h, 2), "area_m2": round(w * h, 1),
                  "min": [round(bound.get("navmap_min_x", 0), 3), round(bound.get("navmap_min_y", 0), 3)],
                  "max": [round(bound.get("navmap_max_x", 0), 3), round(bound.get("navmap_max_y", 0), 3)]}
    dock = charger.get("charger_pose")
    areas = tail.get("area_list") or []
    rooms = [a for a in areas if isinstance(a, dict) and a.get("type") in (None, "room")]
    return {
        "md5": parsed["md5"],
        "size": len(data),
        "extent": extent,
        "dock_m": [round(dock[0], 3), round(dock[1], 3)] if isinstance(dock, list) and len(dock) >= 2 else None,
        "room_count": len(rooms),
        "furniture_count": len(tail.get("furniture_list") or []),
        "components": sorted(n for n in members),
    }
