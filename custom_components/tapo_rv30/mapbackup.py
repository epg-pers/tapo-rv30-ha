"""Decode a .bkmap map backup file into its parts.

A backup downloaded from the cloud (or served by the robot) is a small header, a gzip'd
tar of the map's component files, then a short JSON tail. This reads those parts back out
so a backup can be inspected without the robot.

Layout:
    25 bytes                  fixed prefix: "MZ", 16 constant bytes, 0xAA55, uint32 LE version
                              (2), uint8 32 (the length of the md5 that follows)
    32 bytes                  md5 (hex ASCII) of the gzip member below
    0x01 + uint32 BE          the gzip member's length
    gzip( tar(...) )          the component files, below
    0x03 + uint32 BE + JSON   {"real_origin_coor", "area_list", "furniture_list"}

The tar holds the robot's own map files: map.gridmap (the occupancy grid, in the robot's
proprietary packed form), navmap_bound.json (explored extent, metres), charger_pose.json
(dock, metres), area_info.json / area_user.json (rooms), path_map and path_record.

The map id is in the backup itself (the last 8 bytes of map.gridmap, int64 LE, and "mapId" in
the two area files), and the robot restores a backup under that id. reid_bkmap() changes it so
a backup comes back as a new map beside the original: a copy.
"""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import re
import tarfile
import zlib
from typing import Any

_GZIP_MAGIC = b"\x1f\x8b\x08"


MAX_UNPACKED = 64 * 1024 * 1024   # bytes a backup may unpack to


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
        # Capped: a real map backup unpacks to a few MB; a corrupt or hostile file must not
        # take Home Assistant's memory with it.
        raw = dec.decompress(data[gz:], MAX_UNPACKED)
        if dec.unconsumed_tail:
            raise ValueError("not a .bkmap: unpacks to more than "
                             f"{MAX_UNPACKED // (1024 * 1024)} MB")
        raw += dec.flush()
    except zlib.error as exc:
        raise ValueError(f"not a .bkmap: bad gzip ({exc})") from exc
    members: dict[str, bytes] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(raw)) as tf:
            for i, m in enumerate(tf):
                if i >= 256:
                    raise ValueError("not a .bkmap: too many files")
                if m.isfile():
                    f = tf.extractfile(m)
                    members[m.name.lstrip("./")] = f.read() if f else b""
    except (tarfile.TarError, EOFError) as exc:
        raise ValueError(f"not a .bkmap: bad archive ({exc})") from exc
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


_PREFIX = bytes.fromhex("4d5a905e741f534ba1f8f7c918df8ff07d6eaa550200000020")
_HEAD = len(_PREFIX) + 32 + 5      # prefix, md5, 0x01 + length
_AREA_FILES = ("area_info.json", "area_user.json")


def _id_in(members: dict[str, bytes]) -> int | None:
    grid = members.get("map.gridmap") or b""
    return int.from_bytes(grid[-8:], "little", signed=True) if len(grid) >= 8 else None


def map_id_of(data: bytes) -> int | None:
    """The map id a backup restores under (from map.gridmap), or None if it can't be read."""
    return _id_in(parse_bkmap(data)["members"])


def reid_bkmap(data: bytes, new_id: int) -> bytes:
    """The same backup carrying map id new_id, so the robot restores it as a new map.

    The id is patched in place (same width, so no tar header changes), the tar re-gzipped and
    the header's md5 and length rewritten. The JSON tail is kept as it is. Raises ValueError for
    anything that is not a version-2 .bkmap laid out as above, so nothing half-understood is
    ever handed to the robot.
    """
    try:
        return _reid(data, new_id)
    except (tarfile.TarError, EOFError) as exc:
        raise ValueError(f"backup archive is damaged ({exc})") from exc


def _reid(data: bytes, new_id: int) -> bytes:
    """reid_bkmap without the archive errors translated."""
    if len(data) <= _HEAD or data[:len(_PREFIX)] != _PREFIX or data[len(_PREFIX) + 32] != 1:
        raise ValueError("not a version 2 .bkmap")
    size = int.from_bytes(data[len(_PREFIX) + 33:_HEAD], "big")
    gz, tail = data[_HEAD:_HEAD + size], data[_HEAD + size:]
    if len(gz) != size or hashlib.md5(gz).hexdigest().encode() != data[len(_PREFIX):len(_PREFIX) + 32]:
        raise ValueError("backup is damaged: the payload does not match its header")
    dec = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        raw = bytearray(dec.decompress(gz, MAX_UNPACKED))
    except zlib.error as exc:
        raise ValueError(f"backup payload is not valid gzip ({exc})") from exc
    if dec.unconsumed_tail or dec.unused_data or not dec.eof:
        raise ValueError("backup payload is not a single, complete gzip member")
    old_id = None
    patched = set()
    with tarfile.open(fileobj=io.BytesIO(bytes(raw)), mode="r:") as tf:
        for m in tf:
            name = m.name.lstrip("./")
            if not m.isfile() or name not in ("map.gridmap", *_AREA_FILES):
                continue
            body = raw[m.offset_data:m.offset_data + m.size]
            if name == "map.gridmap":
                old_id = int.from_bytes(body[-8:], "little", signed=True)
                if not 0 < old_id < 2**31 or not 0 < new_id < 2**31:
                    raise ValueError("unexpected map id in map.gridmap")
                body[-8:] = new_id.to_bytes(8, "little", signed=True)
            else:
                text = bytes(body)
                key = re.compile(rb'("mapId"\s*:\s*)(\d+)')
                found = key.search(text)
                if not found:
                    continue
                new = key.sub(lambda mt: mt.group(1) + str(new_id).encode(), text, count=1)
                if len(new) != len(text):
                    raise ValueError("new map id must have as many digits as the old one")
                body = bytearray(new)
            raw[m.offset_data:m.offset_data + m.size] = body
            patched.add(name)
    if old_id is None:
        raise ValueError("backup has no map.gridmap")
    if old_id == new_id:
        raise ValueError("the backup already has that map id")
    out = gzip.compress(bytes(raw), mtime=0)
    return (_PREFIX + hashlib.md5(out).hexdigest().encode() + b"\x01" + len(out).to_bytes(4, "big")
            + out + tail)


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
