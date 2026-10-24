"""Reading and picturing saved map backups. No Home Assistant imports, so it can be
unit-tested without a running HA.

Backups live in a folder (config/tapo_rv30/map_backups). Each cloud backup is a
cloud_<map_id>_<ts>.bin (.bkmap), usually beside a _snapshot image and a
local_<map_id>_*.json (a getMapData dump). The picture for a backup is, in order of
preference: its snapshot, the companion getMapData rendered like the live map, or a
schematic drawn from the .bkmap's own explored extent and dock.
"""
from __future__ import annotations

import base64
import io
import json
import os
import re
from typing import Any

from . import mapbackup

THUMB_PX = 220
# cloud_<map_id>_<timestamp>.bin / .bkmap  (never the _snapshot preview)
_BIN_RE = re.compile(r"^(cloud|local)_(\d+)_(\d+)\.(bin|bkmap)$")
_SNAP_RE = re.compile(r"^(?:cloud|local)_(\d+)_(\d+)_snapshot\.(png|jpg|jpeg)$")
_LOCAL_RE = re.compile(r"^local_(\d+)_([\w-]+)\.json$")


def safe_path(folder: str, name: str) -> str | None:
    """Resolve name to a real file inside folder, rejecting path traversal."""
    if not name or "/" in name or "\\" in name or name.startswith("."):
        return None
    path = os.path.join(folder, name)
    if os.path.dirname(os.path.realpath(path)) != os.path.realpath(folder):
        return None
    return path if os.path.isfile(path) else None


def scan_all(folders: list[str]) -> list[dict[str, Any]]:
    """scan() over several folders (the robot's own first, then the shared one older versions
    used); each entry's "dir" says where it lives. A name seen in an earlier folder wins."""
    seen, out = set(), []
    for folder in folders:
        for e in scan(folder):
            if e["file"] not in seen:
                seen.add(e["file"])
                out.append(e)
    out.sort(key=lambda e: e["ts"], reverse=True)
    return out


def locate(folders: list[str], name: str) -> str | None:
    """safe_path() in the first folder that has the file."""
    for folder in folders:
        p = safe_path(folder, name)
        if p:
            return p
    return None


def scan(folder: str) -> list[dict[str, Any]]:
    """Group the files in the backup folder into one entry per backup, newest first."""
    try:
        names = os.listdir(folder)
    except OSError:
        return []
    snaps: dict[tuple[str, str], str] = {}
    locals_: dict[str, tuple[str, str]] = {}
    for n in names:
        m = _SNAP_RE.match(n)
        if m:
            snaps[(m.group(1), m.group(2))] = n
            continue
        m = _LOCAL_RE.match(n)
        if m and locals_.get(m.group(1), ("", ""))[1] < m.group(2):
            locals_[m.group(1)] = (n, m.group(2))
    entries = []
    for n in names:
        m = _BIN_RE.match(n)
        if not m:
            continue
        source, map_id, ts = m.group(1), m.group(2), m.group(3)
        try:
            size = os.path.getsize(os.path.join(folder, n))
        except OSError:
            continue
        entries.append({
            "dir": folder, "file": n, "source": source, "map_id": int(map_id), "ts": int(ts), "size": size,
            "snapshot": snaps.get((map_id, ts)),
            "local_json": locals_.get(map_id, (None,))[0],
        })
    entries.sort(key=lambda e: e["ts"], reverse=True)
    return entries


def facts_for(folder: str, entry: dict) -> dict | None:
    try:
        with open(os.path.join(folder, entry["file"]), "rb") as fh:
            return mapbackup.facts(fh.read())
    except Exception:  # a damaged file must not break the Backups list
        return None


def image_png(folder: str, entry: dict) -> tuple[bytes | None, str]:
    """Best available picture for a backup as (bytes, mime). Blocking; call in executor."""
    if entry.get("snapshot"):
        try:
            with open(os.path.join(folder, entry["snapshot"]), "rb") as fh:
                raw = fh.read()
            return raw, "image/jpeg" if raw[:2] == b"\xff\xd8" else "image/png"
        except OSError:
            pass
    if entry.get("local_json"):
        try:
            from .maprender import _png, render_map
            with open(os.path.join(folder, entry["local_json"])) as fh:
                data = json.load(fh)
            img, _geom, _mg = render_map(data)
            return _png(img), "image/png"
        except Exception:
            pass
    try:
        with open(os.path.join(folder, entry["file"]), "rb") as fh:
            png = schematic(mapbackup.facts(fh.read()))
        if png:
            return png, "image/png"
    except Exception:
        pass
    return None, ""


def schematic(facts: dict) -> bytes | None:
    """A simple drawing from a .bkmap's own extent and dock, for backups with no snapshot or
    companion map. Shows the explored area to scale with the dock marked."""
    from PIL import Image, ImageDraw

    extent = facts.get("extent")
    if not extent:
        return None
    pad, ppm = 12, 48  # px padding, px per metre
    w = max(1, int(extent["width_m"] * ppm)) + pad * 2
    h = max(1, int(extent["height_m"] * ppm)) + pad * 2
    img = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rectangle([pad, pad, w - pad, h - pad], fill=(226, 232, 240, 255), outline=(120, 132, 150, 255), width=2)
    minx = extent["min"][0]
    maxy = extent["max"][1]
    dock = facts.get("dock_m")
    if dock:
        dx = pad + int((dock[0] - minx) * ppm)
        dy = pad + int((maxy - dock[1]) * ppm)  # image y grows downward
        d.ellipse([dx - 6, dy - 6, dx + 6, dy + 6], fill=(255, 200, 0, 255), outline=(255, 255, 255, 255), width=2)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def thumb(png: bytes, mime: str) -> str:
    """Downscale an image to a small PNG data URI for the list grid."""
    from PIL import Image
    try:
        img = Image.open(io.BytesIO(png))
        img.thumbnail((THUMB_PX, THUMB_PX))
        buf = io.BytesIO()
        img.convert("RGBA").save(buf, format="PNG")
        return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()
    except Exception:
        return "data:" + mime + ";base64," + base64.b64encode(png).decode()


def data_uri(png: bytes, mime: str) -> str:
    return "data:" + mime + ";base64," + base64.b64encode(png).decode()
