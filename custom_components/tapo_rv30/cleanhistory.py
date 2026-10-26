"""Clean map history: a local archive of finished runs, each kept as the slice of the robot's
record that is needed to draw it, compressed. No Home Assistant imports, so it can be
unit-tested without a running HA.

A run is saved when the integration already reads its record (to draw the last clean and to
work out which rooms it covered), so keeping history costs no extra calls to the robot. Maps
are drawn from disk when asked for, so they can be seen while the robot is cleaning or
offline, and after the robot has dropped the run from its own list."""
from __future__ import annotations

import contextlib
import gzip
import json
import os
import threading

# How long runs are kept. "Off" keeps none (and clears what was kept).
RETENTION_DAYS: dict[str, int | None] = {
    "Off": 0, "1 week": 7, "1 month": 30, "3 months": 91, "1 year": 365, "Forever": None,
}
DEFAULT_RETENTION = "3 months"
DEFAULT_LIMIT = 200
MIN_LIMIT, MAX_LIMIT = 10, 1000

# What render_record reads; the rest of a record (room settings, cleaning attributes and so on)
# is not kept. Only no-go zones are drawn, so only they are kept from the area list.
_MAP_FIELDS = ("width", "height", "pix_len", "map_data", "resolution", "real_origin_coor",
               "pos_array", "pos_len", "real_charge_coor", "map_id", "map_name")
_META_FIELDS = ("started", "minutes", "area", "map_id", "map_name", "start_type", "rule_name",
                "error", "emptied_bin")
_INDEX = "index.json"
# Runs forgotten on the History tab, so keeping the newest run automatically (after a restart
# or a map turn redraws it) does not bring them back. Opening one on purpose keeps it again.
_FORGOTTEN = "forgotten.json"
_MAX_FORGOTTEN = 200


class HistoryError(Exception):
    """A run's map cannot be shown (not kept, and the robot cannot be asked now)."""


def slim(detail: dict) -> dict:
    """The part of a getCleanRecordExtraInfo reply that drawing the run needs."""
    out = {k: detail[k] for k in _MAP_FIELDS if k in detail}
    out["area_list"] = [{"type": a.get("type"), "vertexs": a.get("vertexs")}
                        for a in detail.get("area_list") or []
                        if isinstance(a, dict) and a.get("type") == "forbid"]
    return out


def retention_days(label: str | None) -> int | None:
    return RETENTION_DAYS.get(label or DEFAULT_RETENTION, RETENTION_DAYS[DEFAULT_RETENTION])


class CleanHistory:
    """One robot's saved runs: <folder>/<start time>.json.gz plus a small index, so listing
    never opens the runs themselves. All methods block (file I/O): call them from the
    executor. A lock keeps the index consistent when two of them overlap."""

    def __init__(self, folder: str) -> None:
        self.folder = folder
        self._lock = threading.Lock()
        self._index: dict[str, dict] | None = None
        self._forgotten: set[int] | None = None

    # ---- index ---------------------------------------------------------------------------
    def _path(self, started: int) -> str:
        return os.path.join(self.folder, f"{int(started)}.json.gz")

    def _load(self) -> dict[str, dict]:
        if self._index is not None:
            return self._index
        try:
            with open(os.path.join(self.folder, _INDEX), encoding="utf-8") as fh:
                index = json.load(fh)
            if not isinstance(index, dict):
                raise ValueError("not an index")
        except FileNotFoundError:
            index = {}
        except (OSError, ValueError):
            index = self._rebuild()
        # A run whose file has gone (deleted by hand) is dropped; one with no index entry
        # (a crash between writing it and the index) is picked up from its own header.
        names = set(os.listdir(self.folder)) if os.path.isdir(self.folder) else set()
        index = {k: v for k, v in index.items() if f"{k}.json.gz" in names}
        for name in names - {f"{k}.json.gz" for k in index}:
            if name.endswith(".json.gz") and name[:-8].isdigit():
                meta = self._read_meta(os.path.join(self.folder, name))
                if meta is not None:
                    index[name[:-8]] = meta
        self._index = index
        return index

    def _rebuild(self) -> dict[str, dict]:
        index = {}
        if os.path.isdir(self.folder):
            for name in os.listdir(self.folder):
                if name.endswith(".json.gz") and name[:-8].isdigit():
                    meta = self._read_meta(os.path.join(self.folder, name))
                    if meta is not None:
                        index[name[:-8]] = meta
        return index

    def _read_meta(self, path: str) -> dict | None:
        try:
            with gzip.open(path, "rt", encoding="utf-8") as fh:
                meta = json.load(fh).get("meta")
            return {**meta, "bytes": os.path.getsize(path)} if isinstance(meta, dict) else None
        except (OSError, ValueError, EOFError, AttributeError):
            return None

    def _save(self) -> None:
        os.makedirs(self.folder, exist_ok=True)
        path = os.path.join(self.folder, _INDEX)
        tmp = f"{path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self._index or {}, fh, separators=(",", ":"))
        os.replace(tmp, path)

    def _load_forgotten(self) -> set[int]:
        if self._forgotten is None:
            try:
                with open(os.path.join(self.folder, _FORGOTTEN), encoding="utf-8") as fh:
                    self._forgotten = {int(t) for t in json.load(fh)}
            except (OSError, ValueError, TypeError, OverflowError):
                self._forgotten = set()
        return self._forgotten

    def _save_forgotten(self) -> None:
        os.makedirs(self.folder, exist_ok=True)
        path = os.path.join(self.folder, _FORGOTTEN)
        tmp = f"{path}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(sorted(self._forgotten or ()), fh)
        os.replace(tmp, path)

    # ---- runs ----------------------------------------------------------------------------
    def has(self, started: int) -> bool:
        with self._lock:
            return str(int(started)) in self._load()

    def add(self, started: int, meta: dict, detail: dict, auto: bool = True) -> bool:
        """Keep one run. False when it was already kept (nothing is rewritten), or when `auto`
        and it was forgotten. Kept on purpose (not `auto`), a forgotten run is kept again."""
        key = str(int(started))
        with self._lock:
            index = self._load()
            if key in index:
                return False
            forgotten = self._load_forgotten()
            if auto and int(started) in forgotten:
                return False
            meta = {k: meta.get(k) for k in _META_FIELDS}
            meta["started"] = int(started)
            blob = gzip.compress(json.dumps({"meta": meta, "map": slim(detail)},
                                            separators=(",", ":")).encode("utf-8"), 6)
            os.makedirs(self.folder, exist_ok=True)
            path = self._path(started)
            tmp = f"{path}.tmp"
            with open(tmp, "wb") as fh:
                fh.write(blob)
            os.replace(tmp, path)
            index[key] = {**meta, "bytes": len(blob)}
            self._save()
            if int(started) in forgotten:
                forgotten.discard(int(started))
                self._save_forgotten()
            return True

    def get(self, started: int) -> dict | None:
        """The kept map of one run (the slice render_record draws), or None."""
        with self._lock:
            if str(int(started)) not in self._load():
                return None
        try:
            with gzip.open(self._path(started), "rt", encoding="utf-8") as fh:
                return json.load(fh).get("map")
        except (OSError, ValueError, EOFError, AttributeError):
            return None

    def delete(self, started: int) -> bool:
        key = str(int(started))
        with self._lock:
            index = self._load()
            if key not in index:
                return False
            forgotten = self._load_forgotten()
            forgotten.add(int(started))
            # Only the newest runs are kept automatically, so old marks can go.
            for t in sorted(forgotten)[:-_MAX_FORGOTTEN]:
                forgotten.discard(t)
            self._save_forgotten()
            with contextlib.suppress(FileNotFoundError):
                os.remove(self._path(started))
            del index[key]
            self._save()
            return True

    def entries(self) -> list[dict]:
        """Every kept run's summary, newest first."""
        with self._lock:
            return sorted((dict(v) for v in self._load().values()),
                          key=lambda m: m.get("started") or 0, reverse=True)

    def usage(self) -> dict:
        with self._lock:
            index = self._load()
            return {"runs": len(index), "bytes": sum(int(v.get("bytes") or 0) for v in index.values())}

    def prune(self, now: float, days: int | None, limit: int) -> int:
        """Drop runs older than `days` (None keeps any age) and all but the newest `limit`.
        Returns how many were removed."""
        with self._lock:
            index = self._load()
            keys = sorted(index, key=int, reverse=True)
            cutoff = None if days is None else now - days * 86400
            # Off (0 days) keeps nothing, even a run stamped ahead of this clock by the robot's.
            drop = [k for i, k in enumerate(keys)
                    if days == 0 or i >= max(0, int(limit)) or (cutoff is not None and int(k) < cutoff)]
            for k in drop:
                with contextlib.suppress(FileNotFoundError):
                    os.remove(self._path(int(k)))
                del index[k]
            if drop:
                self._save()
            return len(drop)
