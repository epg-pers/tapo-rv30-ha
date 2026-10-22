"""Restore a map from a backup file (beta, for testing).

The robot restores with mapRecovery {map_id, map_md5, url}: it downloads the file at
url and checks its MD5. The file is the robot's own backup (as made by the Tapo app's
"back up map"), so a copy kept in Home Assistant can be served back to it from here.
"""
from __future__ import annotations

import hashlib
import logging
import secrets
import time
from email.utils import formatdate
from typing import Any

from aiohttp import web
from homeassistant.components.http import HomeAssistantView
from homeassistant.core import HomeAssistant

_LOGGER = logging.getLogger(__name__)
DATA_KEY = "tapo_rv30_map_serve"
LINK_SECONDS = 600


class MapBackupView(HomeAssistantView):
    """Serves one backup file per random token, for a few minutes, without login
    (the robot has no Home Assistant credentials). Answers like a storage bucket:
    HEAD, byte ranges, ETag and Last-Modified."""

    url = "/api/tapo_rv30/map_backup/{token}/{name:.*}"
    extra_urls = ["/api/tapo_rv30/map_backup/{token}"]
    name = "api:tapo_rv30:map_backup"
    requires_auth = False

    def __init__(self, links: dict[str, dict[str, Any]]) -> None:
        self._links = links

    def _respond(self, request: web.Request, token: str, head: bool) -> web.Response:
        link = self._links.get(token)
        if link is None or link["expires"] < time.monotonic():
            return web.Response(status=404)
        if link.get("redirect"):
            link["hits"].append({"method": request.method, "from": request.remote, "at": time.time(),
                                 "agent": request.headers.get("User-Agent"), "status": 302})
            return web.Response(status=302, headers={"Location": link["redirect"]})
        data = link["data"]
        headers = {"ETag": f'"{link["md5"]}"', "Accept-Ranges": "bytes", "Cache-Control": "no-transform",
                   "Last-Modified": link["modified"],
                   # As S3 answers (the proxy in front of Home Assistant may replace Server).
                   "Server": "AmazonS3", "x-amz-server-side-encryption": "AES256",
                   "x-amz-request-id": secrets.token_hex(8).upper()}
        status, body = 200, data
        rng = request.headers.get("Range")
        if rng and rng.startswith("bytes="):
            start_s, _, end_s = rng[6:].split(",")[0].partition("-")
            try:
                if start_s:
                    start, end = int(start_s), int(end_s) if end_s else len(data) - 1
                else:
                    start, end = len(data) - int(end_s), len(data) - 1
                end = min(end, len(data) - 1)
                if start > end or start < 0:
                    raise ValueError
                status, body = 206, data[start:end + 1]
                headers["Content-Range"] = f"bytes {start}-{end}/{len(data)}"
            except ValueError:
                return web.Response(status=416, headers={"Content-Range": f"bytes */{len(data)}"})
        link["hits"].append({"method": request.method, "from": request.remote, "at": time.time(),
                             "range": rng, "agent": request.headers.get("User-Agent"), "status": status})
        _LOGGER.info("Map backup %s: %s from %s (%s)", link["name"], request.method, request.remote, status)
        if head:
            headers["Content-Length"] = str(len(body))
            return web.Response(status=status, headers=headers, content_type="application/octet-stream")
        return web.Response(status=status, body=body, headers=headers, content_type="application/octet-stream")

    async def get(self, request: web.Request, token: str, name: str | None = None) -> web.Response:
        return self._respond(request, token, head=False)

    async def head(self, request: web.Request, token: str, name: str | None = None) -> web.Response:
        return self._respond(request, token, head=True)


def serve_data(hass: HomeAssistant, name: str, data: bytes, url_tail: str,
               redirect: str | None = None) -> tuple[str, str, dict]:
    """Offer data for download; returns (url path, md5, link record). The path ends in
    url_tail, shaped like TP-Link's own link ("robotVacMap/<map id>"). With redirect,
    the link answers 302 to that URL instead (a diagnostic)."""
    links = hass.data.get(DATA_KEY)
    if links is None:
        links = hass.data[DATA_KEY] = {}
        hass.http.register_view(MapBackupView(links))
    for tok in [t for t, v in links.items() if v["expires"] < time.monotonic()]:
        links.pop(tok)
    token = secrets.token_urlsafe(24)
    md5 = hashlib.md5(data).hexdigest()
    link = {"data": data, "name": name, "md5": md5, "expires": time.monotonic() + LINK_SECONDS, "hits": [],
            "modified": formatdate(usegmt=True), "redirect": redirect}
    links[token] = link
    return f"/api/tapo_rv30/map_backup/{token}/{url_tail}", md5, link
