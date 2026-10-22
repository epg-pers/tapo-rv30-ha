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
from typing import Any

from aiohttp import web
from homeassistant.components.http import HomeAssistantView
from homeassistant.core import HomeAssistant

_LOGGER = logging.getLogger(__name__)
DATA_KEY = "tapo_rv30_map_serve"
LINK_SECONDS = 600


class MapBackupView(HomeAssistantView):
    """Serves one backup file per random token, for a few minutes, without login
    (the robot has no Home Assistant credentials)."""

    url = "/api/tapo_rv30/map_backup/{token}"
    name = "api:tapo_rv30:map_backup"
    requires_auth = False

    def __init__(self, links: dict[str, dict[str, Any]]) -> None:
        self._links = links

    async def get(self, request: web.Request, token: str) -> web.Response:
        link = self._links.get(token)
        if link is None or link["expires"] < time.monotonic():
            return web.Response(status=404)
        link["hits"].append({"from": request.remote, "at": time.time(),
                             "range": request.headers.get("Range"), "agent": request.headers.get("User-Agent")})
        _LOGGER.info("Map backup %s fetched by %s", link["name"], request.remote)
        # Headers as TP-Link's storage sends them; no-transform keeps proxies from
        # re-encoding the body.
        return web.Response(body=link["data"], content_type="application/octet-stream", headers={
            "ETag": f'"{link["md5"]}"', "Accept-Ranges": "bytes", "Cache-Control": "no-transform",
            "Content-Disposition": f'attachment; filename="{link["name"]}"'})


def serve_data(hass: HomeAssistant, name: str, data: bytes) -> tuple[str, str, dict]:
    """Offer data for download; returns (url path, md5, link record)."""
    links = hass.data.get(DATA_KEY)
    if links is None:
        links = hass.data[DATA_KEY] = {}
        hass.http.register_view(MapBackupView(links))
    for tok in [t for t, v in links.items() if v["expires"] < time.monotonic()]:
        links.pop(tok)
    token = secrets.token_urlsafe(24)
    md5 = hashlib.md5(data).hexdigest()
    link = {"data": data, "name": name, "md5": md5, "expires": time.monotonic() + LINK_SECONDS, "hits": []}
    links[token] = link
    return f"/api/tapo_rv30/map_backup/{token}", md5, link
