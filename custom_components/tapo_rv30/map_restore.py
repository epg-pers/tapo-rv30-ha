"""Serve a downloaded map backup (.bkmap) to the robot for a local mapRecovery.

The robot's firmware downloads the backup file from whatever URL mapRecovery is given - it
does not have to be TP-Link's storage - checks its MD5, and applies it. So we host the
backup HA already holds on a short-lived, unguessable local URL and hand that to the robot:
restore works with no cloud round-trip.

One constraint: the robot's HTTP client needs a plain response with a correct Content-Length
(which aiohttp's FileResponse sends). The URL therefore has to be HA's direct LAN address -
a reverse proxy in front of HA that re-chunks the body makes the robot's download stall near
the end and the recovery fails.
"""
from __future__ import annotations

from aiohttp import web
from homeassistant.components.http import HomeAssistantView
from homeassistant.core import HomeAssistant, callback

from .const import DOMAIN

_KEY = f"{DOMAIN}_bkmap_store"


class _BkmapView(HomeAssistantView):
    """Hands one downloaded .bkmap back to the robot, by unguessable token."""

    url = "/api/tapo_rv30/bkmap/{token}"
    name = "api:tapo_rv30:bkmap"
    requires_auth = False  # the robot has no HA credentials; the token is the guard

    def __init__(self, store: dict[str, str]) -> None:
        self._store = store

    async def get(self, request: web.Request, token: str) -> web.StreamResponse:
        path = self._store.get(token)
        if not path:
            return web.Response(status=404)
        # No file check here: that would block the event loop, and FileResponse answers 404
        # for a missing file by itself.
        return web.FileResponse(path)


@callback
def async_setup_map_restore(hass: HomeAssistant) -> dict[str, str]:
    """Register the file view once and return the shared token -> path store."""
    store = hass.data.get(_KEY)
    if store is None:
        store = hass.data[_KEY] = {}
        hass.http.register_view(_BkmapView(store))
    return store
