"""Serve the bundled Lovelace card and the room mask the card uses for
tap-to-room, and register the card as a dashboard resource so it works
with no manual setup."""
from __future__ import annotations

import logging
from pathlib import Path

from aiohttp import web
from homeassistant.components.frontend import add_extra_js_url
from homeassistant.components.http import HomeAssistantView, StaticPathConfig
from homeassistant.core import HomeAssistant

from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

STATIC_URL = f"/{DOMAIN}_static"
CARD_FILE = "tapo-rv30-card.js"
DATA_FRONTEND = f"{DOMAIN}_frontend_ready"


def card_url(version: str) -> str:
    return f"{STATIC_URL}/{CARD_FILE}?v={version}"


async def async_setup_frontend(hass: HomeAssistant, version: str) -> None:
    """Idempotent: static path, resource registration, mask view."""
    if hass.data.get(DATA_FRONTEND):
        return
    hass.data[DATA_FRONTEND] = True

    await hass.http.async_register_static_paths([
        StaticPathConfig(STATIC_URL, str(Path(__file__).parent / "frontend"), cache_headers=False)
    ])
    hass.http.register_view(RoomMaskView())
    await _register_resource(hass, card_url(version))


async def _register_resource(hass: HomeAssistant, url: str) -> None:
    """Add (or re-point after an upgrade) the card in Lovelace's resource list.
    Storage mode gets a proper resource entry; YAML mode gets the extra-JS hook."""
    lovelace = hass.data.get("lovelace")
    resources = getattr(lovelace, "resources", None)
    mode = getattr(lovelace, "mode", None)
    base = url.split("?", 1)[0]
    try:
        if resources is not None and mode == "storage":
            if not getattr(resources, "loaded", True):
                await resources.async_load()
            for item in resources.async_items():
                if str(item.get("url", "")).split("?", 1)[0] == base:
                    if item.get("url") != url:
                        await resources.async_update_item(item["id"], {"res_type": "module", "url": url})
                        _LOGGER.debug("Updated card resource to %s", url)
                    return
            await resources.async_create_item({"res_type": "module", "url": url})
            _LOGGER.info("Registered the Tapo RV30 card as a dashboard resource (%s)", url)
            return
    except Exception as exc:
        _LOGGER.warning("Lovelace resource registration failed (%r); loading the card via extra JS instead", exc)
    add_extra_js_url(hass, url)


class RoomMaskView(HomeAssistantView):
    """GET /api/tapo_rv30/<entry_id>/rooms.png -> 8-bit PNG, pixel = room id."""
    url = f"/api/{DOMAIN}/{{entry_id}}/rooms.png"
    name = f"api:{DOMAIN}:rooms"
    requires_auth = True

    async def get(self, request: web.Request, entry_id: str) -> web.Response:
        coordinator = request.app["hass"].data.get(DOMAIN, {}).get(entry_id)
        if coordinator is None or coordinator.room_mask is None:
            return web.Response(status=404, text="no map")
        return web.Response(body=coordinator.room_mask, content_type="image/png",
                            headers={"Cache-Control": "no-cache"})
