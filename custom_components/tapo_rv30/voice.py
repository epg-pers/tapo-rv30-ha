"""Assist sentences: "vacuum the kitchen and the lounge", "send the robot home".

Registered as sentence triggers with the conversation agent, the same mechanism the
automation sentence trigger uses, so they work with the built-in Assist pipeline and any
local or cloud speech front end. Room names are matched against the robot's current map.
"""
from __future__ import annotations

import logging

from homeassistant.core import HomeAssistant, callback

from .const import DOMAIN
from .mapdata import fold, split_room_phrase

_LOGGER = logging.getLogger(__name__)

ROBOT = "(vacuum|robot|hoover|vac|robot vacuum|vacuum cleaner)"
CLEAN = "(vacuum|clean|hoover|sweep)"

SENTENCES_ROOMS = [
    f"{CLEAN} [the] {{rooms}}",
    f"[please] {CLEAN} [the] {{rooms}} [please]",
    f"(tell|ask|get) [the] {ROBOT} to {CLEAN} [the] {{rooms}}",
]
SENTENCES_ALL = [
    f"{CLEAN} (everywhere|everything|[the] (whole|entire) (house|home|flat|floor|place))",
    f"(start|run) [the] {ROBOT}",
]
SENTENCES_HOME = [
    f"(send|tell|get) [the] {ROBOT} (home|back|to [the] (dock|base|charger))",
    f"{ROBOT} (go home|dock|return to [the] (dock|base))",
]
SENTENCES_STOP = [f"(stop|pause|halt) [the] {ROBOT}", f"{ROBOT} stop"]


def _coordinators(hass: HomeAssistant) -> list:
    return list((hass.data.get(DOMAIN) or {}).values())


def _pick(hass: HomeAssistant, text: str):
    """The robot the sentence is about: by name if several, else the only one."""
    coords = _coordinators(hass)
    if not coords:
        return None
    if len(coords) > 1:
        low = fold(text)
        for c in coords:
            if fold(c.device_name) in low:
                return c
    return coords[0]


async def _clean_rooms(hass: HomeAssistant, coord, phrase: str) -> str:
    wanted = split_room_phrase(phrase)
    rooms = {fold(r.get("name_text") or ""): r for r in coord.rooms_named()}
    chosen, unknown = [], []
    for w in wanted:
        key = fold(w)
        hit = rooms.get(key) or next((r for k, r in rooms.items() if key and key in k), None)
        (chosen if hit else unknown).append(hit or w)
    if unknown:
        return (f"I don't know a room called {', '.join(unknown)}. "
                f"{coord.device_name} knows {', '.join(r['name_text'] for r in coord.rooms_named()) or 'no rooms'}.")
    if coord.busy:
        return f"{coord.device_name} is already {coord.busy}."
    names = [r["name_text"] for r in chosen]
    try:
        await hass.async_add_executor_job(coord.client.clean_rooms, [r["id"] for r in chosen], coord.map_id)
    except Exception as exc:
        _LOGGER.warning("Voice clean_rooms failed: %s", exc)
        return f"{coord.device_name} did not accept that: {exc}"
    await coord.async_refresh_soon()
    return f"{coord.device_name} is cleaning {' and '.join(names)}."


@callback
def async_setup_voice(hass: HomeAssistant):
    """Register the sentences; returns an unregister callback (None if no agent)."""
    try:
        from homeassistant.components.conversation import get_agent_manager
        manager = get_agent_manager(hass)
    except Exception as exc:                       # conversation not loaded on this install
        _LOGGER.debug("Voice sentences not registered: %s", exc)
        return None

    async def on_rooms(user_input, result):
        coord = _pick(hass, user_input.text)
        if coord is None:
            return "No Tapo robot is set up."
        ent = result.entities.get("rooms")
        phrase = (ent.text if ent is not None else "").strip()
        return await _clean_rooms(hass, coord, phrase)

    async def on_all(user_input, result):
        coord = _pick(hass, user_input.text)
        if coord is None:
            return "No Tapo robot is set up."
        if coord.busy:
            return f"{coord.device_name} is already {coord.busy}."
        await hass.async_add_executor_job(coord.client.start)
        await coord.async_refresh_soon()
        return f"{coord.device_name} is cleaning the whole house."

    async def on_home(user_input, result):
        coord = _pick(hass, user_input.text)
        if coord is None:
            return "No Tapo robot is set up."
        await hass.async_add_executor_job(coord.client.dock)
        await coord.async_refresh_soon()
        return f"{coord.device_name} is heading home."

    async def on_stop(user_input, result):
        coord = _pick(hass, user_input.text)
        if coord is None:
            return "No Tapo robot is set up."
        await hass.async_add_executor_job(coord.client.stop)
        await coord.async_refresh_soon()
        return f"{coord.device_name} stopped."

    unregisters = [
        manager.register_trigger(SENTENCES_ROOMS, on_rooms),
        manager.register_trigger(SENTENCES_ALL, on_all),
        manager.register_trigger(SENTENCES_HOME, on_home),
        manager.register_trigger(SENTENCES_STOP, on_stop),
    ]

    @callback
    def unregister() -> None:
        for u in unregisters:
            u()

    return unregister
