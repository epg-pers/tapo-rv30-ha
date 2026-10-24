"""Assist sentences: "vacuum the kitchen and the lounge", "send the robot home".

Registered as sentence triggers with the conversation agent, the same mechanism the
automation sentence trigger uses, so they work with the built-in Assist pipeline and any
local or cloud speech front end. Room names are matched against the robot's current map.
"""
from __future__ import annotations

import logging
import re

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
    # A robot by name ("tell Jarvis to clean the kitchen") is added at registration, from the
    # names of the robots set up, so it can never catch "send the parcel home".
]
SENTENCES_ALL = [
    f"{CLEAN} (everywhere|everything|[the] (whole|entire) (house|home|flat|floor|place))",
    f"(start|run) [the] {ROBOT}",
]
SENTENCES_HOME = [
    f"(send|tell|get) [the] {ROBOT} (home|back|to [the] (dock|base|charger))",
    f"{ROBOT} (go home|dock|return to [the] (dock|base))",
]
SENTENCES_STOP = [f"(stop|halt) [the] {ROBOT}", f"{ROBOT} stop"]
SENTENCES_PAUSE = [f"pause [the] {ROBOT}", f"{ROBOT} pause"]

# "vacuum go home" and "clean the whole house" also fit the rooms wildcard; whichever
# trigger answers, these phrases must do what they say rather than look for a room.
_WHOLE = {"everywhere", "everything", "whole house", "entire house", "whole home", "entire home",
          "whole flat", "entire flat", "whole floor", "entire floor", "whole place", "entire place"}
_HOME = {"go home", "home", "dock", "return to dock", "return to the dock", "return to base",
         "return to the base", "back"}
_STOP = {"stop", "halt"}
_PAUSE = {"pause"}


def _coordinators(hass: HomeAssistant) -> list:
    return list((hass.data.get(DOMAIN) or {}).values())


def _name_key(text: str) -> str:
    """A robot name or sentence as matched: folded, punctuation as spaces ("R2-D2" -> "r2 d2"),
    the same form the sentence templates are built from."""
    return " ".join(re.sub(r"[^\w ]+", " ", fold(text or "")).split())


def _named(coords: list, text: str):
    """The robot named in the text: whole words only ("Bot" is not in "robot"), the longest
    name winning ("Jarvis Two" over "Jarvis"); None if no name, or two robots share it."""
    low = f" {_name_key(text)} "
    hits = [(len(n), c) for c in coords if (n := _name_key(c.device_name)) and f" {n} " in low]
    if not hits:
        return None
    longest = max(n for n, _ in hits)
    best = [c for n, c in hits if n == longest]
    return best[0] if len(best) == 1 else None


def _pick(hass: HomeAssistant, text: str, rooms: list[str] | None = None, active: bool = False):
    """The robot the sentence is about: the only one; or the one named in it; or, with
    several, the only one that has all the rooms asked for (or, for stop / pause / home, the
    only one that is working). None when that still leaves a choice."""
    coords = _coordinators(hass)
    if len(coords) <= 1:
        return coords[0] if coords else None
    named = _named(coords, text)
    if named is not None:
        return named
    if rooms:
        have = [c for c in coords
                if all(any(_room_match(fold(w), fold(r.get("name_text") or "")) for r in c.rooms_named())
                       for w in rooms)]
        if len(have) == 1:
            return have[0]
    if active:
        working = [c for c in coords if c.busy or c.status_code == 4]
        if len(working) == 1:
            return working[0]
    return None


def _room_match(said: str, name: str) -> bool:
    """A room asked for by part of its name: the start of one of its words, three letters or
    more ("bath" is Bathroom). "it" is not Kitchen and "room" is not Bedroom: a stray
    sentence must not start a clean."""
    said = said.strip()
    if said == name:
        return True
    return len(said) >= 3 and said not in _GENERIC and any(w.startswith(said) for w in name.split())


_GENERIC = {"room", "rooms", "area", "floor", "house", "home"}     # in many names, mean none of them


def _which(hass: HomeAssistant) -> str:
    names = [c.device_name for c in _coordinators(hass)]
    return (f"Which robot: {' or '.join(names)}? Say its name, for example "
            f"\"tell {names[0]} to clean the kitchen\" or \"send {names[0]} home\".")


def _clean_phrase(phrase: str, hass: HomeAssistant) -> str:
    """Drop a trailing "please" and a "with <robot>" naming the robot from a room phrase."""
    p = re.sub(r"[\s,]+please[.!]*$", "", phrase.strip(), flags=re.I)
    m = re.search(r"\s+(with|using)\s+(the\s+)?(.+)$", p, flags=re.I)
    if m and _named(_coordinators(hass), m.group(3)) is not None:
        p = p[:m.start()]
    return p.strip()


async def _clean_rooms(hass: HomeAssistant, coord, phrase: str) -> str:
    wanted = split_room_phrase(phrase)
    rooms = {fold(r.get("name_text") or ""): r for r in coord.rooms_named()}
    chosen, unknown = [], []
    for w in wanted:
        key = fold(w)
        partial = [r for k, r in rooms.items() if _room_match(key, k)]
        if key not in rooms and len(partial) > 1:
            return (f"{w} could be {' or '.join(r['name_text'] for r in partial)}. "
                    "Which one?")
        hit = rooms.get(key) or (partial[0] if partial else None)
        (chosen if hit else unknown).append(hit or w)
    if unknown:
        return (f"I don't know a room called {', '.join(unknown)}. "
                f"{coord.device_name} knows {', '.join(r['name_text'] for r in coord.rooms_named()) or 'no rooms'}.")
    if coord.busy:
        return f"{coord.device_name} is already {coord.busy}."
    if why := coord.start_refused():
        return f"{coord.device_name} {why}."
    names = [r["name_text"] for r in chosen]
    try:
        await hass.async_add_executor_job(coord.client.clean_rooms, [r["id"] for r in chosen], coord.map_id)
    except Exception as exc:
        _LOGGER.warning("Voice clean_rooms failed: %s", exc)
        return f"{coord.device_name} did not accept that: {exc}"
    await coord.async_refresh_soon()
    return f"{coord.device_name} is cleaning {' and '.join(names)}."


def _register(manager, sentences: list[str], cb):
    """register_trigger takes (sentences, callback) on current Home Assistant and a single
    TriggerDetails on some releases; use whichever this one has."""
    try:
        return manager.register_trigger(sentences, cb)
    except TypeError:
        from homeassistant.components.conversation.trigger import TriggerDetails
        return manager.register_trigger(TriggerDetails(sentences, cb))


@callback
def async_setup_voice(hass: HomeAssistant):
    """Register the sentences; returns an unregister callback (None if no agent)."""
    try:
        from homeassistant.components.conversation import get_agent_manager
        manager = get_agent_manager(hass)
    except Exception as exc:                       # conversation not loaded on this install
        _LOGGER.debug("Voice sentences not registered: %s", exc)
        return None

    def _robot_text(user_input, result) -> str:
        return user_input.text

    async def on_rooms(user_input, result):
        if not _coordinators(hass):
            return "No Tapo robot is set up."
        ent = result.entities.get("rooms")
        phrase = _clean_phrase((ent.text if ent is not None else "").strip(), hass)
        key = " ".join(fold(phrase).replace("the ", " ").split())
        if key in _WHOLE:
            return await on_all(user_input, result)
        if key in _HOME:
            return await on_home(user_input, result)
        if key in _STOP:
            return await on_stop(user_input, result)
        if key in _PAUSE:
            return await on_pause(user_input, result)
        coord = _pick(hass, _robot_text(user_input, result), rooms=split_room_phrase(phrase))
        if coord is None:
            return _which(hass)
        return await _clean_rooms(hass, coord, phrase)

    async def on_all(user_input, result):
        if not _coordinators(hass):
            return "No Tapo robot is set up."
        coord = _pick(hass, _robot_text(user_input, result), active=False)
        if coord is None:
            return _which(hass)
        if coord.busy:
            return f"{coord.device_name} is already {coord.busy}."
        if why := coord.start_refused():
            return f"{coord.device_name} {why}."
        return await _do(coord, coord.client.start, "is cleaning the whole house")

    async def on_home(user_input, result):
        if not _coordinators(hass):
            return "No Tapo robot is set up."
        coord = _pick(hass, _robot_text(user_input, result), active=True)
        if coord is None:
            return _which(hass)
        return await _do(coord, coord.client.dock, "is heading home")

    async def on_stop(user_input, result):
        if not _coordinators(hass):
            return "No Tapo robot is set up."
        coord = _pick(hass, _robot_text(user_input, result), active=True)
        if coord is None:
            return _which(hass)
        reply = await _do(coord, coord.client.stop, "stopped")
        await coord.async_forget_run()
        return reply

    async def on_pause(user_input, result):
        if not _coordinators(hass):
            return "No Tapo robot is set up."
        coord = _pick(hass, _robot_text(user_input, result), active=True)
        if coord is None:
            return _which(hass)
        return await _do(coord, coord.client.pause, "is paused")

    async def _do(coord, fn, done: str) -> str:
        try:
            await hass.async_add_executor_job(fn)
        except Exception as exc:
            _LOGGER.warning("Voice command failed: %s", exc)
            return f"{coord.device_name} did not accept that: {exc}"
        await coord.async_refresh_soon()
        return f"{coord.device_name} {done}."

    names = sorted({n for n in (_name_key(c.device_name) for c in _coordinators(hass)) if n})
    named_rooms, named_home, named_all, named_stop, named_pause = [], [], [], [], []
    if names:
        robot = "(" + "|".join(names) + ")"
        named_rooms = [f"(tell|ask|get) {robot} to {CLEAN} [the] {{rooms}}"]
        named_home = [f"(send|tell|get) {robot} (home|back|to [the] (dock|base|charger))",
                      f"{robot} (go home|dock)"]
        named_all = [f"(start|run) {robot}"]
        named_stop = [f"(stop|halt) {robot}"]
        named_pause = [f"pause {robot}"]
    unregisters = []
    try:
        for sentences, cb in ((SENTENCES_ROOMS + named_rooms, on_rooms), (SENTENCES_ALL + named_all, on_all),
                              (SENTENCES_HOME + named_home, on_home), (SENTENCES_STOP + named_stop, on_stop),
                              (SENTENCES_PAUSE + named_pause, on_pause)):
            unregisters.append(_register(manager, sentences, cb))
    except Exception:
        for u in unregisters:     # all or nothing
            u()
        raise

    @callback
    def unregister() -> None:
        for u in unregisters:
            u()

    return unregister
