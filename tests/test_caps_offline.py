"""A robot that is offline when Home Assistant starts (or the entry reloads) must fail the
first refresh quickly. The capability probes tolerate one transport hiccup per getter, so
probing an unreachable robot waited out a connect timeout for every getter (about 18 of
them, 15 s each) before the status read failed and setup could give up."""
import asyncio
import threading
import time
import types

import pytest
import requests
from homeassistant.helpers.update_coordinator import UpdateFailed

from custom_components.tapo_rv30 import coordinator as C
from custom_components.tapo_rv30.tpap import TapoVacuumClient


class Hass:
    loop = types.SimpleNamespace(time=time.monotonic)

    async def async_add_executor_job(self, fn, *a):
        return fn(*a)


def _client(online: bool):
    """A client whose every request is one connect attempt: refused when offline."""
    c = TapoVacuumClient.__new__(TapoVacuumClient)
    c._lock = threading.RLock()
    c.attempts = []

    def send(method, params=None):
        c.attempts.append(method)
        if not online:
            raise requests.ConnectTimeout("connect timeout=15")
        if method == "get_device_info":
            return {"result": {"nickname": "", "model": "RV30"}}
        if method == "getComponentList":
            return {"result": {"component_list": [{"id": "clean", "ver_code": 1}]}}
        if method == "getChildLockInfo":
            return {"result": {"child_lock_status": True}}
        raise RuntimeError(f"Device error -1002 on {method}")     # a definite "no"

    def send_multi(requests_):
        c.attempts.append("multi")
        raise requests.ConnectTimeout("connect timeout=15")       # stop the poll at the status read

    c.send, c.send_multi = send, send_multi
    return c


def _coord(monkeypatch, online: bool):
    monkeypatch.setattr(C, "STATUS_RETRY_DELAY", 0)
    c = C.TapoCoordinator.__new__(C.TapoCoordinator)
    c.hass, c.entry, c.client = Hass(), None, _client(online)
    c.device_name, c.device_model, c.device_mac, c.fw_version = "Robot", "RV30", None, None
    c._info_fetched = c._caps_fetched = False
    c._caps_attempts = 0
    c.components, c.bool_settings, c.bool_settings_supported, c.dock_actions = {}, {}, [], []
    c._last_ok = c._first_fail = None
    c.data = None

    async def load_restore():
        return None
    c._load_restore = load_restore
    return c


def test_offline_robot_fails_the_first_refresh_after_a_few_attempts(monkeypatch):
    c = _coord(monkeypatch, online=False)
    with pytest.raises(UpdateFailed):
        asyncio.run(c._update_once())
    # get_device_info, then the status read and its retries: no capability getters at all.
    assert c.client.attempts == ["get_device_info"] + ["multi"] * C.STATUS_RETRIES
    assert c._caps_attempts == 0 and not c._caps_fetched      # nothing learnt: probe again later


def test_unreachable_component_list_skips_the_probes(monkeypatch):
    c = _coord(monkeypatch, online=False)
    c._info_fetched = True          # device info read on an earlier poll
    asyncio.run(c._fetch_capabilities())
    assert c.client.attempts == ["getComponentList"]
    assert c._caps_attempts == 0 and not c._caps_fetched


def test_robot_that_answers_still_runs_the_probes(monkeypatch):
    c = _coord(monkeypatch, online=True)
    with pytest.raises(UpdateFailed):
        asyncio.run(c._update_once())
    probed = set(c.client.attempts)
    assert {"getComponentList", "getChildLockInfo"} <= probed
    assert {g for g, _, _ in TapoVacuumClient.BOOL_SETTINGS.values()} <= probed
    assert {g for g, _, _ in TapoVacuumClient.DOCK_ACTIONS.values()} <= probed
    assert c.components == {"clean": 1} and c.bool_settings_supported == ["child_lock"]
    assert c._caps_fetched


class _Stop(Exception):
    pass


def test_probe_runs_on_the_same_poll_once_the_status_read_answers(monkeypatch):
    """One dropped device info read must not leave setup without its probed entities."""
    c = _coord(monkeypatch, online=True)
    send = c.client.send

    def flaky(method, params=None):
        if method == "get_device_info" and "get_device_info" not in c.client.attempts:
            c.client.attempts.append(method)
            raise requests.ConnectTimeout("connect timeout=15")
        return send(method, params)
    c.client.send = flaky

    async def fetch_status():
        assert not c._caps_fetched          # not probed before the status read
        return {"status_code": 6}
    c._fetch_status = fetch_status
    c._map_base = c._map_read_at = None
    c._map_retry = c._map_warned = False
    c._refresh_map = lambda: None

    def stop():                             # the rest of the poll is not under test
        raise _Stop
    c._note_rotation = stop
    with pytest.raises(_Stop):
        asyncio.run(c._update_once())
    assert c._caps_fetched and c.bool_settings_supported == ["child_lock"]


def _status_ok(c):
    """Status answers; the rest of the poll is not under test."""
    async def fetch_status():
        return {"status_code": 6}
    c._fetch_status = fetch_status
    c._map_base = c._map_read_at = None
    c._map_retry = c._map_warned = False
    c._refresh_map = lambda: None

    def stop():
        raise _Stop
    c._note_rotation = stop


def test_component_list_that_never_reads_still_ends_the_probing(monkeypatch):
    """Status reads fine but getComponentList always fails with a non-device error (an
    unreadable reply): each poll counts an attempt, so probing stops at CAPS_ATTEMPTS and
    the settings that do answer are found."""
    c = _coord(monkeypatch, online=True)
    c._info_fetched = True
    send = c.client.send

    def bad_components(method, params=None):
        if method == "getComponentList":
            c.client.attempts.append(method)
            raise RuntimeError("unreadable reply")
        return send(method, params)
    c.client.send = bad_components
    _status_ok(c)
    for poll in range(1, c.CAPS_ATTEMPTS + 1):
        with pytest.raises(_Stop):
            asyncio.run(c._update_once())
        assert c._caps_attempts == poll
    assert c._caps_fetched and c.bool_settings_supported == ["child_lock"]
    c.client.attempts.clear()
    with pytest.raises(_Stop):
        asyncio.run(c._update_once())
    assert c.client.attempts == []          # done: no more component list reads


def test_later_probe_asks_for_one_reload_per_key(monkeypatch):
    """Entities set up without the probed ones: a later probe that finds them reloads the
    entry once; the same key found again (after that reload) does not reload it again."""
    reloads = []
    hass = Hass()
    hass.data = {}
    hass.config_entries = types.SimpleNamespace(async_schedule_reload=reloads.append)
    entry = types.SimpleNamespace(entry_id="e1", options={})

    def probed(online_keys):
        c = _coord(monkeypatch, online=True)
        c.hass, c.entry, c._reload_asked = hass, entry, False
        c.data = {"status_code": 6}         # setup is over: entities exist
        c.client.probe_bool_settings = lambda: (dict.fromkeys(online_keys, True), True)
        c.client.probe_dock_actions = lambda: ([], True)
        asyncio.run(c._fetch_capabilities())
        return c

    probed(["child_lock"])
    assert reloads == ["e1"]
    probed(["child_lock"])                  # the reloaded entry finds it again
    assert reloads == ["e1"]
    probed(["child_lock", "ai_avoid"])      # a different key still gets its entity
    assert reloads == ["e1", "e1"]
