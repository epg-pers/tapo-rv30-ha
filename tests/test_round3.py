"""Regression tests for the 0.29 fixes: hostile or odd robot data, security downgrades,
batching, map setup plans, the planner and voice names."""
import base64
import gzip
import io
import ssl
import tarfile
import types
from datetime import datetime

import pytest
import requests

from custom_components.tapo_rv30 import mapbackup, mapdata, planlogic, voice
from custom_components.tapo_rv30 import mapsnapshot as ms
from custom_components.tapo_rv30 import tpap as T


# ---- robot data ---------------------------------------------------------------------
def test_lz4_refuses_an_implausible_size_before_allocating():
    with pytest.raises(mapdata.MapValidationError):
        mapdata.lz4_block_decompress(b"\x00" * 10, 10_000_000_000)


def test_path_with_a_bad_length_is_empty():
    assert mapdata.decode_path("", "not a number") == []


def test_names_that_are_not_strings_are_no_name():
    assert mapdata.b64name(None) == "" and mapdata.b64name(5) == ""


def test_schedule_and_dnd_fields_of_any_type():
    s = mapdata.decode_schedule({"s_min": "480", "week_day": "127"}, {}, None)
    assert s["time"] == "08:00" and len(s["days"]) == 7
    assert mapdata.decode_schedule({"s_min": None}, {}, None)["time"] == "00:00"
    assert mapdata.dnd_window({"do_not_disturb": 1, "s_min": None, "e_min": "480"})["end"] == "08:00"


def test_one_off_schedule_keeps_its_date():
    s = mapdata.decode_schedule({"s_min": 630, "mode": "once", "year": 2026, "month": 10, "day": 21}, {}, None)
    assert s["date"] == "2026-10-21"
    now = datetime(2026, 10, 21, 10, 0)
    assert planlogic.schedule_soon(now, [{**s, "enabled": True}]) is not None
    assert planlogic.schedule_soon(datetime(2026, 10, 22, 10, 0), [{**s, "enabled": True}]) is None


def test_prompt_and_error_lists_are_normalised():
    assert [p["code"] for p in mapdata.new_prompts(None, {"prompts": "12"})] == [12]
    assert T._ints(7) == [7] and T._ints(["3", None, "x", True]) == [3]
    assert T._ids([1, "a", None, {}]) == [1, "a"]


def _bkmap(payload: bytes) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        info = tarfile.TarInfo("map.gridmap")
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
    return b"MZ" + b"\0" * 16 + b"\x55\xaa\x02\0\0\0" + bytes([32]) + b"a" * 32 + gzip.compress(buf.getvalue())


def test_backup_that_unpacks_too_far_is_refused(monkeypatch):
    monkeypatch.setattr(mapbackup, "MAX_UNPACKED", 64 * 1024)
    with pytest.raises(ValueError, match="unpacks to more"):
        mapbackup.parse_bkmap(_bkmap(b"\0" * (1024 * 1024)))


def test_backup_with_a_broken_archive_is_a_value_error():
    with pytest.raises(ValueError):
        mapbackup.parse_bkmap(b"MZ" + b"\0" * 16 + b"\x55\xaa\x02\0\0\0" + bytes([32]) + b"a" * 32
                              + gzip.compress(b"not a tar at all" * 50))


# ---- map setup plans ------------------------------------------------------------------
def _name(s):
    return base64.b64encode(s.encode()).decode()


def test_plan_counts_only_added_zones_and_skips_orphan_schedules():
    z1 = {"type": "forbid", "id": 1, "vertexs": [[0, 0], [1, 0], [1, 1]]}
    z2 = {"type": "forbid", "id": 2, "vertexs": [[5, 5], [6, 5], [6, 6]]}
    snap = ms.build(1, "Home", [{"type": "room", "id": 1, "name": _name("Hall")}, z1, z2], [], [],
                    [{"id": "S1", "s_min": 60, "week_day": 1, "clean_attr": {"map_id": 1, "custom_rule_id": 9}}],
                    "now")
    plan = ms.plan(snap, 1, [{"type": "room", "id": 1, "name": _name("Hall")}, z1], [], [], [])
    assert ms.summary(plan)["zones"] == {"forbid": 1}
    assert plan["schedules"] == [] and any("preset is not in the saved setup" in s for s in plan["skipped"])


def test_unnamed_saved_room_never_blanks_a_name():
    snap = ms.build(1, "Home", [{"type": "room", "id": 1, "name": ""}], [], [], [], "now")
    plan = ms.plan(snap, 1, [{"type": "room", "id": 1, "name": _name("Hall")}], [], [], [])
    assert plan["rooms"] is None


# ---- planner ----------------------------------------------------------------------------
def test_unknown_battery_waits_when_a_minimum_is_set():
    cfg = dict(planlogic.DEFAULT_CONFIG, enabled=True,
               windows={"weekdays": ["00:00", "23:59"], "weekends": ["00:00", "23:59"]})
    now = datetime(2026, 10, 21, 12, 0)
    room = planlogic.RoomState("1:1", "Kitchen", now.timestamp() - 10 * 86400, 2, [], False)
    snap = planlogic.Snapshot(now=now, robot_docked=True, robot_busy=None, robot_error=False, battery=None,
                              dnd=None, people_home=[], schedules=[], skip_today=False, ran_window=None,
                              rooms=[room], robot_now=now)
    d = planlogic.decide(snap, cfg)
    assert d.action == "wait" and d.waiting_for == "battery"


# ---- TPAP client ----------------------------------------------------------------------------
def _client(tmp_path):
    return T.TapoVacuumClient("192.0.2.1", "u", "p", cache_dir=tmp_path)


def test_closed_client_sends_nothing(tmp_path):
    c = _client(tmp_path)
    c.close()
    with pytest.raises(RuntimeError, match="closed"):
        c.send("getVacStatus")


def _discover_reply(tls, pake, dac=False):
    return {"error_code": 0, "result": {"mac": "11-22-33-44-55-66",
                                        "tpap": {"pake": pake, "tls": tls, "port": 4433, "dac": dac}}}


def test_weaker_discovery_than_at_setup_is_refused(tmp_path, monkeypatch):
    c = _client(tmp_path)
    c.expected_security = {"tls": 1, "pake": [2], "dac": False}
    monkeypatch.setattr(c, "_post", lambda *a, **k: _discover_reply(1, [0]))
    with pytest.raises(T.AuthError, match="weaker security"):
        c._discover()
    monkeypatch.setattr(c, "_post", lambda *a, **k: _discover_reply(1, [2]))
    c._discover()                        # the same offer is fine
    assert c.security == {"tls": 1, "pake": [2], "dac": False}


def test_pinned_robot_failing_the_pin_fails_closed(tmp_path, monkeypatch):
    c = _client(tmp_path)
    c.expected_security = {"tls": 2, "pake": [2], "dac": False}

    def wrong_cert(*a, **k):
        err = ssl.SSLCertVerificationError(1, "certificate verify failed")
        err.verify_code = 20
        raise requests.exceptions.SSLError(err)
    monkeypatch.setattr(c, "_post", wrong_cert)
    with pytest.raises(T.AuthError, match="pinned"):
        c._discover()

    def dropped(*a, **k):     # the robot rebooting mid-handshake is not a wrong certificate
        raise requests.exceptions.SSLError(ssl.SSLEOFError(8, "EOF occurred in violation of protocol"))
    monkeypatch.setattr(c, "_post", dropped)
    with pytest.raises(requests.exceptions.SSLError):
        c._discover()


def test_batch_refused_after_one_worked_falls_back_for_that_chunk_only(tmp_path, monkeypatch):
    c = _client(tmp_path)
    calls = []

    def send(method, params=None):
        calls.append(method)
        if method == "multipleRequest":
            if calls.count("multipleRequest") == 2:
                raise RuntimeError("Device error -1")
            return {"result": {"responses": [{"method": r["method"], "error_code": 0, "result": {"ok": 1}}
                                             for r in params["requests"]]}}
        return {"result": {"single": 1}}
    monkeypatch.setattr(c, "send", send)
    reqs = [(f"get{i}", None) for i in range(7)]
    out = c.send_multi(reqs)
    assert set(out) == {m for m, _ in reqs} and c._multi_supported is True
    assert calls.count("get5") == 1 and calls.count("get0") == 0


# ---- voice -----------------------------------------------------------------------------------
def _robots(*names):
    return [types.SimpleNamespace(device_name=n) for n in names]


def test_voice_names_whole_words_longest_and_punctuation():
    bot, jarvis, two, r2 = _robots("Bot", "Jarvis", "Jarvis Two", "R2-D2")
    assert voice._named([bot, jarvis], "send the robot home") is None
    assert voice._named([jarvis, two], "tell jarvis two to clean") is two
    assert voice._named([jarvis, two], "send jarvis home") is jarvis
    assert voice._named([r2, jarvis], "send r2 d2 home") is r2
    assert voice._named(_robots("Jarvis", "Jarvis"), "send jarvis home") is None
