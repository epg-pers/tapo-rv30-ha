import os

import pytest

from custom_components.tapo_rv30.tpap import (
    _CIPHER_LABELS,
    _build_cred,
    _decrypt,
    _derive_cipher,
    _encode_w,
    _encrypt,
    _nonce,
)


@pytest.mark.parametrize("value,expected", [
    (0, b"\x00"),
    (1, b"\x01"),                 # odd length, high bit clear: left as is
    (0x80, b"\x00\x80"),          # odd length, high bit set: padded
    (0x1234, b"\x12\x34"),        # even length
    (0x800000, b"\x00\x80\x00\x00"),
])
def test_encode_w(value, expected):
    assert _encode_w(value) == expected


@pytest.mark.parametrize("cipher", sorted(_CIPHER_LABELS))
def test_encrypt_decrypt_round_trip(cipher):
    key, nonce = _derive_cipher(os.urandom(32), cipher)
    assert len(key) == _CIPHER_LABELS[cipher]["kl"]
    for seq in (1, 2, 1000):
        ct = _encrypt(cipher, key, nonce, b'{"method":"getVacStatus"}', seq)
        assert _decrypt(cipher, key, nonce, ct, seq) == b'{"method":"getVacStatus"}'
    with pytest.raises(Exception):
        _decrypt(cipher, key, nonce, ct, seq + 1)     # wrong sequence -> wrong nonce


def test_nonce_changes_with_seq():
    base = os.urandom(12)
    assert _nonce(base, 1) != _nonce(base, 2)
    assert len(_nonce(base, 1)) == 12


def test_build_cred_plain_and_shadow():
    assert _build_cred({}, "me@x.com", "pw", "") == "me@x.com/pw"
    assert _build_cred({}, "", "pw", "") == "pw"
    sha1 = _build_cred({"type": "password_shadow", "params": {"passwd_id": 2}}, "me@x.com", "pw", "")
    assert len(sha1) == 40 and sha1 == sha1.lower()


def _client_with_send(responses):
    """A client whose send() answers from a dict of method -> result or exception."""
    from custom_components.tapo_rv30.tpap import TapoVacuumClient
    c = TapoVacuumClient.__new__(TapoVacuumClient)
    import threading
    c._lock = threading.RLock()
    calls = []

    def send(method, params=None):
        calls.append((method, params))
        r = responses[method]
        if isinstance(r, Exception):
            raise r
        return {"result": r}
    c.send = send
    c._calls = calls
    return c


def test_probe_dock_actions_device_error_is_final_transport_error_is_not():
    from custom_components.tapo_rv30.tpap import TapoVacuumClient
    getters = [g for g, _, _ in TapoVacuumClient.DOCK_ACTIONS.values()]
    c = _client_with_send({g: RuntimeError("Device error -1002 on " + g) for g in getters})
    assert c.probe_dock_actions() == ([], True)
    c = _client_with_send({**{g: {} for g in getters}, getters[0]: RuntimeError("transport error: timed out")})
    actions, complete = c.probe_dock_actions()
    assert complete is False and len(actions) == len(getters) - 1


def test_probe_bool_settings_reports_inconclusive():
    from custom_components.tapo_rv30.tpap import TapoVacuumClient
    items = list(TapoVacuumClient.BOOL_SETTINGS.items())
    responses = {getter: {field: True} for _, (getter, _, field) in items}
    responses[items[0][1][0]] = RuntimeError("Device error -1002")
    out, complete = _client_with_send(responses).probe_bool_settings()
    assert complete is True and items[0][0] not in out and out[items[1][0]] is True
    responses[items[1][1][0]] = RuntimeError("transport error: reset")
    out, complete = _client_with_send(responses).probe_bool_settings()
    assert complete is False and items[1][0] not in out


def test_set_water_sends_only_the_changed_level():
    # A partial setCleanAttr body is accepted (verified on an RV30 Max Plus, 1.3.3); echoing the
    # read back could carry flags that make the robot ignore the levels.
    c = _client_with_send({"setCleanAttr": {}})
    c.set_water(3)
    assert c._calls == [("setCleanAttr", {"type": "global", "cistern": 3})]


def test_lz4_decompress_is_cached():
    from custom_components.tapo_rv30.mapdata import lz4_block_decompress
    block = bytes([0x30]) + b"XYZ"
    a = lz4_block_decompress(block, 3); b = lz4_block_decompress(block, 3)
    assert a == b"XYZ" and a is b


def _client_status(status):
    """A client that reports `status` and records the setSwitchClean / setRobotPause it sends."""
    c = _client_with_send({"getVacStatus": {"status": status}, "setSwitchClean": {}, "setRobotPause": {},
                           "getMapInfo": {"current_map_id": 1, "map_list": []}})
    return c


@pytest.mark.parametrize("status", [7, 10, 12, 14])
def test_start_resumes_every_paused_state(status):
    c = _client_status(status)
    c.start()
    assert [m for m, _ in c._calls] == ["getVacStatus", "setRobotPause"]
    assert c._calls[1][1] == {"pause": False}


@pytest.mark.parametrize("status", [1, 2, 13])
def test_start_while_working_is_a_no_op(status):
    c = _client_status(status)
    c.start()
    assert [m for m, _ in c._calls] == ["getVacStatus"]


@pytest.mark.parametrize("status", [3, 11])
def test_start_under_remote_or_go_to_says_why(status):
    from custom_components.tapo_rv30.tpap import RobotBusy
    c = _client_status(status)
    with pytest.raises(RobotBusy, match="stop it before starting a clean"):
        c.start()


def test_start_from_dock_starts_a_clean():
    c = _client_status(6)
    c.start()
    assert [m for m, _ in c._calls] == ["getVacStatus", "setSwitchClean"]


@pytest.mark.parametrize("call", [
    lambda c: c.clean_rooms([1], 1), lambda c: c.clean_zones(1, [[0, 0, 1, 1]], 2, 1, 1),
    lambda c: c.clean_spot(), lambda c: c.run_preset(2, 1), lambda c: c.clean_custom_rule(2, 1)])
@pytest.mark.parametrize("status,word", [(1, "is cleaning"), (7, "is paused"), (11, "is going to a point")])
def test_new_cleans_refused_readably_while_busy(call, status, word):
    from custom_components.tapo_rv30.tpap import RobotBusy
    c = _client_status(status)
    with pytest.raises(RobotBusy, match=word):
        call(c)
    assert "setSwitchClean" not in [m for m, _ in c._calls]


def test_resend_safe_only_for_reads():
    from custom_components.tapo_rv30.tpap import _resend_safe
    assert _resend_safe("getVacStatus", None)
    assert _resend_safe("multipleRequest", {"requests": [{"method": "getVacStatus"}, {"method": "getBatteryInfo"}]})
    assert not _resend_safe("multipleRequest", {"requests": [{"method": "getVacStatus"}, {"method": "setVolume"}]})
    assert not _resend_safe("setSwitchClean", {})


def _timeout_client(monkeypatch):
    import threading

    import requests

    from custom_components.tapo_rv30 import tpap
    c = tpap.TapoVacuumClient.__new__(tpap.TapoVacuumClient)
    c._lock = threading.RLock()
    c._seq, c._cipher_id, c._key, c._base_nonce, c._session_id = 1, 0, b"", b"", "s"
    c.posts, c.cleared = [], []
    monkeypatch.setattr(tpap, "_encrypt", lambda *a: b"")
    c._ensure_auth = lambda: None
    c.authenticate = lambda: None
    c._clear_session = lambda: c.cleared.append(1)

    def post(path, body=None, binary=False):
        c.posts.append(path)
        raise requests.ReadTimeout("read timed out")
    c._post = post
    return c


def test_write_is_not_resent_after_a_lost_reply(monkeypatch):
    c = _timeout_client(monkeypatch)
    with pytest.raises(RuntimeError, match="not sent again"):
        c.send("setSwitchClean", {"clean_on": True})
    assert len(c.posts) == 1 and c.cleared       # sent once; next call starts a fresh session


def test_read_is_retried_after_a_lost_reply(monkeypatch):
    c = _timeout_client(monkeypatch)
    with pytest.raises(RuntimeError):
        c.send("getVacStatus")
    assert len(c.posts) == 2


@pytest.mark.parametrize("tls,tport,url,verify", [
    (0, 4433, "https://10.0.0.5:4433", False),    # RV30 Max Plus Gen2: tls 0 on the https port
    (0, None, "https://10.0.0.5:4433", False),
    (0, 80, "http://10.0.0.5:80", False),         # plain http only on a different port it names
    (1, 4433, "https://10.0.0.5:4433", False),
    (2, None, "https://10.0.0.5:4433", True),
])
def test_tls_mode_keeps_https_on_the_discovery_port(tls, tport, url, verify):
    import requests

    from custom_components.tapo_rv30.tpap import TapoVacuumClient
    c = TapoVacuumClient.__new__(TapoVacuumClient)
    c.host, c.port, c._http = "10.0.0.5", 4433, requests.Session()
    c._tls_mode, c._tpap_port = tls, tport
    c._apply_tls_mode()
    assert c.base_url == url and c._verify is verify


def _conn_error_client(monkeypatch, exc):
    c = _timeout_client(monkeypatch)

    def post(path, body=None, binary=False):
        c.posts.append(path)
        raise exc
    c._post = post
    return c


def test_write_not_resent_after_connection_lost_mid_reply(monkeypatch):
    import requests
    c = _conn_error_client(monkeypatch, requests.ConnectionError("Connection aborted: RemoteDisconnected"))
    with pytest.raises(RuntimeError, match="not sent again"):
        c.send("setSwitchClean", {"clean_on": True})
    assert len(c.posts) == 1


def test_write_resent_when_it_never_left(monkeypatch):
    import requests
    from urllib3.exceptions import MaxRetryError, NewConnectionError
    refused = requests.ConnectionError(MaxRetryError(None, "/", NewConnectionError(None, "refused")))
    for exc in (refused, requests.ConnectTimeout("connect timed out"), requests.HTTPError("401")):
        c = _conn_error_client(monkeypatch, exc)
        with pytest.raises(RuntimeError):
            c.send("setSwitchClean", {"clean_on": True})
        assert len(c.posts) == 2, exc
