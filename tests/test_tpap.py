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


def test_set_water_reads_and_writes_under_the_lock():
    c = _client_with_send({"getCleanAttr": {"suction": 2, "cistern": 0, "clean_number": 1},
                           "setCleanAttr": {}})
    c.set_water(3)
    assert c._calls[-1] == ("setCleanAttr", {"suction": 2, "cistern": 3, "clean_number": 1, "type": "global"})


def test_lz4_decompress_is_cached():
    from custom_components.tapo_rv30.mapdata import lz4_block_decompress
    block = bytes([0x30]) + b"XYZ"
    a = lz4_block_decompress(block, 3); b = lz4_block_decompress(block, 3)
    assert a == b"XYZ" and a is b
