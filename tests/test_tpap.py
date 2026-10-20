import os

import pytest

from custom_components.tapo_rv30.tpap import (
    _CIPHER_LABELS, _decrypt, _derive_cipher, _encode_w, _encrypt, _nonce, _build_cred,
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
