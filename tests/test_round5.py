"""Regression tests for the 0.31 transport fixes: a TLS hiccup is not a wrong certificate,
writes are not resent after an unreadable reply, sequence numbers are reserved before sending,
and a robot cannot ask for an absurd number of password rounds."""
import json
import ssl

import pytest
import requests

from custom_components.tapo_rv30 import tpap as T


def _client(tmp_path):
    c = T.TapoVacuumClient("192.0.2.1", "u", "p", cache_dir=tmp_path)
    c._session_id, c._seq, c._key, c._base_nonce = "s1", 10, b"k" * 16, b"n" * 12
    return c


def _ssl_error(inner):
    return requests.exceptions.SSLError(requests.packages.urllib3.exceptions.MaxRetryError(None, "/", inner))


def test_only_a_refused_certificate_counts_as_one():
    wrong = ssl.SSLCertVerificationError(1, "certificate verify failed")
    wrong.verify_code = 20
    expired = ssl.SSLCertVerificationError(1, "certificate has expired")
    expired.verify_code = 10
    assert T._cert_rejected(_ssl_error(wrong))
    assert not T._cert_rejected(_ssl_error(expired))                     # a wrong clock, not an impostor
    assert not T._cert_rejected(_ssl_error(ssl.SSLEOFError(8, "EOF")))   # robot rebooting mid-handshake


def test_unreadable_reply_to_a_write_is_not_resent(tmp_path, monkeypatch):
    c = _client(tmp_path)
    posts = []

    def post(*a, **k):
        posts.append(1)
        return b"\x00\x00\x00\x0a" + b"garbage that does not decrypt"
    monkeypatch.setattr(c, "_post", post)
    with pytest.raises(RuntimeError, match="not sent again"):
        c._send_once("setSwitchClean", {"clean_on": True})
    assert len(posts) == 1 and c._session_id == ""     # session dropped, nothing resent here


def test_plain_error_reply_is_classified(tmp_path, monkeypatch):
    c = _client(tmp_path)
    monkeypatch.setattr(c, "_post", lambda *a, **k: json.dumps({"error_code": -40401}).encode())
    with pytest.raises(T._SessionLost):         # an expired session: re-handshake and resend as before
        c._send_once("setSwitchClean", {"clean_on": True})


def test_sequence_is_reserved_before_sending_and_bounded(tmp_path, monkeypatch):
    c = _client(tmp_path)
    seen = []

    def post(*a, **k):
        seen.append(c._seq)
        raise requests.exceptions.ConnectionError("reset")
    monkeypatch.setattr(c, "_post", post)
    with pytest.raises(Exception):
        c._send_once("getVacStatus", None)
    assert seen == [11]                         # advanced (and saved) before the request left
    c._session_id, c._seq = "s1", 0xFFFFFFFF
    with pytest.raises(T._SessionLost, match="out of range"):
        c._send_once("getVacStatus", None)


def test_closed_client_saves_no_session(tmp_path):
    c = _client(tmp_path)
    c.close()
    c._save_session()
    assert not c._cache.exists()


def test_clock_and_name_problems_are_not_a_wrong_certificate():
    for code in (9, 10):                                    # not yet valid, expired
        e = ssl.SSLCertVerificationError(1, "certificate time")
        e.verify_code = code
        assert not T._cert_rejected(_ssl_error(e))


def test_absurd_password_rounds_are_refused(tmp_path, monkeypatch):
    c = _client(tmp_path)
    reply = {"error_code": 0, "result": {"iterations": T._MAX_ITERATIONS + 1}}
    monkeypatch.setattr(c, "_post", lambda *a, **k: reply)
    with pytest.raises(T.AuthError, match="iterations"):
        c._handshake("userpw", "secret")


def test_reply_numbering_is_counted_and_bounded(tmp_path):
    c = _client(tmp_path)
    c._note_rseq(1, 1)
    c._note_rseq(2, 5)
    c._note_rseq(3, 5)
    st = c.rseq_stats
    assert (st["equal"], st["different"], st["repeated"]) == (1, 2, 1) and st["last_mismatch"] == [3, 5]
    for n in range(2000):
        c._note_rseq(n, n)
    assert len(st["seen"]) <= 1000


def test_reserved_sequence_is_on_disk(tmp_path, monkeypatch):
    c = _client(tmp_path)
    monkeypatch.setattr(c, "_post", lambda *a, **k: (_ for _ in ()).throw(requests.exceptions.ConnectionError()))
    with pytest.raises(Exception):
        c._send_once("getVacStatus", None)
    assert json.loads(c._cache.read_text())["seq"] == 11


def test_failed_session_save_removes_the_old_copy(tmp_path, monkeypatch, caplog):
    c = _client(tmp_path)
    c._save_session()
    assert c._cache.exists()
    monkeypatch.setattr(T.os, "open", lambda *a, **k: (_ for _ in ()).throw(OSError("disk full")))
    c._save_session()
    c._save_session()
    assert not c._cache.exists()
    assert sum("could not save" in r.message for r in caplog.records) == 1


def test_dropouts_and_device_errors_are_told_apart():
    assert T._is_dropout(T.AuthError("x")) and T._is_dropout(requests.exceptions.ConnectionError())
    assert not T._is_dropout(RuntimeError("Device error -1"))
