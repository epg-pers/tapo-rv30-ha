"""Two robots on one account: the robot answering at an entry's address must be the one the
entry was set up for (its MAC from discovery), without ever refusing a single robot whose MAC
is unknown, malformed or written differently."""
import pytest

from custom_components.tapo_rv30 import tpap as T
from custom_components.tapo_rv30.const import CONF_MAC, CONF_SECURITY

MAC_A = "E0-D3-62-AA-AA-AA"
MAC_B = "E0-D3-62-BB-BB-BB"
SEC = {"tls": 1, "pake": [2], "dac": False}


def _client(tmp_path, expected_mac=None):
    c = T.TapoVacuumClient("192.0.2.1", "u", "p", cache_dir=tmp_path)
    c.expected_mac = expected_mac
    return c


def _discover_reply(mac):
    result = {"tpap": {"pake": [2], "tls": 1, "port": 4433, "dac": False}}
    if mac is not ...:
        result["mac"] = mac
    return {"error_code": 0, "result": result}


@pytest.mark.parametrize(("value", "expected"), [
    ("E0-D3-62-AA-BB-CC", "e0d362aabbcc"),
    ("e0:d3:62:aa:bb:cc", "e0d362aabbcc"),
    ("E0D362AABBCC", "e0d362aabbcc"),
    (" e0.d3.62.aa.bb.cc ", "e0d362aabbcc"),
    (None, None), ("", None), ("unknown", None), ("E0-D3-62-AA-BB", None),
    ("E0-D3-62-AA-BB-CC-DD", None), ("00:00:00:00:00:00", None), ("FF-FF-FF-FF-FF-FF", None),
    (0xE0D362AABBCC, None), (["E0-D3-62-AA-BB-CC"], None),
])
def test_normalise_mac(value, expected):
    assert T.normalise_mac(value) == expected


def test_same_robot_passes_whatever_the_mac_format(tmp_path, monkeypatch):
    c = _client(tmp_path, "E0-D3-62-AA-BB-CC")
    monkeypatch.setattr(c, "_post", lambda *a, **k: _discover_reply("e0:d3:62:aa:bb:cc"))
    c._discover()
    assert c._device_mac == "e0:d3:62:aa:bb:cc"


def test_a_different_robot_is_refused_without_asking_for_a_password(tmp_path, monkeypatch):
    c = _client(tmp_path, MAC_B)
    monkeypatch.setattr(c, "_post", lambda *a, **k: _discover_reply(MAC_A))
    with pytest.raises(T.WrongDevice, match=r"e0:d3:62:aa:aa:aa\) now answers at 192\.0\.2\.1; .*reconfigure") as err:
        c._discover()
    assert not isinstance(err.value, T.AuthError)
    assert isinstance(err.value, RuntimeError)
    assert T._is_dropout(err.value)        # a batch stops at it rather than trying every getter


@pytest.mark.parametrize("expected", [None, "", "not a mac", "E0-D3-62", "00-00-00-00-00-00"])
def test_unknown_stored_mac_skips_the_check(tmp_path, monkeypatch, expected):
    c = _client(tmp_path, expected)
    monkeypatch.setattr(c, "_post", lambda *a, **k: _discover_reply(MAC_A))
    c._discover()
    assert c._device_mac == MAC_A


@pytest.mark.parametrize("received", [..., None, "", "zz-zz", "E0-D3-62-AA", "00:00:00:00:00:00"])
def test_unknown_received_mac_skips_the_check(tmp_path, monkeypatch, received):
    c = _client(tmp_path, MAC_B)
    monkeypatch.setattr(c, "_post", lambda *a, **k: _discover_reply(received))
    c._discover()


def test_session_loss_reaching_another_robot_fails_plainly(tmp_path, monkeypatch):
    """The re-handshake after a lost session stops at discovery: no handshake with the other
    robot, no second attempt, and a RuntimeError the coordinator turns into "unavailable"."""
    c = _client(tmp_path, MAC_B)
    c._session_id, c._seq, c._key, c._base_nonce = "s1", 10, b"k" * 16, b"n" * 12
    posts, handshakes = [], []

    def lost(*a, **k):
        raise T._SessionLost("session expired")
    monkeypatch.setattr(c, "_send_once", lost)
    monkeypatch.setattr(c, "_post", lambda *a, **k: posts.append(a) or _discover_reply(MAC_A))
    monkeypatch.setattr(c, "_handshake", lambda *a: handshakes.append(a))
    with pytest.raises(T.WrongDevice):
        c.send("getVacStatus")
    assert handshakes == [] and len(posts) == 1
    # The next poll tries once more (the right robot may be back) and fails the same way.
    with pytest.raises(T.WrongDevice):
        c.get_status()
    assert handshakes == [] and len(posts) == 2


def test_swapped_robots_repro(tmp_path, monkeypatch):
    """Entry B is set up against robot B, then robot A takes B's address and B's session is lost."""
    c = _client(tmp_path)
    answers = iter([_discover_reply(MAC_B), _discover_reply(MAC_A)])
    monkeypatch.setattr(c, "_post", lambda *a, **k: next(answers))
    handshakes = []

    def handshake(ptype, secret):
        handshakes.append(c._device_mac)
        c._session_id = "s1"
    monkeypatch.setattr(c, "_handshake", handshake)
    c.authenticate()
    data = T.learned_entry_data({}, c.security, c.session_mac)
    c.expected_security, c.expected_mac = data[CONF_SECURITY], data[CONF_MAC]
    c._clear_session()
    with pytest.raises(T.WrongDevice):
        c.authenticate()
    assert handshakes == [MAC_B]


# ---- learning (trust on first use, in async_setup_entry) -----------------------------
def test_first_setup_learns_the_mac(tmp_path):
    c = _client(tmp_path)
    c._device_mac, c._tpap_pake, c._tls_mode, c._session_id = MAC_A, [2], 1, "s1"
    data = T.learned_entry_data({"host": "192.0.2.1"}, c.security, c.session_mac)
    assert data == {"host": "192.0.2.1", CONF_SECURITY: SEC, CONF_MAC: "e0d362aaaaaa"}


def test_an_entry_that_has_the_mac_is_not_rewritten():
    stored = {"host": "192.0.2.1", CONF_SECURITY: SEC, CONF_MAC: "e0d362aaaaaa"}
    assert T.learned_entry_data(stored, SEC, "e0d362aaaaaa") is None
    assert T.learned_entry_data(stored, SEC, "e0d362bbbbbb") is None      # never replaced
    assert T.learned_entry_data(stored, SEC, None) is None


def test_an_older_entry_learns_the_mac_and_keeps_the_rest():
    old = {"host": "192.0.2.1", "transport": "tpap", CONF_SECURITY: SEC}
    assert T.learned_entry_data(old, SEC, MAC_A) == {**old, CONF_MAC: "e0d362aaaaaa"}
    # A malformed stored MAC is unknown, so the robot's real one replaces it.
    assert T.learned_entry_data({**old, CONF_MAC: "junk"}, SEC, MAC_A) == {**old, CONF_MAC: "e0d362aaaaaa"}


def test_no_usable_mac_learns_nothing():
    old = {"host": "192.0.2.1", CONF_SECURITY: SEC}
    for mac in (None, "", "junk", "00-00-00-00-00-00"):
        assert T.learned_entry_data(old, SEC, mac) is None


def test_security_learning_is_unchanged():
    assert T.learned_entry_data({}, SEC, None) == {CONF_SECURITY: SEC}
    stronger = {"tls": 2, "pake": [2], "dac": False}
    assert T.learned_entry_data({CONF_SECURITY: SEC}, stronger, None) == {CONF_SECURITY: stronger}
    weaker = {"tls": 1, "pake": [0, 2], "dac": False}
    assert T.learned_entry_data({CONF_SECURITY: SEC}, weaker, None) is None


def test_session_mac_needs_a_session(tmp_path):
    c = _client(tmp_path)
    c._device_mac = MAC_A
    assert c.session_mac is None          # discovery alone (a failed handshake) proves nothing
    c._session_id = "s1"
    assert c.session_mac == "e0d362aaaaaa"


# ---- cached session -------------------------------------------------------------------
def _cache_session(tmp_path, mac):
    c = _client(tmp_path)
    c._device_mac, c._tpap_pake, c._tls_mode = mac, [2], 1
    c._session_id, c._seq, c._key, c._base_nonce = "s1", 10, b"k" * 16, b"n" * 12
    c._save_session()


def test_cached_session_with_another_robot_is_not_used(tmp_path):
    _cache_session(tmp_path, MAC_A)
    c = _client(tmp_path, MAC_B)
    assert c._load_session() is False
    assert c._session_id == "" and c._device_mac == ""


@pytest.mark.parametrize(("cached", "expected"), [
    (MAC_A, "e0:d3:62:aa:aa:aa"),     # same robot, other format
    (MAC_A, None),                    # entry from before the MAC was stored
    ("", MAC_B),                      # cache without a MAC
    ("junk", MAC_B),
])
def test_cached_session_is_used_unless_known_to_be_another_robot(tmp_path, cached, expected):
    _cache_session(tmp_path, cached)
    c = _client(tmp_path, expected)
    assert c._load_session() is True
    assert c._session_id == "s1"


# ---- coordinator ----------------------------------------------------------------------
def test_poll_fails_at_once_without_counting_the_robot_as_unreachable(monkeypatch):
    """Another robot at the address is not a dropout: no retries with backoff, and no
    "stopped answering" repair after UNREACHABLE_AFTER."""
    import asyncio
    import types

    from custom_components.tapo_rv30 import coordinator as C

    calls, sleeps, failures = [], [], []

    def get_status():
        calls.append(1)
        raise T.WrongDevice("a different robot (MAC e0:d3:62:aa:aa:aa) now answers at 192.0.2.1")

    async def executor(fn, *args):
        return fn(*args)

    async def sleep(delay):
        sleeps.append(delay)

    coord = C.TapoCoordinator.__new__(C.TapoCoordinator)
    coord.hass = types.SimpleNamespace(async_add_executor_job=executor)
    coord.client = types.SimpleNamespace(get_status=get_status)
    monkeypatch.setattr(coord, "_note_failure", lambda: failures.append(1), raising=False)
    monkeypatch.setattr(C.asyncio, "sleep", sleep)
    with pytest.raises(C.UpdateFailed, match="different robot") as err:
        asyncio.run(coord._fetch_status())
    assert isinstance(err.value.__cause__, T.WrongDevice)
    assert calls == [1] and sleeps == [] and failures == []
