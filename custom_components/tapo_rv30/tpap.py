"""TPAP SPAKE2+ transport and vacuum client for Tapo RV30.

Handshake, cipher suites, TLS modes and credential handling follow the
reference behaviour reverse-engineered in python-kasa (PR #1592) with the
extensions from github.com/danieyal/tapo-rv30-ha (P-384/P-521 suites,
factory default passcode, TLS mode 2 with the TP-Link root CA, DAC proof).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import ssl
import struct
import tempfile
import threading
import warnings
from datetime import UTC, datetime
from pathlib import Path

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers.aead import AESCCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from ecdsa import NIST256p, NIST384p, NIST521p, ellipticcurve
from requests.adapters import HTTPAdapter
from urllib3.exceptions import InsecureRequestWarning

from .const import DOCKED_CODES

_LOGGER = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Crypto primitives
# ---------------------------------------------------------------------------
def _b64e(b: bytes) -> str: return base64.b64encode(b).decode()
def _b64d(s: str) -> bytes: return base64.b64decode(s)
def _md5hex(s: str) -> str: return hashlib.md5(s.encode()).hexdigest()
def _sha1hex(s: str) -> str: return hashlib.sha1(s.encode()).hexdigest()
def _sha256(d: bytes) -> bytes: return hashlib.sha256(d).digest()
def _sha512(d: bytes) -> bytes: return hashlib.sha512(d).digest()

def _hkdf(master: bytes, *, salt: bytes, info: bytes, length: int, algo: str = "SHA256") -> bytes:
    alg = hashes.SHA512() if algo.upper() == "SHA512" else hashes.SHA256()
    return HKDF(algorithm=alg, length=length, salt=salt, info=info).derive(master)

def _hkdf_expand(label: str, prk: bytes, dlen: int, alg: str) -> bytes:
    algorithm = hashes.SHA512() if alg.upper() == "SHA512" else hashes.SHA256()
    return HKDF(algorithm=algorithm, length=dlen,
                salt=b"\x00" * dlen, info=label.encode()).derive(prk)

def _hmac_fn(alg: str, key: bytes, data: bytes) -> bytes:
    h = hashlib.sha512 if alg.upper() == "SHA512" else hashlib.sha256
    return hmac.new(key, data, h).digest()

def _cmac_aes(key: bytes, data: bytes) -> bytes:
    c = CMAC(algorithms.AES(key)); c.update(data); return c.finalize()

def _pbkdf2(pw: bytes, salt: bytes, iters: int, length: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", pw, salt, iters, length)

# SPAKE2+ per-suite parameters: suite type -> (M, N, ecdsa curve, cryptography curve).
# Suites 1/2/8/9 are P-256, 3/4 are P-384 and 5 is P-521.
_SUITE_PARAMS = {
    "p256": (
        bytes.fromhex("02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f"),
        bytes.fromhex("03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49"),
        NIST256p, ec.SECP256R1(),
    ),
    "p384": (
        bytes.fromhex("030ff0895ae5ebf6187080a82d82b42e2765e3b2f8749c7e05eba366434b363d3d"
                      "c36f15314739074d2eb8613fceec2853"),
        bytes.fromhex("02c72cf2e390853a1c1c4ad816a62fd15824f56078918f43f922ca21518f9c543b"
                      "b252c5490214cf9aa3f0baab4b665c10"),
        NIST384p, ec.SECP384R1(),
    ),
    "p521": (
        bytes.fromhex("02003f06f38131b2ba2600791e82488e8d20ab889af753a41806c5db18d37d8560"
                      "8cfae06b82e4a72cd744c719193562a653ea1f119eef9356907edc9b56979962d7aa"),
        bytes.fromhex("0200c7924b9ec017f3094562894336a53c50167ba8c5963876880542bc669e494b2"
                      "532d76c5b53dfb349fdf69154b9e0048c58a42e8ed04cef052a3bc349d95575cd25"),
        NIST521p, ec.SECP521R1(),
    ),
}
_SUITE_CURVES = {1: "p256", 2: "p256", 8: "p256", 9: "p256",
                 3: "p384", 4: "p384", 5: "p521"}

def _suite_params(suite_type: int):
    name = _SUITE_CURVES.get(suite_type)
    if name is None:
        raise AuthError(f"Unsupported TPAP cipher suite: {suite_type}")
    return _SUITE_PARAMS[name]

def _sec1_xy(sec1: bytes, curve: ec.EllipticCurve):
    p = ec.EllipticCurvePublicKey.from_encoded_point(curve, sec1)
    n = p.public_numbers(); return n.x, n.y

def _xy_unc(x: int, y: int, curve: ec.EllipticCurve) -> bytes:
    return ec.EllipticCurvePublicNumbers(x, y, curve).public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)

def _l8(b: bytes) -> bytes: return len(b).to_bytes(8, "little") + b

def _encode_w(w: int) -> bytes:
    ml = 1 if w == 0 else (w.bit_length() + 7) // 8
    u = w.to_bytes(ml, "big", signed=False)
    return (b"\x00" + u) if (ml % 2 != 0 and u[0] & 0x80) else u

# ---------------------------------------------------------------------------
# Session cipher (AES-CCM / ChaCha20-Poly1305)
# ---------------------------------------------------------------------------
_TAG_LEN   = 16
_NONCE_LEN = 12
_CIPHER_LABELS = {
    "aes_128_ccm":       {"ks": b"tp-kdf-salt-aes128-key",   "ki": b"tp-kdf-info-aes128-key",
                           "ns": b"tp-kdf-salt-aes128-iv",    "ni": b"tp-kdf-info-aes128-iv",   "kl": 16},
    "aes_256_ccm":       {"ks": b"tp-kdf-salt-aes256-key",   "ki": b"tp-kdf-info-aes256-key",
                           "ns": b"tp-kdf-salt-aes256-iv",    "ni": b"tp-kdf-info-aes256-iv",   "kl": 32},
    "chacha20_poly1305": {"ks": b"tp-kdf-salt-chacha20-key", "ki": b"tp-kdf-info-chacha20-key",
                           "ns": b"tp-kdf-salt-chacha20-iv",  "ni": b"tp-kdf-info-chacha20-iv", "kl": 32},
}

def _derive_cipher(shared: bytes, cid: str, hkdf_hash: str = "SHA256"):
    L = _CIPHER_LABELS[cid]
    key   = _hkdf(shared, salt=L["ks"], info=L["ki"], length=L["kl"], algo=hkdf_hash)
    nonce = _hkdf(shared, salt=L["ns"], info=L["ni"], length=_NONCE_LEN, algo=hkdf_hash)
    return key, nonce

def _nonce(base: bytes, seq: int) -> bytes:
    return base[:-4] + struct.pack(">I", seq)

def _encrypt(cid: str, key: bytes, bn: bytes, pt: bytes, seq: int) -> bytes:
    n = _nonce(bn, seq)
    return AESCCM(key, tag_length=16).encrypt(n, pt, None) if cid.startswith("aes_") \
        else ChaCha20Poly1305(key).encrypt(n, pt, None)

def _decrypt(cid: str, key: bytes, bn: bytes, ct: bytes, seq: int) -> bytes:
    n = _nonce(bn, seq)
    return AESCCM(key, tag_length=16).decrypt(n, ct, None) if cid.startswith("aes_") \
        else ChaCha20Poly1305(key).decrypt(n, ct, None)

# ---------------------------------------------------------------------------
# Credential helpers
# ---------------------------------------------------------------------------
def _derive_ab(cred: bytes, salt: bytes, iters: int, hl: int = 32):
    iD = hl + 8; out = _pbkdf2(cred, salt, iters, 2 * iD)
    return int.from_bytes(out[:iD], "big"), int.from_bytes(out[iD:], "big")

def _build_cred(extra: dict, user: str, pw: str, mac12: str) -> str:
    if not extra:
        return (user + "/" + pw) if user else pw
    t = (extra.get("type") or "").lower()
    p = extra.get("params") or {}
    if t == "password_shadow":
        pid = int(p.get("passwd_id", 0))
        if pid == 2:
            return _sha1hex(pw)
        if pid == 3 and user and len(mac12) == 12:
            mac = ":".join(mac12[i:i+2] for i in range(0, 12, 2)).upper()
            return _sha1hex(_md5hex(user) + "_" + mac)
        return pw
    if t == "password_sha_with_salt":
        name = "admin" if int(p.get("sha_name", -1)) == 0 else "user"
        try:
            salt = base64.b64decode(p.get("sha_salt", "")).decode()
            return hashlib.sha256((name + salt + pw).encode()).hexdigest()
        except Exception:
            return pw
    return (user + "/" + pw) if user else pw

def _sha256hex_upper(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest().upper()

def _mac_default_passcode(mac: str) -> str:
    """Derive the factory default passcode a device advertising pake type 0 expects."""
    mac_hex = mac.replace(":", "").replace("-", "")
    try:
        mac_bytes = bytes.fromhex(mac_hex)
    except ValueError as exc:
        raise AuthError("Invalid device MAC for default passcode derivation") from exc
    if len(mac_bytes) < 6:
        raise AuthError("Device MAC too short for default passcode derivation")
    ikm = b"GqY5o136oa4i6VprTlMW2DpVXxmfW8" + mac_bytes[3:6] + mac_bytes[0:3]
    return _hkdf(ikm, salt=b"tp-kdf-salt-default-passcode",
                 info=b"tp-kdf-info-default-passcode", length=32).hex().upper()

# ---------------------------------------------------------------------------
# TapoVacuumClient
# ---------------------------------------------------------------------------
_PAKE_CTX = b"PAKE V1"

# Device error codes that mean "the session is gone, re-handshake and retry".
# Values mirror python-kasa SmartErrorCode: SESSION_TIMEOUT_ERROR, SESSION_EXPIRED,
# INVALID_NONCE, TRANSPORT_NOT_AVAILABLE_ERROR and STAT_ACCESS_ERROR.
_SESSION_ERRORS = {9999, -40401, -40413, 1002, -2203}
# Codes that mean the credentials themselves are wrong — retrying never helps:
# LOGIN_ERROR, LOGIN_FAILED_ERROR, AES_DECODE_FAIL_ERROR, HAND_SHAKE_FAILED_ERROR,
# TRANSPORT_UNKNOWN_CREDENTIALS_ERROR and HOMEKIT_LOGIN_FAIL.
_AUTH_ERRORS = {-1501, 1111, -1005, 1100, 1003, -40412}

# TP-Link device root CA, used when the device asks for verified TLS (tls mode 2).
_ROOT_CA_PEM = """-----BEGIN CERTIFICATE-----
MIICNzCCAdygAwIBAgIUNLD7w5j5WU/efCe8bqkfGSRGgLYwCgYIKoZIzj0EAwIw
ezEnMCUGA1UEAwweVFAtTElOSyBTWVNURU1TIERFVklDRSBST09UIENBMR0wGwYD
VQQKDBRUUC1MSU5LIFNZU1RFTVMgSU5DLjEPMA0GA1UEBwwGSXJ2aW5lMRMwEQYD
VQQIDApDYWxpZm9ybmlhMQswCQYDVQQGEwJVUzAgFw0yNDExMjIwMjU3NDhaGA8y
MDU0MTExNTAyNTc0OFowezEnMCUGA1UEAwweVFAtTElOSyBTWVNURU1TIERFVklD
RSBST09UIENBMR0wGwYDVQQKDBRUUC1MSU5LIFNZU1RFTVMgSU5DLjEPMA0GA1UE
BwwGSXJ2aW5lMRMwEQYDVQQIDApDYWxpZm9ybmlhMQswCQYDVQQGEwJVUzBZMBMG
ByqGSM49AgEGCCqGSM49AwEHA0IABLwo8H9H6BoJDvcoewi4wPrPryVXir4z4yXV
n29R5XCAcFfKk06pYPupG6pjaKOLKWXnaOdPZThDFxwGLo3urV2jPDA6MAsGA1Ud
DwQEAwIBhjAMBgNVHRMEBTADAQH/MB0GA1UdDgQWBBRivfUtiHYsZBOKo80uZEwk
XhBkdDAKBggqhkjOPQQDAgNJADBGAiEA+7j5jemtXcGYN0unH+9rjVhVAL7WrsOi
5rbc0IIvD6MCIQCZuGGssu4Ygt2V8Vr0QF2fO9wxfNB3aRRMYQ+6lMrLGA==
-----END CERTIFICATE-----"""

_TLS_CIPHERS = ":".join([
    "ECDHE-ECDSA-AES256-GCM-SHA384", "ECDHE-ECDSA-AES256-SHA384",
    "ECDHE-ECDSA-AES256-SHA",        "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES128-SHA256",     "ECDHE-ECDSA-AES128-SHA",
    "ECDHE-RSA-AES256-GCM-SHA384",   "ECDHE-RSA-AES256-SHA384",
    "ECDHE-RSA-AES256-SHA",          "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-SHA256",       "ECDHE-RSA-AES128-SHA",
])


class _PinnedCAAdapter(HTTPAdapter):
    """requests adapter that trusts only the TP-Link root CA, without hostname checks.

    A device certifies itself by model name (CN "RV30 Max Plus(EU)") with no
    usable subjectAltName, so it can never match the IP we dial. The chain up to
    the pinned root is the real check; the hostname match is turned off.
    """

    def init_poolmanager(self, *args, **kwargs):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.set_ciphers(_TLS_CIPHERS)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(cadata=_ROOT_CA_PEM)
        kwargs["ssl_context"] = ctx
        # Without this urllib3 runs its own hostname match and rejects the cert,
        # because our context has check_hostname off but assert_hostname unset.
        kwargs["assert_hostname"] = False
        return super().init_poolmanager(*args, **kwargs)

    def cert_verify(self, conn, url, verify, cert):
        """Leave verification to our pinned context.

        The default would set ca_certs to the certifi bundle, and urllib3 loads
        that into our context on top of the pinned root — which would let any
        public CA vouch for the device. Skipping it keeps the root pinned.
        """
        return


def _is_device_error(exc: BaseException) -> bool:
    """True when the robot itself answered with an error code (it understood the call
    and said no), as opposed to a transport or session problem."""
    return "Device error" in str(exc)


class AuthError(Exception):
    """Raised when SPAKE2+ auth fails (wrong credentials, bad attestation)."""


class _SessionLost(Exception):
    """Internal: the encrypted session is no longer usable — re-handshake."""


def _opt_int(value) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _raise_for_error(response: dict, action: str) -> None:
    """Classify a device error code so callers know whether retrying helps."""
    code = _opt_int(response.get("error_code")) or 0
    if code == 0:
        return
    msg = f"{action} failed: error_code={code}"
    if code in _AUTH_ERRORS:
        raise AuthError(msg)
    if code in _SESSION_ERRORS:
        raise _SessionLost(msg)
    raise RuntimeError(f"Device error {code} on {action}")


def _load_cert(value: str) -> x509.Certificate:
    """Load a certificate the device sent as PEM or bare base64 DER."""
    data = value.strip()
    if "-----BEGIN" in data:
        return x509.load_pem_x509_certificate(data.encode())
    return x509.load_der_x509_certificate(_b64d(data))


def _verify_cert_chain(ca: x509.Certificate, ica: x509.Certificate | None) -> None:
    """Verify the device attestation chain up to the pinned TP-Link root."""
    root = x509.load_pem_x509_certificate(_ROOT_CA_PEM.encode())
    now  = datetime.now(UTC)
    chain = [ca] + ([ica] if ica else []) + [root]
    for cert in chain:
        if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
            raise AuthError("DAC certificate is outside its validity window")
    # Each certificate must be signed by the next one up, ending at the root.
    for cert, issuer in zip(chain, chain[1:]):
        if cert.issuer != issuer.subject:
            raise AuthError("DAC certificate chain is not contiguous")
        pub  = issuer.public_key()
        algo = cert.signature_hash_algorithm
        if algo is None:
            raise AuthError("DAC certificate has no signature hash algorithm")
        if isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(algo))
        elif isinstance(pub, rsa.RSAPublicKey):
            pub.verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), algo)
        else:
            raise AuthError(f"Unsupported DAC issuer key: {type(pub).__name__}")


class TapoVacuumClient:
    """Synchronous TPAP client.  All methods are blocking — run in an executor."""

    def __init__(self, host: str, username: str, password: str, port: int = 4433,
                 cache_dir: str | Path | None = None) -> None:
        self.host     = host
        self.port     = port
        self.username = username
        self.password = password
        self._http    = requests.Session()
        self._cache   = self._cache_path(host, cache_dir)
        # HA calls us from several executor threads (poll + commands); the session
        # seq/nonce is shared state, so one request at a time.
        self._lock    = threading.RLock()
        # None = untried, then True/False once the firmware has answered multipleRequest.
        self._multi_supported: bool | None = None

        # Discovery metadata — filled in by _discover(), cached between runs.
        self._device_mac = ""
        self._tpap_pake: list[int] = []
        self._tls_mode: int | None = None
        self._tpap_port: int | None = None
        self._tpap_dac   = False
        self._user_hash_type: int | None = None

        self._session_id = ""
        self._seq        = 1
        self._cipher_id  = "aes_128_ccm"
        self._hkdf_hash  = "SHA256"
        self._key        = b""
        self._base_nonce = b""
        self._shared_key = b""
        self._dac_nonce  = ""
        self.base_url    = f"https://{host}:{port}"

    # ---- Session cache file ----------------------------------------------------
    @staticmethod
    def _cache_path(host: str, cache_dir: str | Path | None) -> Path:
        """Session cache location: the caller's directory (HA's .storage) when
        given, else a per-user temp dir; the directory is 0700 and the file 0600
        so no other local user can read or pre-plant a session."""
        base = Path(cache_dir) if cache_dir else Path(tempfile.gettempdir()) / f"tapo_rv30_{os.getuid()}"
        try:
            base.mkdir(mode=0o700, parents=True, exist_ok=True)
        except Exception:
            pass
        return base / f"session_{host}.json"

    # ---- Internal HTTP -------------------------------------------------------
    def _apply_tls_mode(self) -> None:
        """Re-target the base URL and TLS trust from the discovered tls/port hints.

        tls 0 = plain http, 1 = https with an untrusted (self-signed) cert,
        2 = https validated against the pinned TP-Link root CA.
        """
        scheme = "http" if self._tls_mode == 0 else "https"
        if self._tpap_port and self._tpap_port > 0:
            port = self._tpap_port
        elif scheme == "https":
            port = 4433
        else:
            port = self.port
        self.base_url = f"{scheme}://{self.host}:{port}"

        self._verify = self._tls_mode == 2
        self._http.mount("https://", _PinnedCAAdapter() if self._verify else HTTPAdapter())

    _verify = False   # TLS mode 1 (self-signed) until discovery says otherwise

    def _post(self, path: str, body=None, binary: bool = False):
        url = self.base_url + path
        kwargs = dict(timeout=15, verify=self._verify)
        if binary:
            kwargs.update(data=body, headers={"Content-Type": "application/octet-stream"})
        else:
            kwargs.update(json=body, headers={"Content-Type": "application/json"})
        # verify is passed per request: requests lets REQUESTS_CA_BUNDLE override
        # session.verify. The self-signed warning is silenced here only, not
        # process-wide, and only while we are knowingly unverified.
        with warnings.catch_warnings():
            if not self._verify:
                warnings.simplefilter("ignore", InsecureRequestWarning)
            r = self._http.post(url, **kwargs)
        r.raise_for_status()
        return r.content if binary else r.json()

    # ---- Session cache -------------------------------------------------------
    _CACHE_FIELDS = ("mac", "pake", "sid", "seq", "cid", "hkdf", "tls", "tport", "dac", "uht")

    def _load_session(self) -> bool:
        """JSON, never pickle: a tampered file can at worst fail the session."""
        try:
            d = json.loads(self._cache.read_text())
            if d.get("host") != self.host or d.get("user") != self.username:
                return False
            self._device_mac = d["mac"];  self._tpap_pake  = list(d["pake"])
            self._session_id = d["sid"];  self._seq        = int(d["seq"])
            self._cipher_id  = d["cid"];  self._hkdf_hash  = d["hkdf"]
            self._key        = _b64d(d["key"]); self._base_nonce = _b64d(d["nonce"])
            self._tls_mode       = _opt_int(d.get("tls"))
            self._tpap_port      = _opt_int(d.get("tport"))
            self._tpap_dac       = bool(d.get("dac", False))
            self._user_hash_type = _opt_int(d.get("uht"))
            if self._cipher_id not in _CIPHER_LABELS or not self._session_id:
                return False
            self._apply_tls_mode()
            return True
        except Exception:
            return False

    def _save_session(self) -> None:
        try:
            payload = json.dumps({
                "host": self.host, "user": self.username,
                "mac": self._device_mac, "pake": self._tpap_pake,
                "sid": self._session_id, "seq": self._seq,
                "cid": self._cipher_id, "hkdf": self._hkdf_hash,
                "key": _b64e(self._key), "nonce": _b64e(self._base_nonce),
                "tls": self._tls_mode, "tport": self._tpap_port,
                "dac": self._tpap_dac, "uht": self._user_hash_type,
            })
            fd = os.open(self._cache, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as fh:
                fh.write(payload)
        except Exception as exc:
            _LOGGER.debug("Session cache write failed: %s", exc)

    def _clear_session(self) -> None:
        try: self._cache.unlink()
        except Exception: pass
        self._session_id = ""

    # ---- SPAKE2+ auth --------------------------------------------------------
    def _discover(self) -> None:
        d = self._post("/", {"method": "login", "params": {"sub_method": "discover"}})
        _raise_for_error(d, "discover")
        r = d["result"]
        tpap = r.get("tpap") or {}
        self._device_mac     = r.get("mac") or ""
        self._tpap_pake      = list(tpap.get("pake") or [])
        self._tls_mode       = _opt_int(tpap.get("tls"))
        self._tpap_port      = _opt_int(tpap.get("port"))
        self._tpap_dac       = bool(tpap.get("dac"))
        self._user_hash_type = _opt_int(tpap.get("user_hash_type"))
        # Discovery runs before the real TLS mode is known, so re-target now.
        self._apply_tls_mode()

    def _passcode_type(self) -> str:
        """Pick the passcode scheme, preferring what the robot advertises."""
        pake = set(self._tpap_pake)
        for values, ptype in (((0,), "default_userpw"),
                              ((2,), "userpw"),
                              ((3,), "shared_token")):
            if pake & set(values):
                return ptype
        return "default_userpw"

    def _candidate_secrets(self, ptype: str) -> list[str]:
        """Secrets to try in order; a rejected one falls through to the next."""
        if ptype == "default_userpw":
            out = []
            if self._device_mac:
                out.append(_mac_default_passcode(self._device_mac))
            # Some firmware advertises type 0 but still takes the account
            # password, so keep it as a fallback rather than failing outright.
            if self.password:
                out.append(self.password)
            return out
        if ptype == "shared_token":
            return [_md5hex(self.password)]
        return [self.password]

    def _resolve_cred(self, ptype: str, secret: str, register: dict) -> str:
        if ptype == "default_userpw":
            return secret
        mac12 = self._device_mac.replace(":", "").replace("-", "")
        return _build_cred(register.get("extra_crypt") or {}, self.username, secret, mac12)

    def authenticate(self) -> None:
        """Run the full SPAKE2+ handshake. Raises AuthError on failure."""
        self._discover()
        ptype = self._passcode_type()
        candidates = self._candidate_secrets(ptype)
        if not candidates:
            raise AuthError(f"No credential candidates for passcode type {ptype!r}")

        last: Exception | None = None
        for n, secret in enumerate(candidates, start=1):
            try:
                self._handshake(ptype, secret)
                return
            except AuthError as exc:
                last = exc
                if n < len(candidates):
                    _LOGGER.debug("TPAP credential candidate %d/%d rejected: %s",
                                  n, len(candidates), exc)
        raise last

    def _handshake(self, ptype: str, secret: str) -> None:
        ur = _b64e(os.urandom(32))
        username = _sha256hex_upper("admin") if self._user_hash_type == 1 else _md5hex("admin")

        reg = self._post("/", {"method": "login", "params": {
            "sub_method": "pake_register", "username": username,
            "user_random": ur, "cipher_suites": [1],
            "encryption": ["aes_128_ccm", "chacha20_poly1305", "aes_256_ccm"],
            "passcode_type": ptype, "stok": None,
        }})
        _raise_for_error(reg, "pake_register")
        r = reg["result"]

        st    = int(r.get("cipher_suites") or 2)
        iters = int(r.get("iterations") or 10000)
        if iters <= 0:
            raise AuthError("pake_register returned invalid iterations")
        self._cipher_id = (r.get("encryption") or "aes_128_ccm").lower().replace("-", "_")
        if self._cipher_id not in _CIPHER_LABELS:
            raise AuthError(f"Unsupported session cipher: {self._cipher_id}")
        self._hkdf_hash = "SHA512" if st in (2, 4, 5, 7, 9) else "SHA256"
        cmac = st in (8, 9)
        dlen = 64 if self._hkdf_hash == "SHA512" else 32

        cred = self._resolve_cred(ptype, secret, r)

        M_enc, N_enc, nist, curve = _suite_params(st)
        G = nist.generator; order = G.order(); ec_curve = nist.curve
        Mx, My = _sec1_xy(M_enc, curve); Nx, Ny = _sec1_xy(N_enc, curve)
        M = ellipticcurve.Point(ec_curve, Mx, My, order)
        N = ellipticcurve.Point(ec_curve, Nx, Ny, order)

        a, b = _derive_ab(cred.encode(), _b64d(r["dev_salt"]), iters)
        w, h = a % order, b % order
        x = secrets.randbelow(order - 1) + 1

        L      = x * G + w * M
        L_enc  = _xy_unc(L.x(), L.y(), curve)
        Rx, Ry = _sec1_xy(_b64d(r["dev_share"]), curve)
        R      = ellipticcurve.Point(ec_curve, Rx, Ry, order)
        R_enc  = _xy_unc(R.x(), R.y(), curve)
        Rp     = R + (-(w * N))
        Z_enc  = _xy_unc((x * Rp).x(), (x * Rp).y(), curve)
        V_enc  = _xy_unc(((h % order) * Rp).x(), ((h % order) * Rp).y(), curve)

        hfn   = _sha512 if self._hkdf_hash == "SHA512" else _sha256
        ctx   = hfn(_PAKE_CTX + _b64d(ur) + _b64d(r["dev_random"]))
        trans = (_l8(ctx) + _l8(b"") + _l8(b"")
                 + _l8(_xy_unc(Mx, My, curve)) + _l8(_xy_unc(Nx, Ny, curve))
                 + _l8(L_enc) + _l8(R_enc) + _l8(Z_enc) + _l8(V_enc)
                 + _l8(_encode_w(w)))
        T = hfn(trans)

        ml   = 16 if cmac else 32
        conf = _hkdf_expand("ConfirmationKeys", T, ml * 2, self._hkdf_hash)
        KcA, KcB = conf[:ml], conf[ml:ml * 2]
        shared   = _hkdf_expand("SharedKey", T, dlen, self._hkdf_hash)
        mac_fn   = _cmac_aes if cmac else (lambda k, d: _hmac_fn(self._hkdf_hash, k, d))
        u_conf   = mac_fn(KcA, R_enc)
        e_conf   = mac_fn(KcB, L_enc)

        params = {
            "sub_method":   "pake_share",
            "user_share":   _b64e(L_enc),
            "user_confirm": _b64e(u_conf),
        }
        # tls 0 leaves the transport unauthenticated, so a device offering DAC
        # proves its identity by signing our nonce with its attestation cert.
        use_dac = self._tls_mode == 0 and self._tpap_dac
        if use_dac:
            self._dac_nonce = _b64e(os.urandom(32))
            params["dac_nonce"] = self._dac_nonce

        share = self._post("/", {"method": "login", "params": params})
        _raise_for_error(share, "pake_share")
        s = share["result"]

        if (s.get("dev_confirm") or "").lower() != _b64e(e_conf).lower():
            raise AuthError("SPAKE2+ confirmation mismatch — wrong password?")

        self._shared_key = shared
        if use_dac:
            self._verify_dac_proof(s)

        self._session_id = s.get("sessionId") or s.get("stok") or ""
        if not self._session_id:
            raise AuthError("pake_share response missing session id")
        # The reference implementation treats a missing start_seq as fatal; keep
        # the historical default of 1 so older firmware still works, but say so.
        if s.get("start_seq") is None:
            _LOGGER.warning("TPAP: %s omitted start_seq, defaulting to 1", self.host)
            self._seq = 1
        else:
            self._seq = int(s["start_seq"])
        self._key, self._base_nonce = _derive_cipher(shared, self._cipher_id, self._hkdf_hash)
        self._save_session()
        _LOGGER.debug("TPAP session established with %s (suite %s, %s)",
                      self.host, st, self._cipher_id)

    def _verify_dac_proof(self, share_result: dict) -> None:
        """Check the device attestation chain and its signature over our nonce."""
        dac_ca    = share_result.get("dac_ca") or ""
        dac_ica   = share_result.get("dac_ica") or ""
        dac_proof = share_result.get("dac_proof")
        if not (dac_ca and isinstance(dac_proof, str)):
            return
        try:
            ca  = _load_cert(dac_ca)
            ica = _load_cert(dac_ica) if dac_ica else None
            _verify_cert_chain(ca, ica)
            pub = ca.public_key()
            if not isinstance(pub, ec.EllipticCurvePublicKey):
                raise AuthError(f"Unsupported DAC key type: {type(pub).__name__}")
            pub.verify(_b64d(dac_proof), self._shared_key + _b64d(self._dac_nonce),
                       ec.ECDSA(hashes.SHA256()))
        except AuthError:
            raise
        except Exception as exc:
            raise AuthError(f"DAC verification failed: {exc}") from exc

    def _ensure_auth(self) -> None:
        if not self._session_id:
            self._load_session() or self.authenticate()

    # ---- Send ----------------------------------------------------------------
    def send(self, method: str, params: dict | None = None) -> dict:
        """Send an encrypted request, re-handshaking once if the session lapsed."""
        with self._lock:
            return self._send(method, params)

    def _send(self, method: str, params: dict | None) -> dict:
        self._ensure_auth()
        for attempt in range(2):
            try:
                return self._send_once(method, params)
            except _SessionLost as exc:
                if attempt == 0:
                    _LOGGER.debug("TPAP session lost (%s), re-authenticating", exc)
                    self._clear_session()
                    try:
                        self.authenticate()
                    except _SessionLost as reauth:
                        raise RuntimeError(str(reauth)) from reauth
                else:
                    raise RuntimeError(str(exc)) from exc
        raise RuntimeError("unreachable")

    def _send_once(self, method: str, params: dict | None) -> dict:
        payload = (struct.pack(">I", self._seq)
                   + _encrypt(self._cipher_id, self._key, self._base_nonce,
                              json.dumps({"method": method,
                                          "params": params or {}}).encode(),
                              self._seq))
        try:
            raw = self._post(f"/stok={self._session_id}/ds", payload, binary=True)
        except requests.RequestException as exc:
            # A reset or refused connection usually means the device dropped us.
            raise _SessionLost(f"transport error: {exc}") from exc
        if len(raw) < 4 + _TAG_LEN:
            raise _SessionLost(f"response too short ({len(raw)} bytes)")
        rseq = struct.unpack(">I", raw[:4])[0]
        try:
            plain = _decrypt(self._cipher_id, self._key, self._base_nonce, raw[4:], rseq)
        except Exception as exc:
            raise _SessionLost(f"decrypt failed: {exc}") from exc
        self._seq += 1
        self._save_session()
        resp = json.loads(plain.decode())
        _raise_for_error(resp, method)
        return resp

    # ---- Batched reads --------------------------------------------------------
    _MULTI_BATCH = 5   # what python-kasa uses against real devices

    def send_multi(self, requests: list[tuple[str, dict | None]]) -> dict[str, dict]:
        """Run several getters in as few round trips as the firmware allows.

        Returns {method: result} for the ones that succeeded; a getter the
        model doesn't support is simply absent. Falls back to one call per
        method if the firmware rejects multipleRequest.
        """
        out: dict[str, dict] = {}
        if self._multi_supported is not False:
            try:
                for i in range(0, len(requests), self._MULTI_BATCH):
                    chunk = requests[i:i + self._MULTI_BATCH]
                    resp = self.send("multipleRequest", {"requests": [
                        {"method": m, "params": p or {}} for m, p in chunk]})
                    for item in (resp.get("result") or {}).get("responses", []):
                        if item.get("error_code", 0) == 0:
                            out[item["method"]] = item.get("result") or {}
                        else:
                            _LOGGER.debug("%s failed in batch: %s", item.get("method"), item.get("error_code"))
                self._multi_supported = True
                return out
            except RuntimeError as exc:
                if self._multi_supported is None and "Device error" in str(exc):
                    _LOGGER.debug("multipleRequest not supported (%s); using single requests", exc)
                    self._multi_supported = False
                else:
                    raise
        for m, p in requests:
            try:
                out[m] = self.send(m, p)["result"] or {}
            except Exception as exc:
                _LOGGER.debug("%s failed: %s", m, exc)
        return out

    _STATUS_REQUESTS = [("getVacStatus", None), ("getBatteryInfo", None), ("getCleanInfo", None),
                        ("getCleanAttr", {"type": "global"}), ("getMopState", None),
                        ("getConsumablesInfo", None), ("getAreaUnit", None)]

    def get_status(self) -> dict:
        r = self.send_multi(self._STATUS_REQUESTS)
        if "getVacStatus" not in r:
            raise RuntimeError("getVacStatus failed")
        vac, batt, info = r["getVacStatus"], r.get("getBatteryInfo", {}), r.get("getCleanInfo", {})
        attr, mop = r.get("getCleanAttr", {}), r.get("getMopState", {})
        return {
            "status_code":  vac["status"],
            "error_codes":  vac.get("err_status") or [0],
            "battery":      batt.get("battery_percentage", 0),
            "suction":      attr.get("suction", 4),
            "cistern":      attr.get("cistern", 0),
            "clean_number": attr.get("clean_number", 1),
            "mop_attached": mop.get("mop_state", False),
            "clean_area":   info.get("clean_area", 0),
            "clean_time":   info.get("clean_time", 0),
            "clean_percent":info.get("clean_percent", 0),
            "consumables":  r.get("getConsumablesInfo", {}),
            "area_unit":    r.get("getAreaUnit", {}).get("area_unit", 0),
        }

    def get_device_info(self) -> dict:
        """Model, firmware and (decoded) nickname."""
        import base64
        raw = self.send("get_device_info")["result"]
        try:
            name = base64.b64decode(raw.get("nickname", "")).decode(errors="replace").strip()
        except Exception:
            name = raw.get("nickname", "")
        return {
            "name":   name or "Tapo RV30",
            "model":  raw.get("model") or "RV30",
            "fw_ver": raw.get("fw_ver"),
            "hw_ver": raw.get("hw_ver"),
            "rssi":   raw.get("rssi"),
            "signal_level": raw.get("signal_level"),
            "mac":    raw.get("mac"),
        }

    def get_latest_firmware(self) -> dict:
        """{fw_ver, need_to_upgrade, release_note, ...} from the robot's own update check."""
        return self.send("get_latest_fw")["result"]

    def get_nickname(self) -> str:
        return self.get_device_info()["name"]

    def get_clean_records(self) -> dict:
        return self.send("getCleanRecords")["result"]

    def get_path(self, path_id: int, start_pos: int = 0) -> dict:
        """Points of the current/last run: {path_id, point_counts, total_points, pos_array, pos_len}."""
        return self.send("getPathData", {"path_id": int(path_id), "start_pos": int(start_pos)})["result"]

    # ---- Capabilities ------------------------------------------------------------
    def get_components(self) -> dict[str, int]:
        """{component_id: version} from getComponentList; what this model can do."""
        r = self.send("getComponentList")["result"]
        return {c["id"]: int(c.get("ver_code", 0)) for c in r.get("component_list", []) if "id" in c}

    # Optional on/off settings seen across RV20/RV30/RV50 firmware; which ones a
    # model has is found by probing once (probe_bool_settings).
    BOOL_SETTINGS = {
        "child_lock":          ("getChildLockInfo", "setChildLockInfo", "child_lock_status"),
        "carpet_boost":        ("getCarpetAutoBoost", "setCarpetAutoBoost", "auto_boost"),
        "ai_avoid":            ("getAiAvoidSwitch", "setAiAvoidSwitch", "switch"),
        "automatic_remopping": ("getAutomaticRemoppingSwitch", "setAutomaticRemoppingSwitch", "switch"),
        "clean_along_floor":   ("getCleanAlongFloorSwitch", "setCleanAlongFloorSwitch", "switch"),
        "extended_mopping":    ("getExtendedMoppingSwitch", "setExtendedMoppingSwitch", "switch"),
        "pet_area_deep_clean": ("getPetAreaDeepSwitch", "setPetAreaDeepSwitch", "switch"),
        "sweep_walk":          ("getSweepWalk", "setSweepWalk", "sweepWalk"),
    }

    def probe_bool_settings(self) -> tuple[dict[str, bool], bool]:
        """Which BOOL_SETTINGS this model answers, with their current values, and
        whether every probe got a definite answer. A device error (-1002 and friends)
        is a definite "no"; a transport hiccup is not, and the caller probes again."""
        out, complete = {}, True
        for key, (getter, _, field) in self.BOOL_SETTINGS.items():
            try:
                out[key] = bool(self.send(getter)["result"].get(field))
            except Exception as exc:
                if not _is_device_error(exc):
                    complete = False
                _LOGGER.debug("%s not supported: %s", getter, exc)
        return out, complete

    def get_bool_settings(self, keys) -> dict[str, bool]:
        out = {}
        for key in keys:
            getter, _, field = self.BOOL_SETTINGS[key]
            try:
                out[key] = bool(self.send(getter)["result"].get(field))
            except Exception as exc:
                _LOGGER.debug("%s failed: %s", getter, exc)
        return out

    def set_bool_setting(self, key: str, value: bool) -> None:
        _, setter, field = self.BOOL_SETTINGS[key]
        self.send(setter, {field: bool(value)})

    # ---- Maps ----------------------------------------------------------------------
    def set_current_map(self, map_id: int) -> None:
        """Switch the active map (the robot relocalises on it)."""
        self.send("setMapInfo", {"current_map_id": int(map_id)})

    # ---- Presets (Tapo app "customisation rules") ------------------------------------
    def get_presets(self) -> list[dict]:
        """Saved presets: [{rule_id, rule_name (b64), map_id, mode, invalid}, ...]."""
        r = self.send("getCustomizationRulesInfo")["result"]
        return r.get("rule_list") or []

    def get_preset_detail(self, map_id: int, rule_id: int) -> dict:
        """Rooms and per-room settings of one preset."""
        return self.send("getCustomizationRuleData", {"map_id": int(map_id), "rule_id": int(rule_id)})["result"]

    def run_preset(self, rule_id: int, map_id: int, clean_order: bool = True) -> None:
        """Start a preset exactly as the app does (clean_mode 5); switches map first if needed."""
        current, _ = self.get_map_info()
        if current != map_id:
            self.set_current_map(map_id)
        self.clean_custom_rule(rule_id, map_id, clean_order)

    def get_consumables(self) -> dict:
        return self.send("getConsumablesInfo")["result"]

    def get_map_info(self) -> tuple[int, list[dict]]:
        r = self.send("getMapInfo")["result"]
        return r["current_map_id"], r["map_list"]

    def get_map_data(self, map_id: int) -> dict:
        return self.send("getMapData", {"map_id": map_id})["result"]

    def _status(self) -> int:
        return self.send("getVacStatus")["result"].get("status")

    def start(self) -> None:
        # Paused mid-job: the robot rejects a new setSwitchClean (-3002), so resume the job instead.
        if self._status() == 7:
            return self.resume()
        self.send("setSwitchClean", {
            "clean_mode": 0, "clean_on": True,
            "clean_order": True, "force_clean": False,
        })

    def set_global_levels(self, **levels) -> None:
        """suction / cistern / clean_number for the next runs (what the app's clean page sets).
        Read and write under the session lock so two entity writes running in parallel
        executor threads cannot put a stale copy of each other's field back."""
        with self._lock:
            cur = self.send("getCleanAttr", {"type": "global"})["result"]
            cur.update(levels); cur["type"] = "global"
            self.send("setCleanAttr", cur)

    def clean_rooms(self, room_ids: list[int], map_id: int, clean_order: bool = True,
                    levels: dict | None = None) -> None:
        if levels:
            self.set_global_levels(**levels)
        self.send("setSwitchClean", {
            "clean_mode":  3,
            "clean_on":    True,
            "clean_order": clean_order,
            "force_clean": False,
            "map_id":      map_id,
            "room_list":   list(room_ids),
            "start_type":  1,
        })

    def clean_custom_rule(self, custom_rule_id, map_id: int, clean_order: bool = True) -> None:
        """Run a Tapo-app cleaning preset. Schedules built from a preset carry
        clean_mode 5 + custom_rule_id instead of a room_list; this sends the same
        shape setSwitchClean. Inferred from schedule data, not confirmed by the app."""
        self.send("setSwitchClean", {
            "clean_mode": 5, "clean_on": True, "clean_order": clean_order,
            "force_clean": False, "map_id": map_id,
            "custom_rule_id": custom_rule_id, "start_type": 1,
        })

    def get_schedules(self) -> list[dict]:
        """Saved schedule rules as configured in the Tapo app (get_schedule_rules)."""
        r = self.send("get_schedule_rules", {"start_index": 0})
        return (r.get("result") or {}).get("rule_list", [])

    # Schedule management: the app posts the ScheduleRule bean as-is. Verified on an
    # RV30 Max Plus: add returns {"id": "S1"}, edit needs the whole rule (a partial
    # body is -1008), remove takes {"remove_all", "rule_list"}. s_min is minutes after
    # midnight in the robot's own region (the app only shifts it when the phone's
    # zone differs from the robot's).
    def add_schedule(self, rule: dict) -> str | None:
        r = self.send("addScheduleRule", rule)
        return (r.get("result") or {}).get("id")

    def edit_schedule(self, rule: dict) -> None:
        self.send("editScheduleRule", rule)

    def remove_schedules(self, ids: list[str] | None = None, remove_all: bool = False) -> None:
        self.send("removeScheduleRules", {"remove_all": bool(remove_all), "rule_list": list(ids or [])})

    # Matter (component "matter"; calls and fields from the app's RobotMatterRepository).
    # getMatterSetupInfo: the robot's fixed setup code and QR payload, the same ones
    # printed on it. getCommissionedStatus: status 0 unbound / 1 window open / 2 bound,
    # bind_fabrics, expired_time (seconds left in the window). startCommission opens
    # a pairing window and answers {"expired_time": seconds}.
    def start_matter_commissioning(self) -> dict:
        return self.send("startCommission")["result"] or {}

    def remove_matter_fabric(self, fabric_index: int) -> None:
        self.send("removeBindFabric", {"fabric_index": int(fabric_index)})

    def get_clean_record_detail(self, record_index: int) -> dict:
        """A finished run with its own map grid, overlays and driven path."""
        return self.send("getCleanRecordExtraInfo", {"record_index": int(record_index)})["result"]

    def run_schedule(self, schedule_id) -> None:
        """Start the clean a saved schedule would start, now.

        There is no known device call to fire a schedule by id, so this replays
        its settings: suction / water / passes via setCleanAttr, then the rooms,
        preset or whole house via setSwitchClean.
        """
        rule = next((r for r in self.get_schedules() if r.get("id") == schedule_id), None)
        if rule is None:
            raise ValueError(f"No schedule with id {schedule_id!r}")
        attr = rule.get("clean_attr") or {}
        with self._lock:
            cur = self.send("getCleanAttr", {"type": "global"})["result"]
            for key in ("suction", "cistern", "clean_number"):
                if attr.get(key) is not None:
                    cur[key] = attr[key]
            cur["type"] = "global"
            self.send("setCleanAttr", cur)
        map_id = attr.get("map_id")
        if map_id is None:
            map_id, _ = self.get_map_info()
        order = attr.get("clean_order", True)
        if attr.get("custom_rule_id") is not None:
            self.clean_custom_rule(attr["custom_rule_id"], map_id, order)
        elif attr.get("room_list"):
            self.clean_rooms(attr["room_list"], map_id, order)
        else:
            self.start()

    def pause(self) -> None:
        if self._status() == 4:
            self.send("setSwitchCharge", {"switch_charge": False})
        else:
            self.send("setRobotPause", {"pause": True})

    def resume(self) -> None:
        self.send("setRobotPause", {"pause": False})

    def locate(self) -> None:
        # The app's "find my robot" (PlaySelectAudioParams seek_me preset).
        self.send("playSelectAudio", {"audio_type": "seek_me"})

    def dock(self) -> None:
        self.send("setSwitchCharge", {"switch_charge": True})

    def stop(self) -> None:
        """End the job (stop used to be pause, leaving the robot 'paused' forever)."""
        status = self._status()
        if status in DOCKED_CODES:  # at the dock (incl. 9 emptying dust): nothing to stop
            return
        if status == 4:  # returning: cancel the trip home
            self.send("setSwitchCharge", {"switch_charge": False})
            return
        if status in (11, 12):  # going to a point: setSwitchClean does not end that
            self.stop_goto()
            return
        try:
            self.send("setSwitchClean", {"clean_on": False})
        except RuntimeError:
            self.send("setRobotPause", {"pause": True})  # at least halt it

    # ---- Go to point (component "goto_point"; method and params from the Tapo app,
    # verified on an RV30 Max Plus: status becomes 11 "Going To Point") ----
    def goto_point(self, x_mm: int, y_mm: int) -> None:
        self.send("gotoPoint", {"switch": True, "point": [int(x_mm), int(y_mm)]})

    def stop_goto(self) -> None:
        self.send("gotoPoint", {"switch": False, "point": [0, 0]})

    # ---- Remote control (component "direction_control"; call, codes and timing from the
    # app's RobotRemoteControlViewModel / RobotRemoteControlActivity, verified on an RV30
    # Max Plus). Entering sends
    # direction 0 with control=true and answers away_sta_ms, how long the robot takes to
    # leave the dock (the app counts it down, 4000 ms when absent). Leaving sends
    # direction 4 (stop) with control=false. While driving the app re-sends the held
    # direction about every 300 ms after each answer and sends 4 when the finger lifts.
    def remote_control(self, enable: bool) -> int | None:
        r = self.send("directionControl", {"direction": 0 if enable else 4, "control": bool(enable)})
        return (r.get("result") or {}).get("away_sta_ms")

    def remote_drive(self, direction: int) -> None:
        self.send("directionControl", {"direction": int(direction)})

    def set_fan_speed(self, value: int) -> None:
        self.send("setCleanAttr", {"suction": value, "type": "global"})

    def set_passes(self, value: int) -> None:
        self.send("setCleanAttr", {"clean_number": value, "type": "global"})

    def set_water(self, value: int) -> None:
        self.set_global_levels(cistern=value)

    # ---- Settings & extras (names from the decompiled Tapo app, 2026-10-13) ----
    _SETTINGS = (("dust", "getDustCollectionInfo", None), ("dnd", "getDoNotDisturb", None),
                 ("volume", "getVolume", None), ("child_lock", "getChildLockInfo", None),
                 ("carpet_boost", "getCarpetAutoBoost", None), ("records", "getCleanRecords", None),
                 ("schedules", "get_schedule_rules", {"start_index": 0}),
                 ("firmware", "get_latest_fw", None), ("device", "get_device_info", None),
                 ("auto_update", "getAutoUpdateInfo", None),
                 ("matter_status", "getCommissionedStatus", None), ("matter_setup", "getMatterSetupInfo", None))

    def get_settings(self) -> dict:
        """Slow-changing settings; a getter the model doesn't support is just left out."""
        out = {}
        for key, method, params in self._SETTINGS:
            try:
                out[key] = self.send(method, params)["result"]
            except Exception as exc:
                _LOGGER.debug("%s failed: %s", method, exc)
        return out

    def _merge_set(self, getter: str, setter: str, **changes) -> None:
        with self._lock:   # read-modify-write as one unit (see set_global_levels)
            cur = self.send(getter)["result"]
            cur.update(changes)
            self.send(setter, cur)

    def empty_bin(self) -> None:
        self.send("setSwitchDustCollection", {"switch_dust_collection": True})

    # Omni-dock actions (getter used to detect support, setter to trigger). From
    # cavefire/tapo-vacuum-ha and jan-tdy/TapoVac-ADV, confirmed on an RV50 Pro Omni there.
    DOCK_ACTIONS = {
        "wash_mop":    ("getBackWashMode", "setWashMopSwitch", "switch_wash_mop"),
        "dry_mop":     ("getDryMopMode", "setDryMopSwitch", "switch_dry_mop"),
        "remove_hair": ("getCutHairMode", "setCutHairSwitch", "switch_cut_hair"),
    }

    def probe_dock_actions(self) -> tuple[list[str], bool]:
        """Dock actions the robot answers the getter for, and whether every probe was
        conclusive (see probe_bool_settings)."""
        out, complete = [], True
        for key, (getter, _, _) in self.DOCK_ACTIONS.items():
            try:
                self.send(getter)
                out.append(key)
            except Exception as exc:
                if not _is_device_error(exc):
                    complete = False
                _LOGGER.debug("%s not supported: %s", getter, exc)
        return out, complete

    def dock_action(self, key: str) -> None:
        _, setter, field = self.DOCK_ACTIONS[key]
        self.send(setter, {field: True})

    def set_auto_empty(self, on: bool) -> None:
        self._merge_set("getDustCollectionInfo", "setDustCollectionInfo", auto_dust_collection=on)

    # dust_collection_mode values from the app's EmptyingSettings: 0 smart, 1 light,
    # 2 balanced, 3 max. Verified on an RV30 Max Plus (readback follows the write).
    def set_auto_update(self, on: bool) -> None:
        """Automatic firmware updates (enable / time / random_range bean, merged)."""
        self._merge_set("getAutoUpdateInfo", "setAutoUpdateInfo", enable=bool(on))

    def set_auto_empty_mode(self, mode: int) -> None:
        self._merge_set("getDustCollectionInfo", "setDustCollectionInfo", dust_collection_mode=mode)

    def set_dnd(self, **changes) -> None:  # do_not_disturb / s_min / e_min (minutes after midnight)
        self._merge_set("getDoNotDisturb", "setDoNotDisturb", **changes)

    def set_volume(self, value: int) -> None:
        self.send("setVolume", {"volume": value})

    def set_child_lock(self, on: bool) -> None:
        self.send("setChildLockInfo", {"child_lock_status": on})

    def set_carpet_boost(self, on: bool) -> None:
        self.send("setCarpetAutoBoost", {"auto_boost": on})

    def reset_consumable(self, part: str) -> None:  # e.g. "roll_brush" (field name minus _time)
        self.send("resetConsumablesTime", {"reset_list": [part]})

    def set_room_settings(self, map_id: int, changes: dict[int, dict]) -> None:
        """The app sends every room with type 'custom'; unchanged rooms keep their values.
        RV30 Max Plus firmware 1.3.3 answers -1001 to every shape of this (and -1008 to
        getCleanAttr type custom): on that firmware per-room settings only exist inside
        presets made in the Tapo app. services.py turns the -1001 into a clear message."""
        rooms = [a for a in self.get_map_data(map_id).get("area_list", []) if a.get("type") == "room"]
        self.send("setCleanAttr", {"type": "custom", "area_list": [
            {"id": r["id"], "type": "room", "suction": r.get("suction"),
             "cistern": r.get("cistern"), "clean_number": r.get("clean_number"),
             **changes.get(r["id"], {})}
            for r in rooms]})

    def clean_zones(self, map_id: int, zones: list[list[int]],
                    suction: int, cistern: int, passes: int) -> None:
        """Zones are [x1, y1, x2, y2] rectangles in the map's real coordinates (mm)."""
        self.send("setSwitchClean", {
            "clean_on": True, "clean_mode": 4, "map_id": map_id,
            "clean_order": False, "force_clean": False, "start_type": 1,
            "area_list": [{"id": i + 1, "type": "area",
                           "vertexs": [[x1, y1], [x2, y1], [x2, y2], [x1, y2]],
                           "suction": suction, "cistern": cistern, "clean_number": passes}
                          for i, (x1, y1, x2, y2) in enumerate(zones)],
        })

    def clean_spot(self) -> None:
        """The app's spot clean: a 1.5 m square (+-750) around a point - here, the robot."""
        map_id, _ = self.get_map_info()
        x, y = self.get_map_data(map_id)["real_vac_coor"][:2]
        g = self.send("getCleanAttr", {"type": "global"})["result"]
        self.clean_zones(map_id, [[x - 750, y - 750, x + 750, y + 750]],
                         g.get("suction", 3), g.get("cistern", 0), 1)

    # ---- map setup (save / re-apply the editable layers) --------------------------
    # The grid (walls the robot sensed) is SLAM-only and not writable. Everything on top
    # of it is: rooms, no-go zones, virtual walls and carpets. Their polygons are in world
    # mm, so they re-apply onto any grid. Written with setAreaInfo, one call per type (the
    # robot replaces all areas of that type). This is what the Tapo app uses for map edits.
    SETUP_AREA_TYPES = ("room", "forbid", "virtual_wall", "carpet_rectangle", "carpet_round")
    # Fields setAreaInfo accepts (RobotAreaData). Per-room clean settings (suction/cistern/
    # clean_number) are NOT here - those go via setCleanAttr, and on RV30 1.3.3 only exist
    # inside app presets (see set_room_settings).
    _AREA_WRITE_FIELDS = ("type", "id", "name", "color", "define_type", "floor_material",
                          "floor_texture", "carpet_strategy", "label", "vertexs")

    def get_area_setup(self, map_id: int) -> dict:
        """Snapshot a map's editable layers (rooms, no-go zones, virtual walls, carpets) as
        world-coordinate polygons. Not the occupancy grid."""
        data = self.get_map_data(map_id)
        by_type: dict[str, list] = {}
        for a in data.get("area_list", []):
            t = a.get("type")
            if t in self.SETUP_AREA_TYPES:
                by_type.setdefault(t, []).append(a)
        return {"map_id": map_id, "map_hash": data.get("map_hash"),
                "counts": {t: len(v) for t, v in by_type.items()}, "areas": by_type}

    def set_area_setup(self, map_id: int, setup: dict) -> dict:
        """Write a saved setup back, one setAreaInfo call per captured type (the robot
        replaces all areas of that type). Types absent from the snapshot are left untouched.
        Returns {type: error_code}."""
        results: dict[str, int] = {}
        for t in self.SETUP_AREA_TYPES:
            items = (setup.get("areas") or {}).get(t)
            if not items:
                continue
            area_list = [{k: a[k] for k in self._AREA_WRITE_FIELDS if a.get(k) is not None}
                         for a in items]
            r = self.send("setAreaInfo", {"map_id": map_id, "type_list": [t], "area_list": area_list})
            results[t] = r.get("error_code", 0)
        return results

    # ---- live map editing (the editor tab) ---------------------------------------
    def set_areas(self, map_id: int, type_name: str, area_list: list) -> int:
        """Replace every area of one type (forbid / virtual_wall / carpet_rectangle /
        carpet_round / room) with area_list (world-mm polygons). Returns the error_code."""
        out = []
        for a in area_list:
            entry = {k: a[k] for k in self._AREA_WRITE_FIELDS if a.get(k) is not None}
            entry["type"] = type_name
            out.append(entry)
        r = self.send("setAreaInfo", {"map_id": map_id, "type_list": [type_name], "area_list": out})
        return r.get("error_code", 0)

    def set_furniture(self, map_id: int, furniture_list: list) -> int:
        """Replace the map's furniture with furniture_list ({type, id, angle, vertexs})."""
        fl = [{k: f[k] for k in ("type", "id", "angle", "vertexs") if f.get(k) is not None}
              for f in furniture_list]
        r = self.send("setFurnitureInfo", {"map_id": map_id, "furniture_list": fl})
        return r.get("error_code", 0)

    def set_clean_order(self, map_id: int, order_list: list) -> int:
        """Set the room cleaning order (a list of room ids)."""
        r = self.send("setCleanOrder", {"map_id": map_id, "order_list": list(order_list),
                                         "type": "custom"})
        return r.get("error_code", 0)

    # ---- map backup restore (local) ----------------------------------------------
    def recover_map(self, map_id: int, map_md5: str, url: str) -> int:
        """Restore a map backup. The robot downloads the .bkmap from url (any http(s)
        host it can reach - it need not be TP-Link's storage), checks map_md5 and the
        account binding baked into the file, then applies it. Returns the error_code."""
        r = self.send("mapRecovery", {"map_id": int(map_id), "map_md5": str(map_md5), "url": str(url)})
        return r.get("error_code", 0)

    def get_map_br_process(self) -> dict:
        """Backup / recovery progress: {type, process, status}."""
        return self.send("getMapBRProcess").get("result", {})
