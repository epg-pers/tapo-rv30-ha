"""TPAP SPAKE2+ transport and vacuum client for Tapo RV30."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import pickle
import secrets
import struct
import tempfile
import threading
import warnings
from pathlib import Path

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers.aead import AESCCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from ecdsa import NIST256p, ellipticcurve
from urllib3.exceptions import InsecureRequestWarning

from .const import DOCKED_CODES

warnings.filterwarnings("ignore", category=InsecureRequestWarning)
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

# SPAKE2+ P-256 constants
_P256_M = bytes.fromhex("02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f")
_P256_N = bytes.fromhex("03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49")

def _sec1_xy(sec1: bytes):
    p = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), sec1)
    n = p.public_numbers(); return n.x, n.y

def _xy_unc(x: int, y: int) -> bytes:
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key().public_bytes(
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

# ---------------------------------------------------------------------------
# TapoVacuumClient
# ---------------------------------------------------------------------------
_PAKE_CTX = b"PAKE V1"


class AuthError(Exception):
    """Raised when SPAKE2+ auth fails (wrong credentials, session expired)."""


class TapoVacuumClient:
    """Synchronous TPAP client.  All methods are blocking — run in an executor."""

    def __init__(self, host: str, username: str, password: str, port: int = 4433) -> None:
        self.host     = host
        self.port     = port
        self.username = username
        self.password = password
        self.base_url = f"https://{host}:{port}"
        self._http    = requests.Session()
        self._http.verify = False
        self._cache   = Path(tempfile.gettempdir()) / f"tapo_rv30_{host}.pkl"
        # HA calls us from several executor threads (poll + commands); the session
        # seq/nonce is shared state, so one request at a time.
        self._lock    = threading.RLock()

        self._device_mac = ""
        self._tpap_pake: list[int] = []
        self._session_id = ""
        self._seq        = 1
        self._cipher_id  = "aes_128_ccm"
        self._hkdf_hash  = "SHA256"
        self._key        = b""
        self._base_nonce = b""

    # ---- Internal HTTP -------------------------------------------------------
    def _post(self, path: str, body=None, binary: bool = False):
        url = self.base_url + path
        if binary:
            r = self._http.post(url, data=body,
                headers={"Content-Type": "application/octet-stream"}, timeout=15)
        else:
            r = self._http.post(url, json=body,
                headers={"Content-Type": "application/json"}, timeout=15)
        r.raise_for_status()
        return r.content if binary else r.json()

    # ---- Session cache -------------------------------------------------------
    def _load_session(self) -> bool:
        try:
            d = pickle.loads(self._cache.read_bytes())
            if d.get("host") == self.host and d.get("user") == self.username:
                self._device_mac = d["mac"];  self._tpap_pake  = d["pake"]
                self._session_id = d["sid"];  self._seq        = d["seq"]
                self._cipher_id  = d["cid"];  self._hkdf_hash  = d["hkdf"]
                self._key        = d["key"];  self._base_nonce = d["nonce"]
                return True
        except Exception:
            pass
        return False

    def _save_session(self) -> None:
        try:
            self._cache.write_bytes(pickle.dumps({
                "host": self.host, "user": self.username,
                "mac": self._device_mac, "pake": self._tpap_pake,
                "sid": self._session_id, "seq": self._seq,
                "cid": self._cipher_id, "hkdf": self._hkdf_hash,
                "key": self._key, "nonce": self._base_nonce,
            }))
        except Exception:
            pass

    def _clear_session(self) -> None:
        try: self._cache.unlink()
        except Exception: pass
        self._session_id = ""

    # ---- SPAKE2+ auth --------------------------------------------------------
    def _discover(self) -> None:
        d = self._post("/", {"method": "login", "params": {"sub_method": "discover"}})
        r = d["result"]
        self._device_mac = r.get("mac") or ""
        self._tpap_pake  = (r.get("tpap") or {}).get("pake") or []

    def authenticate(self) -> None:
        """Run full SPAKE2+ handshake. Raises AuthError on failure."""
        self._discover()
        ptype = ("default_userpw" if 0 in self._tpap_pake else
                 "userpw"         if 2 in self._tpap_pake else
                 "shared_token"   if 3 in self._tpap_pake else "userpw")
        ur = _b64e(os.urandom(32))

        reg = self._post("/", {"method": "login", "params": {
            "sub_method": "pake_register", "username": _md5hex("admin"),
            "user_random": ur, "cipher_suites": [1],
            "encryption": ["aes_128_ccm", "chacha20_poly1305", "aes_256_ccm"],
            "passcode_type": ptype, "stok": None,
        }})
        if reg.get("error_code", 0):
            raise AuthError(f"pake_register failed: error_code={reg.get('error_code')}")
        r = reg["result"]

        st = int(r.get("cipher_suites") or 2)
        iters = int(r.get("iterations") or 10000)
        self._cipher_id = (r.get("encryption") or "aes_128_ccm").lower().replace("-", "_")
        self._hkdf_hash = "SHA512" if st in (2, 4, 5, 7, 9) else "SHA256"
        cmac = st in (8, 9)
        dlen = 64 if self._hkdf_hash == "SHA512" else 32

        mac12 = self._device_mac.replace(":", "").replace("-", "")
        cred  = _build_cred(r.get("extra_crypt") or {}, self.username, self.password, mac12)

        G = NIST256p.generator; order = G.order(); curve = NIST256p.curve
        Mx, My = _sec1_xy(_P256_M); Nx, Ny = _sec1_xy(_P256_N)
        M = ellipticcurve.Point(curve, Mx, My, order)
        N = ellipticcurve.Point(curve, Nx, Ny, order)

        a, b = _derive_ab(cred.encode(), _b64d(r["dev_salt"]), iters)
        w, h = a % order, b % order
        x = secrets.randbelow(order - 1) + 1

        L     = x * G + w * M;   L_enc = _xy_unc(L.x(), L.y())
        Rx, Ry = _sec1_xy(_b64d(r["dev_share"]))
        R     = ellipticcurve.Point(curve, Rx, Ry, order); R_enc = _xy_unc(R.x(), R.y())
        Rp    = R + (-(w * N))
        Z_enc = _xy_unc((x * Rp).x(), (x * Rp).y())
        V_enc = _xy_unc(((h % order) * Rp).x(), ((h % order) * Rp).y())

        hfn   = _sha512 if self._hkdf_hash == "SHA512" else _sha256
        ctx   = hfn(_PAKE_CTX + _b64d(ur) + _b64d(r["dev_random"]))
        trans = (_l8(ctx) + _l8(b"") + _l8(b"")
                 + _l8(_xy_unc(Mx, My)) + _l8(_xy_unc(Nx, Ny))
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

        share = self._post("/", {"method": "login", "params": {
            "sub_method": "pake_share",
            "user_share":   _b64e(L_enc),
            "user_confirm": _b64e(u_conf),
        }})
        if share.get("error_code", 0):
            raise AuthError(f"pake_share failed: error_code={share.get('error_code')}")
        s = share["result"]

        if (s.get("dev_confirm") or "").lower() != _b64e(e_conf).lower():
            raise AuthError("SPAKE2+ confirmation mismatch — wrong password?")

        self._session_id = s.get("sessionId") or s.get("stok") or ""
        self._seq        = int(s.get("start_seq") or 1)
        self._key, self._base_nonce = _derive_cipher(shared, self._cipher_id, self._hkdf_hash)
        self._save_session()
        _LOGGER.debug("TPAP session established with %s", self.host)

    def _ensure_auth(self) -> None:
        if not self._session_id:
            self._load_session() or self.authenticate()

    # ---- Send ----------------------------------------------------------------
    def send(self, method: str, params: dict | None = None) -> dict:
        with self._lock:
            return self._send(method, params)

    def _send(self, method: str, params: dict | None = None) -> dict:
        """Send an encrypted request. Re-auths once on session expiry."""
        self._ensure_auth()
        for attempt in range(2):
            try:
                payload = (struct.pack(">I", self._seq)
                           + _encrypt(self._cipher_id, self._key, self._base_nonce,
                                      json.dumps({"method": method,
                                                  "params": params or {}}).encode(),
                                      self._seq))
                raw = self._post(f"/stok={self._session_id}/ds", payload, binary=True)
                if len(raw) < 4 + _TAG_LEN:
                    raise RuntimeError(f"Response too short ({len(raw)} bytes)")
                rseq  = struct.unpack(">I", raw[:4])[0]
                plain = _decrypt(self._cipher_id, self._key, self._base_nonce, raw[4:], rseq)
                self._seq += 1
                self._save_session()
                resp = json.loads(plain.decode())
                if resp.get("error_code", 0):
                    raise RuntimeError(f"Device error {resp['error_code']}")
                return resp
            except AuthError:
                raise
            except Exception as exc:
                if attempt == 0:
                    _LOGGER.debug("Send failed (%s), re-authenticating", exc)
                    self._clear_session()
                    self.authenticate()
                else:
                    raise

    # ---- High-level API calls -----------------------------------------------
    def get_status(self) -> dict:
        vac  = self.send("getVacStatus")["result"]
        batt = self.send("getBatteryInfo")["result"]
        info = self.send("getCleanInfo")["result"]
        attr = self.send("getCleanAttr", {"type": "global"})["result"]
        mop  = self.send("getMopState")["result"]
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
        }

    def get_nickname(self) -> str:
        import base64
        raw = self.send("getDeviceInfo")["result"].get("nickname", "")
        try:
            return base64.b64decode(raw).decode(errors="replace").strip() or "Tapo RV30"
        except Exception:
            return raw or "Tapo RV30"

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

    def clean_rooms(self, room_ids: list[int], map_id: int, clean_order: bool = True) -> None:
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
        try:
            self.send("setSwitchClean", {"clean_on": False})
        except RuntimeError:
            self.send("setRobotPause", {"pause": True})  # at least halt it

    def set_fan_speed(self, value: int) -> None:
        self.send("setCleanAttr", {"suction": value, "type": "global"})

    def set_passes(self, value: int) -> None:
        self.send("setCleanAttr", {"clean_number": value, "type": "global"})

    def set_water(self, value: int) -> None:
        cur = self.send("getCleanAttr", {"type": "global"})["result"]
        cur["cistern"] = value; cur["type"] = "global"
        self.send("setCleanAttr", cur)

    # ---- Settings & extras (names from the decompiled Tapo app, 2026-10-13) ----
    _SETTINGS = (("dust", "getDustCollectionInfo", None), ("dnd", "getDoNotDisturb", None),
                 ("volume", "getVolume", None), ("child_lock", "getChildLockInfo", None),
                 ("carpet_boost", "getCarpetAutoBoost", None), ("records", "getCleanRecords", None),
                 ("schedules", "get_schedule_rules", {"start_index": 0}))

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
        cur = self.send(getter)["result"]
        cur.update(changes)
        self.send(setter, cur)

    def empty_bin(self) -> None:
        self.send("setSwitchDustCollection", {"switch_dust_collection": True})

    def set_auto_empty(self, on: bool) -> None:
        self._merge_set("getDustCollectionInfo", "setDustCollectionInfo", auto_dust_collection=on)

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
        """The app sends every room with type 'custom'; unchanged rooms keep their values."""
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
