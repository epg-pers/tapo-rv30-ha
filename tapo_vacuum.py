#!/usr/bin/env python3
"""
Tapo TPAP client for RV30 robot vacuum (Jarvis).
Implements SPAKE2+ auth from python-kasa PR #1592.

Usage:
    python3 tapo_vacuum.py <command> [args]

Commands:
    status                      - Current status (battery, state, fan, water)
    info                        - Device info
    maps                        - List all saved maps
    rooms [map]                 - List rooms in a map (default: current map)
    map [map]                   - Render ASCII map with rooms labelled
    records                     - Cleaning history
    consumables                 - Filter/brush usage
    start                       - Start whole-house clean
    clean <room> [room ...]     - Clean specific rooms by name (partial match ok)
    pause                       - Pause cleaning
    resume                      - Resume cleaning
    dock                        - Return to dock
    fan <speed>                 - Global fan speed: quiet/standard/turbo/max/ultra
    passes <n>                  - Global clean pass count: 1, 2 or 3
    water <level>               - Mop water level: off/low/medium/high
    raw <method> [params_json]  - Raw API call

Config via env vars: TAPO_HOST, TAPO_USER, TAPO_PASS
"""

import base64
import collections
import hashlib
import hmac
import json
import os
import pickle
import secrets
import struct
import sys
import tempfile
import warnings
from datetime import datetime, timezone
from pathlib import Path

import lz4.block
import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers.aead import AESCCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.cmac import CMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from ecdsa import NIST256p, ellipticcurve
from urllib3.exceptions import InsecureRequestWarning

warnings.filterwarnings("ignore", category=InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
DEFAULT_HOST = os.environ.get("TAPO_HOST", "")
DEFAULT_USER = os.environ.get("TAPO_USER", "")
DEFAULT_PASS = os.environ.get("TAPO_PASS", "")
SESSION_CACHE = Path(tempfile.gettempdir()) / "tapo_rv30_session.pkl"

# ---------------------------------------------------------------------------
# Enums / constants
# ---------------------------------------------------------------------------
VACUUM_STATUS = {
    0: "Idle", 1: "Cleaning", 2: "Mapping", 4: "GoingHome",
    5: "Charging", 6: "Charged", 7: "Paused", 8: "Undocked", 100: "Error",
}
ERROR_CODES = {
    0: "Ok", 2: "SideBrushStuck", 3: "MainBrushStuck", 4: "WheelBlocked",
    6: "Trapped", 7: "TrappedCliff", 14: "DustBinRemoved", 15: "UnableToMove",
    16: "LidarBlocked", 21: "UnableToFindDock", 22: "BatteryLow",
}
FAN_SPEEDS   = {"quiet": 1, "standard": 2, "turbo": 3, "max": 4, "ultra": 5}
FAN_NAMES    = {v: k for k, v in FAN_SPEEDS.items()}
WATER_LEVELS = {"off": 0, "low": 1, "medium": 2, "high": 3}
WATER_NAMES  = {v: k for k, v in WATER_LEVELS.items()}

# ANSI colours for map rendering (room index → fg colour code)
ROOM_COLORS = ["\033[91m", "\033[92m", "\033[93m", "\033[94m",
               "\033[95m", "\033[96m", "\033[97m"]
RESET = "\033[0m"
BOLD  = "\033[1m"

# ---------------------------------------------------------------------------
# Crypto helpers  (unchanged from previous version)
# ---------------------------------------------------------------------------
def _b64e(b): return base64.b64encode(b).decode()
def _b64d(s): return base64.b64decode(s)
def _md5hex(s): return hashlib.md5(s.encode()).hexdigest()
def _sha1hex(s): return hashlib.sha1(s.encode()).hexdigest()
def _sha256(d): return hashlib.sha256(d).digest()
def _sha512(d): return hashlib.sha512(d).digest()

def _hkdf(master, *, salt, info, length, algo="SHA256"):
    alg = hashes.SHA512() if algo.upper() == "SHA512" else hashes.SHA256()
    return HKDF(algorithm=alg, length=length, salt=salt, info=info).derive(master)

def _hkdf_expand(label, prk, dlen, alg):
    algorithm = hashes.SHA512() if alg.upper() == "SHA512" else hashes.SHA256()
    return HKDF(algorithm=algorithm, length=dlen,
                salt=b"\x00" * dlen, info=label.encode()).derive(prk)

def _hmac(alg, key, data):
    h = hashlib.sha512 if alg.upper() == "SHA512" else hashlib.sha256
    return hmac.new(key, data, h).digest()

def _cmac_aes(key, data):
    c = CMAC(algorithms.AES(key)); c.update(data); return c.finalize()

def _pbkdf2(pw, salt, iters, length):
    return hashlib.pbkdf2_hmac("sha256", pw, salt, iters, length)

P256_M = bytes.fromhex("02886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f")
P256_N = bytes.fromhex("03d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b49")

def _sec1_xy(sec1):
    p = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), sec1)
    n = p.public_numbers(); return n.x, n.y

def _xy_unc(x, y):
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)

def _l8(b): return len(b).to_bytes(8, "little") + b

def _encode_w(w):
    ml = 1 if w == 0 else (w.bit_length() + 7) // 8
    u = w.to_bytes(ml, "big", signed=False)
    return (b"\x00" + u) if (ml % 2 != 0 and u[0] & 0x80) else u

TAG_LEN = NONCE_LEN = 16; NONCE_LEN = 12
CIPHER_LABELS = {
    "aes_128_ccm":       {"ks": b"tp-kdf-salt-aes128-key",   "ki": b"tp-kdf-info-aes128-key",
                           "ns": b"tp-kdf-salt-aes128-iv",    "ni": b"tp-kdf-info-aes128-iv",   "kl": 16},
    "aes_256_ccm":       {"ks": b"tp-kdf-salt-aes256-key",   "ki": b"tp-kdf-info-aes256-key",
                           "ns": b"tp-kdf-salt-aes256-iv",    "ni": b"tp-kdf-info-aes256-iv",   "kl": 32},
    "chacha20_poly1305": {"ks": b"tp-kdf-salt-chacha20-key", "ki": b"tp-kdf-info-chacha20-key",
                           "ns": b"tp-kdf-salt-chacha20-iv",  "ni": b"tp-kdf-info-chacha20-iv", "kl": 32},
}

def _derive_cipher(shared, cid, hkdf_hash="SHA256"):
    L = CIPHER_LABELS[cid]
    key   = _hkdf(shared, salt=L["ks"], info=L["ki"], length=L["kl"], algo=hkdf_hash)
    nonce = _hkdf(shared, salt=L["ns"], info=L["ni"], length=NONCE_LEN, algo=hkdf_hash)
    return key, nonce

def _nonce(base, seq): return base[:-4] + struct.pack(">I", seq)

def _encrypt(cid, key, bn, pt, seq):
    n = _nonce(bn, seq)
    return AESCCM(key, tag_length=16).encrypt(n, pt, None) if cid.startswith("aes_") \
        else ChaCha20Poly1305(key).encrypt(n, pt, None)

def _decrypt(cid, key, bn, ct, seq):
    n = _nonce(bn, seq)
    return AESCCM(key, tag_length=16).decrypt(n, ct, None) if cid.startswith("aes_") \
        else ChaCha20Poly1305(key).decrypt(n, ct, None)

def _derive_ab(cred, salt, iters, hl=32):
    iD = hl + 8; out = _pbkdf2(cred, salt, iters, 2 * iD)
    return int.from_bytes(out[:iD], "big"), int.from_bytes(out[iD:], "big")

def _mac_pass(mac):
    b = bytes.fromhex(mac.replace(":", "").replace("-", ""))
    ikm = b"GqY5o136oa4i6VprTlMW2DpVXxmfW8" + b[3:6] + b[0:3]
    return _hkdf(ikm, salt=b"tp-kdf-salt-default-passcode",
                 info=b"tp-kdf-info-default-passcode", length=32).hex().upper()

def _build_cred(extra, user, pw, mac12):
    if not extra: return (user + "/" + pw) if user else pw
    t = (extra.get("type") or "").lower(); p = extra.get("params") or {}
    if t == "password_shadow":
        pid = int(p.get("passwd_id", 0))
        if pid == 2: return _sha1hex(pw)
        if pid == 3 and user and len(mac12) == 12:
            mac = ":".join(mac12[i:i+2] for i in range(0, 12, 2)).upper()
            return _sha1hex(_md5hex(user) + "_" + mac)
        return pw
    if t == "password_sha_with_salt":
        name = "admin" if int(p.get("sha_name", -1)) == 0 else "user"
        try:
            salt = base64.b64decode(p.get("sha_salt", "")).decode()
            return hashlib.sha256((name + salt + pw).encode()).hexdigest()
        except Exception: return pw
    return (user + "/" + pw) if user else pw

# ---------------------------------------------------------------------------
# Map helpers
# ---------------------------------------------------------------------------
def _b64name(s):
    """Decode a base64-encoded name field, stripping trailing space."""
    try: return base64.b64decode(s).decode(errors="replace").strip()
    except Exception: return s

def _decode_map_pixels(result):
    """Return (width, height, pixels_bytes) from a getMapData result."""
    raw = base64.b64decode(result["map_data"])
    pixels = lz4.block.decompress(raw, uncompressed_size=result["pix_len"])
    return result["width"], result["height"], pixels

def _render_map(width, height, pixels, rooms, charge_coor, vac_coor, scale=2):
    """
    Render the vacuum map as ANSI-coloured ASCII art.

    rooms   – list of dicts from area_list (type=="room")
    charge_coor / vac_coor – [x, y, angle] in grid coords
    scale   – downsample factor (2 = half resolution)
    """
    room_by_id = {r["id"]: r for r in rooms}
    # Assign a stable colour per room ID
    sorted_ids = sorted(room_by_id)
    color_map  = {rid: ROOM_COLORS[i % len(ROOM_COLORS)]
                  for i, rid in enumerate(sorted_ids)}
    # Build char palette
    #  0   → wall  █
    #  1-N → room letter (A B C…) with colour
    #  127 → unseen space
    #  255 → scanned floor (no room) ·
    room_char = {}
    for i, rid in enumerate(sorted_ids):
        room_char[rid] = chr(ord("A") + i)

    lines = []
    # Pixel rows: row 0 = bottom of real space (robot Y increases upward).
    # Iterate rows bottom→top so the map appears right-way up on screen.
    # Columns: col 0 = right of real space (robot X increases leftward in
    # stored data), so iterate right→left to get the correct orientation.
    for row in range(height - 1, -1, -scale):
        line = []
        for col in range(0, width, scale):
            # Sample the dominant pixel in the scale×scale block
            block = []
            for dr in range(scale):
                for dc in range(scale):
                    r2, c2 = row - dr, col + dc
                    if 0 <= r2 < height and 0 <= c2 < width:
                        block.append(pixels[r2 * width + c2])
            dominant = collections.Counter(block).most_common(1)[0][0]

            if dominant == 0:
                line.append("\033[90m█\033[0m")   # dark grey wall
            elif dominant == 127:
                line.append(" ")                   # unexplored
            elif dominant == 255:
                line.append("\033[37m·\033[0m")    # scanned floor
            elif dominant in room_char:
                col_code = color_map[dominant]
                line.append(f"{col_code}{room_char[dominant]}{RESET}")
            else:
                line.append("?")
        lines.append("".join(line))

    # Overlay charger and vacuum positions.
    # Screen row i  = pixel row  (height - 1 - i*scale)  → py = (height-1-gy)//scale
    # Screen col j  = pixel col  (width  - 1 - j*scale)  → px = (width -1-gx)//scale
    def _overlay(lines, gx, gy, char, col_code):
        px = gx // scale
        py = (height - 1 - gy) // scale
        if 0 <= py < len(lines) and 0 <= px < len(lines[0]):
            row_chars = list(lines[py])
            row_chars[px] = f"{BOLD}{col_code}{char}{RESET}"
            lines[py] = "".join(row_chars)

    if charge_coor:
        _overlay(lines, charge_coor[0], charge_coor[1], "⌂", "\033[33m")
    if vac_coor:
        _overlay(lines, vac_coor[0], vac_coor[1], "●", "\033[36m")

    return lines

# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------
PAKE_CTX = b"PAKE V1"

class TapoVacuum:
    def __init__(self, host=DEFAULT_HOST, user=DEFAULT_USER,
                 password=DEFAULT_PASS, port=4433):
        self.host = host; self.port = port
        self.username = user; self.password = password
        self.base_url = f"https://{host}:{port}"
        self._sess = requests.Session(); self._sess.verify = False
        self._device_mac = ""; self._tpap_pake = []
        self._session_id = ""; self._seq = 1
        self._cipher_id = "aes_128_ccm"; self._hkdf_hash = "SHA256"
        self._key = b""; self._base_nonce = b""

    # ---- HTTP ----------------------------------------------------------------
    def _post(self, path, body=None, binary=False):
        url = self.base_url + path
        if binary:
            r = self._sess.post(url, data=body,
                headers={"Content-Type": "application/octet-stream"}, timeout=15)
        else:
            r = self._sess.post(url, json=body,
                headers={"Content-Type": "application/json"}, timeout=15)
        r.raise_for_status()
        return r.content if binary else r.json()

    # ---- Session cache -------------------------------------------------------
    def _load_session(self):
        try:
            d = pickle.loads(SESSION_CACHE.read_bytes())
            if d.get("host") == self.host and d.get("user") == self.username:
                self._device_mac = d["mac"];  self._tpap_pake  = d["pake"]
                self._session_id = d["sid"];  self._seq        = d["seq"]
                self._cipher_id  = d["cid"];  self._hkdf_hash  = d["hkdf"]
                self._key        = d["key"];  self._base_nonce = d["nonce"]
                return True
        except Exception: pass
        return False

    def _save_session(self):
        try:
            SESSION_CACHE.write_bytes(pickle.dumps({
                "host": self.host, "user": self.username,
                "mac": self._device_mac, "pake": self._tpap_pake,
                "sid": self._session_id, "seq": self._seq,
                "cid": self._cipher_id, "hkdf": self._hkdf_hash,
                "key": self._key, "nonce": self._base_nonce,
            }))
        except Exception: pass

    def _clear_session(self):
        try: SESSION_CACHE.unlink()
        except Exception: pass
        self._session_id = ""

    # ---- Auth ----------------------------------------------------------------
    def _discover(self):
        d = self._post("/", {"method": "login",
                             "params": {"sub_method": "discover"}})
        r = d["result"]
        self._device_mac = r.get("mac") or ""
        self._tpap_pake  = (r.get("tpap") or {}).get("pake") or []

    def _authenticate(self):
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
        if reg.get("error_code", 0): raise RuntimeError(f"pake_register: {reg}")
        r = reg["result"]

        st = int(r.get("cipher_suites") or 2)
        iters = int(r.get("iterations") or 10000)
        self._cipher_id = (r.get("encryption") or "aes_128_ccm").lower().replace("-","_")
        self._hkdf_hash = "SHA512" if st in (2,4,5,7,9) else "SHA256"
        cmac = st in (8, 9); dlen = 64 if self._hkdf_hash == "SHA512" else 32

        mac12 = self._device_mac.replace(":","").replace("-","")
        cred  = (_mac_pass(self._device_mac) if ptype == "default_userpw" and self._device_mac
                 else _build_cred(r.get("extra_crypt") or {}, self.username, self.password, mac12))

        G = NIST256p.generator; order = G.order(); curve = NIST256p.curve
        Mx, My = _sec1_xy(P256_M); Nx, Ny = _sec1_xy(P256_N)
        M = ellipticcurve.Point(curve, Mx, My, order)
        N = ellipticcurve.Point(curve, Nx, Ny, order)

        a, b = _derive_ab(cred.encode(), _b64d(r["dev_salt"]), iters)
        w, h = a % order, b % order
        x = secrets.randbelow(order - 1) + 1

        L      = x * G + w * M;        L_enc = _xy_unc(L.x(), L.y())
        Rx, Ry = _sec1_xy(_b64d(r["dev_share"]))
        R      = ellipticcurve.Point(curve, Rx, Ry, order); R_enc = _xy_unc(R.x(), R.y())
        Rp     = R + (-(w * N))
        Z_enc  = _xy_unc((x * Rp).x(), (x * Rp).y())
        V_enc  = _xy_unc(((h % order) * Rp).x(), ((h % order) * Rp).y())

        hfn   = _sha512 if self._hkdf_hash == "SHA512" else _sha256
        ctx   = hfn(PAKE_CTX + _b64d(ur) + _b64d(r["dev_random"]))
        trans = (_l8(ctx) + _l8(b"") + _l8(b"")
                 + _l8(_xy_unc(Mx,My)) + _l8(_xy_unc(Nx,Ny))
                 + _l8(L_enc) + _l8(R_enc) + _l8(Z_enc) + _l8(V_enc)
                 + _l8(_encode_w(w)))
        T     = hfn(trans)

        ml   = 16 if cmac else 32
        conf = _hkdf_expand("ConfirmationKeys", T, ml * 2, self._hkdf_hash)
        KcA, KcB  = conf[:ml], conf[ml:ml*2]
        shared    = _hkdf_expand("SharedKey", T, dlen, self._hkdf_hash)
        mac_fn    = _cmac_aes if cmac else (lambda k, d: _hmac(self._hkdf_hash, k, d))
        u_confirm = mac_fn(KcA, R_enc)
        e_confirm = mac_fn(KcB, L_enc)

        share = self._post("/", {"method": "login", "params": {
            "sub_method": "pake_share",
            "user_share":   _b64e(L_enc),
            "user_confirm": _b64e(u_confirm),
        }})
        if share.get("error_code", 0): raise RuntimeError(f"pake_share: {share}")
        s = share["result"]

        if (s.get("dev_confirm") or "").lower() != _b64e(e_confirm).lower():
            raise RuntimeError("SPAKE2+ confirmation mismatch - wrong password?")

        self._session_id = s.get("sessionId") or s.get("stok") or ""
        self._seq        = int(s.get("start_seq") or 1)
        self._key, self._base_nonce = _derive_cipher(shared, self._cipher_id, self._hkdf_hash)
        self._save_session()

    def _ensure_auth(self):
        if not self._session_id:
            self._load_session() or self._authenticate()

    # ---- Send ----------------------------------------------------------------
    def send(self, method, params=None):
        self._ensure_auth()
        for attempt in range(2):
            try:
                payload = (struct.pack(">I", self._seq)
                           + _encrypt(self._cipher_id, self._key, self._base_nonce,
                                      json.dumps({"method": method,
                                                  "params": params or {}}).encode(),
                                      self._seq))
                raw = self._post(f"/stok={self._session_id}/ds", payload, binary=True)
                if len(raw) < 4 + 16:
                    raise RuntimeError(f"Response too short ({len(raw)}b)")
                rseq  = struct.unpack(">I", raw[:4])[0]
                plain = _decrypt(self._cipher_id, self._key, self._base_nonce, raw[4:], rseq)
                self._seq += 1; self._save_session()
                resp = json.loads(plain.decode())
                if resp.get("error_code", 0):
                    raise RuntimeError(f"Device error {resp['error_code']}: {resp}")
                return resp
            except Exception as e:
                if attempt == 0:
                    self._clear_session(); self._authenticate()
                else:
                    raise

    # ---- Map helpers --------------------------------------------------------
    def get_map_info(self):
        """Return (current_map_id, map_list)."""
        r = self.send("getMapInfo")["result"]
        return r["current_map_id"], r["map_list"]

    def get_map_data(self, map_id):
        """Fetch full map data for a given map_id."""
        return self.send("getMapData", {"map_id": map_id})["result"]

    def _resolve_map(self, name_pattern=None):
        """Return (map_id, map_list) for the current or named map."""
        current_id, maps = self.get_map_info()
        if name_pattern is None:
            return current_id, maps
        pat = name_pattern.lower()
        for m in maps:
            if pat in _b64name(m["map_name"]).lower():
                return m["map_id"], maps
        raise ValueError(f"No map matching '{name_pattern}'. "
                         f"Available: {[_b64name(m['map_name']) for m in maps]}")

    def get_rooms(self, map_id=None):
        """Return list of room dicts for the given (or current) map."""
        if map_id is None:
            map_id, _ = self.get_map_info()
        data = self.get_map_data(map_id)
        return [a for a in data.get("area_list", []) if a.get("type") == "room"], data

    def _resolve_rooms(self, name_patterns, map_id=None):
        """Match room names (case-insensitive partial) → list of room dicts."""
        rooms, data = self.get_rooms(map_id)
        matched = []
        for pat in name_patterns:
            decoded = [_b64name(r["name"]) for r in rooms]
            exact = [r for r, n in zip(rooms, decoded) if n.lower() == pat.lower()]
            hits = exact or [r for r, n in zip(rooms, decoded) if pat.lower() in n.lower()]
            if not hits:
                available = [_b64name(r["name"]) for r in rooms]
                raise ValueError(f"No room matching '{pat}'. Available: {available}")
            matched.extend(hits)
        # deduplicate preserving order
        seen = set(); result = []
        for r in matched:
            if r["id"] not in seen:
                seen.add(r["id"]); result.append(r)
        return result, int(data["map_id"])

    # ---- Vacuum control -----------------------------------------------------
    def start(self):
        return self.send("setSwitchClean", {
            "clean_mode": 0, "clean_on": True,
            "clean_order": True, "force_clean": False,
        })

    def clean_rooms(self, room_name_patterns, map_name=None):
        """Clean specific rooms by name (partial match)."""
        map_id = None
        if map_name:
            map_id, _ = self._resolve_map(map_name)
        rooms, map_id = self._resolve_rooms(room_name_patterns, map_id)
        return self.send("setSwitchClean", {
            "clean_mode":  3,
            "clean_on":    True,
            "clean_order": True,
            "force_clean": False,
            "map_id":      map_id,
            "room_list":   [r["id"] for r in rooms],
            "start_type":  1,
        })

    def pause(self):
        status = self.send("getVacStatus")["result"].get("status")
        if status == 4:
            return self.send("setSwitchCharge", {"switch_charge": False})
        return self.send("setRobotPause", {"pause": True})

    def resume(self):  return self.send("setRobotPause",   {"pause": False})
    def dock(self):    return self.send("setSwitchCharge",  {"switch_charge": True})

    def set_fan_speed(self, name):
        v = FAN_SPEEDS.get(name.lower())
        if v is None:
            raise ValueError(f"Invalid speed '{name}'. Options: {', '.join(FAN_SPEEDS)}")
        return self.send("setCleanAttr", {"suction": v, "type": "global"})

    def set_passes(self, n):
        n = int(n)
        if n not in (1, 2, 3): raise ValueError("Passes must be 1, 2 or 3")
        return self.send("setCleanAttr", {"clean_number": n, "type": "global"})

    def set_water(self, name):
        v = WATER_LEVELS.get(name.lower())
        if v is None:
            raise ValueError(f"Invalid level '{name}'. Options: {', '.join(WATER_LEVELS)}")
        # setCleanAttr takes current settings + updated cistern
        cur = self.send("getCleanAttr", {"type": "global"})["result"]
        cur["cistern"] = v; cur["type"] = "global"
        return self.send("setCleanAttr", cur)

    def get_status(self):
        vac   = self.send("getVacStatus")["result"]
        batt  = self.send("getBatteryInfo")["result"]
        info  = self.send("getCleanInfo")["result"]
        attr  = self.send("getCleanAttr", {"type": "global"})["result"]
        mop   = self.send("getMopState")["result"]
        sc = vac["status"]; ec = (vac.get("err_status") or [0])[0]
        return {
            "status":     VACUUM_STATUS.get(sc, f"Unknown({sc})"),
            "error":      ERROR_CODES.get(ec, f"Code({ec})") if ec else "None",
            "battery":    batt.get("battery_percentage"),
            "fan_speed":  FAN_NAMES.get(attr.get("suction"), str(attr.get("suction"))),
            "water":      WATER_NAMES.get(attr.get("cistern"), str(attr.get("cistern"))),
            "passes":     attr.get("clean_number"),
            "mop":        "attached" if mop.get("mop_state") else "not attached",
            "clean_area": info.get("clean_area"),
            "clean_mins": info.get("clean_time"),
            "progress":   info.get("clean_percent"),
        }

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _ts(unix):
    return datetime.fromtimestamp(unix, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__); sys.exit(0)

    v   = TapoVacuum()
    cmd = args[0].lower()

    # ---- status --------------------------------------------------------------
    if cmd == "status":
        s = v.get_status()
        print(f"Status:   {BOLD}{s['status']}{RESET}")
        print(f"Battery:  {s['battery']}%")
        print(f"Fan:      {s['fan_speed']}  |  Water: {s['water']}  |  Passes: {s['passes']}")
        print(f"Mop:      {s['mop']}")
        if s["status"] == "Cleaning":
            print(f"Area:     {s['clean_area']} m²  |  Time: {s['clean_mins']} min  |  {s['progress']}% done")
        if s["error"] != "None":
            print(f"ERROR:    {s['error']}")

    # ---- info ----------------------------------------------------------------
    elif cmd == "info":
        r = v.send("getDeviceInfo")["result"]
        print(f"Name:    {_b64name(r.get('nickname',''))}")
        print(f"Model:   {r['model']}  HW {r['hw_ver']}  FW {r['fw_ver']}")
        print(f"IP:      {r['ip']}  SSID: {_b64name(r.get('ssid',''))}  RSSI: {r['rssi']} dBm")
        print(f"MAC:     {r['mac']}")

    # ---- maps ----------------------------------------------------------------
    elif cmd == "maps":
        current_id, maps = v.get_map_info()
        for m in maps:
            marker = " ← current" if m["map_id"] == current_id else ""
            print(f"  [{m['map_id']}] {_b64name(m['map_name'])}{marker}")

    # ---- rooms ---------------------------------------------------------------
    elif cmd == "rooms":
        pat = args[1] if len(args) > 1 else None
        map_id, map_list = v._resolve_map(pat)
        map_name = next((_b64name(m["map_name"]) for m in map_list
                         if m["map_id"] == map_id), str(map_id))
        rooms, _ = v.get_rooms(map_id)
        print(f"Map: {map_name}")
        print(f"{'ID':>4}  {'Name':<20}  {'Fan':<10}  {'Water':<8}  Passes")
        print("-" * 55)
        for r in rooms:
            name    = _b64name(r["name"])
            fan     = FAN_NAMES.get(r.get("suction"), str(r.get("suction")))
            water   = WATER_NAMES.get(r.get("cistern"), str(r.get("cistern")))
            passes  = r.get("clean_number", "?")
            print(f"  {r['id']:>2}  {name:<20}  {fan:<10}  {water:<8}  {passes}")

    # ---- map (visual) -------------------------------------------------------
    elif cmd == "map":
        pat = args[1] if len(args) > 1 else None
        map_id, map_list = v._resolve_map(pat)
        map_name = next((_b64name(m["map_name"]) for m in map_list
                         if m["map_id"] == map_id), str(map_id))
        data  = v.get_map_data(map_id)
        rooms = [a for a in data.get("area_list", []) if a["type"] == "room"]
        w, h, pixels = _decode_map_pixels(data)

        lines = _render_map(w, h, pixels, rooms,
                            data.get("charge_coor"), data.get("vac_coor"), scale=2)

        print(f"\nMap: {BOLD}{map_name}{RESET}  ({w}×{h} px, {data['resolution']}mm/px)\n")
        for line in lines:
            print("  " + line)

        # Legend
        print()
        sorted_rooms = sorted(rooms, key=lambda r: r["id"])
        for i, r in enumerate(sorted_rooms):
            col  = ROOM_COLORS[i % len(ROOM_COLORS)]
            ch   = chr(ord("A") + i)
            name = _b64name(r["name"])
            fan  = FAN_NAMES.get(r.get("suction"), str(r.get("suction")))
            water  = WATER_NAMES.get(r.get("cistern"), str(r.get("cistern")))
            passes = r.get("clean_number", "?")
            print(f"  {col}{ch}{RESET} = {name:<18} fan={fan}  water={water}  passes={passes}")
        print(f"  \033[33m⌂{RESET} = Dock   \033[36m●{RESET} = Jarvis")

    # ---- clean (rooms) -------------------------------------------------------
    elif cmd == "clean":
        if len(args) < 2:
            # whole house
            v.start(); print("Starting whole-house clean.")
        else:
            rooms_matched, map_id = v._resolve_rooms(args[1:])
            names = ", ".join(_b64name(r["name"]) for r in rooms_matched)
            v.clean_rooms(args[1:])
            print(f"Cleaning: {names}")

    # ---- start ---------------------------------------------------------------
    elif cmd == "start":
        v.start(); print("Starting whole-house clean.")

    # ---- pause / resume / dock -----------------------------------------------
    elif cmd == "pause":  v.pause();  print("Paused.")
    elif cmd == "resume": v.resume(); print("Resumed.")
    elif cmd == "dock":   v.dock();   print("Returning to dock.")

    # ---- fan / passes / water ------------------------------------------------
    elif cmd == "fan":
        if len(args) < 2:
            print(f"Usage: fan <{'|'.join(FAN_SPEEDS)}>"); sys.exit(1)
        v.set_fan_speed(args[1]); print(f"Fan speed → {args[1]}")

    elif cmd == "passes":
        if len(args) < 2:
            print("Usage: passes <1|2|3>"); sys.exit(1)
        v.set_passes(args[1]); print(f"Clean passes → {args[1]}")

    elif cmd == "water":
        if len(args) < 2:
            print(f"Usage: water <{'|'.join(WATER_LEVELS)}>"); sys.exit(1)
        v.set_water(args[1]); print(f"Water level → {args[1]}")

    # ---- records -------------------------------------------------------------
    elif cmd == "records":
        _, maps = v.get_map_info()
        map_names = {m["map_id"]: _b64name(m["map_name"]) for m in maps}
        r = v.send("getCleanRecords")["result"]
        total_h, total_m = divmod(r["total_time"], 60)
        print(f"Total: {r['total_number']} cleans  |  "
              f"{r['total_area']} m²  |  {total_h}h {total_m}m\n")
        print(f"{'Date':<20}  {'Map':<14}  {'Area':>6}  {'Time':>6}  {'Dust':>5}  {'Err'}")
        print("-" * 68)
        for rec in r.get("record_list", []):
            ts      = _ts(rec["timestamp"])
            mapname = map_names.get(rec.get("map_id"), "?")[:13]
            area    = rec.get("clean_area", 0)
            mins    = rec.get("clean_time", 0)
            dust    = "yes" if rec.get("dust_collection") else "no"
            err     = ERROR_CODES.get(rec.get("error", 0), str(rec.get("error")))
            print(f"{ts:<20}  {mapname:<14}  {area:>5}m²  {mins:>5}m  {dust:>5}  {err}")

    # ---- consumables ---------------------------------------------------------
    elif cmd == "consumables":
        r = v.send("getConsumablesInfo")["result"]
        # Device reports time used in minutes; limits are in hours
        fields = [("roll_brush_time",     "Main brush",      400),
                  ("edge_brush_time",     "Side brush",      200),
                  ("filter_time",         "Filter",          200),
                  ("sensor_time",         "Sensor",           30),
                  ("charge_contact_time", "Charge contacts",  30)]
        for key, label, limit_h in fields:
            used_h    = r.get(key, 0) / 60
            remain_h  = max(0.0, limit_h - used_h)
            pct_used  = min(100, int(used_h / limit_h * 100))
            bar       = "█" * (pct_used // 5) + "░" * (20 - pct_used // 5)
            warn      = "  ⚠ REPLACE NOW" if remain_h == 0 else \
                        "  ⚠ REPLACE SOON" if remain_h < limit_h * 0.1 else ""
            print(f"{label:<18}  {bar}  {remain_h:.1f}h remaining  ({pct_used}% used){warn}")

    # ---- raw -----------------------------------------------------------------
    elif cmd == "raw":
        method = args[1] if len(args) > 1 else ""
        params = json.loads(args[2]) if len(args) > 2 else {}
        if not method: print("Usage: raw <method> [params_json]"); sys.exit(1)
        print(json.dumps(v.send(method, params), indent=2))

    else:
        print(f"Unknown command: {cmd}\n"); print(__doc__); sys.exit(1)


if __name__ == "__main__":
    main()
