"""Read-only access to the TP-Link cloud's map backups for a robot.

The Tapo app's own "back up map" feature makes the robot upload its map to TP-Link;
this lists those backups and downloads them so they can be kept (and compared with
what the robot reports locally). Nothing here talks to the robot.

Flow, from the Tapo Android app: account region lookup and password login (signed
with the app's public access key), then the device list and the per-device
"map/detail" list (token auth), then plain GETs of the presigned backup links.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import uuid
from typing import Any

import requests

_LOGGER = logging.getLogger(__name__)

APP_TYPE = "TP-Link_Tapo_Android"
APP_VERSION = "3.10.502"
# Public keys baked into the Tapo app for signing account requests.
ACCESS_KEY = "4d11b6b9d5ea4d19a829adbb9714b057"
SECRET_KEY = "6ed7d97f3e73467f8a5bab90b577ba4c"
# The app resolves its account host at runtime; these are the known public ones.
ACCOUNT_HOSTS = ("https://n-wap.i.tplinkcloud.com", "https://n-wap-gw.tplinkcloud.com")
TIMEOUT = 30


class CloudError(Exception):
    """A TP-Link cloud request failed (message is safe to show)."""


def _signed_headers(path: str, body: bytes) -> dict[str, str]:
    content_md5 = base64.b64encode(hashlib.md5(body).digest()).decode()
    nonce = str(uuid.uuid4())
    timestamp = "9999999999"  # the app sends this constant
    msg = f"{content_md5}\n{timestamp}\n{nonce}\n{path}".encode()
    sig = hmac.new(SECRET_KEY.encode(), msg, hashlib.sha1).hexdigest()
    return {
        "Content-Type": "application/json;charset=UTF-8",
        "Content-MD5": content_md5,
        "X-Authorization": f"Timestamp={timestamp}, Nonce={nonce}, AccessKey={ACCESS_KEY}, Signature={sig}",
    }


def _unwrap(resp: requests.Response, what: str) -> Any:
    try:
        data = resp.json()
    except ValueError as exc:
        raise CloudError(f"{what}: HTTP {resp.status_code}, not JSON") from exc
    if isinstance(data, dict) and "error_code" in data:
        if data.get("error_code") not in (0, None):
            raise CloudError(f"{what}: error {data.get('error_code')} {data.get('msg') or ''}".strip())
        return data.get("result", data)
    if resp.status_code >= 400:
        msg = data.get("message") or data.get("msg") if isinstance(data, dict) else None
        raise CloudError(f"{what}: HTTP {resp.status_code} {msg or ''}".strip())
    return data


class TapoCloud:
    def __init__(self, username: str, password: str, terminal_uuid: str) -> None:
        self._username = username
        self._password = password
        self._terminal = terminal_uuid
        self._http = requests.Session()
        self.token: str | None = None
        self.app_server: str | None = None

    def _account_post(self, base: str, path: str, payload: dict, what: str) -> Any:
        body = json.dumps(payload, separators=(",", ":")).encode()
        resp = self._http.post(base + path, data=body, headers=_signed_headers(path, body), timeout=TIMEOUT)
        return _unwrap(resp, what)

    def login(self) -> None:
        errors = []
        for host in ACCOUNT_HOSTS:
            try:
                status = self._account_post(host, "/api/v2/account/getAccountStatusAndUrl",
                                            {"appType": APP_TYPE, "cloudUserName": self._username},
                                            "account lookup")
            except (CloudError, requests.RequestException) as exc:
                errors.append(f"{host}: {exc}")
                continue
            server = (status or {}).get("appServerUrl")
            if not server:
                errors.append(f"{host}: no appServerUrl in {sorted(status or {})}")
                continue
            _LOGGER.debug("TP-Link account host %s -> app server %s", host, server)
            result = self._account_post(server, "/api/v2/account/login", {
                "appType": APP_TYPE, "appVersion": APP_VERSION,
                "cloudUserName": self._username, "cloudPassword": self._password,
                "platform": "Android", "refreshTokenNeeded": False,
                "terminalUUID": self._terminal, "terminalName": "Home Assistant",
                "terminalMeta": "1",
            }, "login")
            if not result or not result.get("token"):
                if result and (result.get("MFAProcessId") or result.get("supportedMFATypes")):
                    raise CloudError("TP-Link asked for a verification code (two-step login); "
                                     "this is not supported yet")
                raise CloudError(f"login: no token (fields {sorted(result or {})})")
            self.token = result["token"]
            self.app_server = result.get("appServerUrl") or server
            return
        raise CloudError("account lookup failed: " + "; ".join(errors))

    def _get(self, url: str, what: str, **params: Any) -> Any:
        resp = self._http.get(url, params=params or None, timeout=TIMEOUT, headers={
            "Authorization": f"ut|{self.token}", "app-cid": f"app:{APP_TYPE}:{self._terminal}",
            "x-app-name": APP_TYPE, "x-app-version": APP_VERSION, "x-term-id": self._terminal,
        })
        return _unwrap(resp, what)

    def things(self) -> list[dict]:
        out, page = [], 0
        while True:
            res = self._get(f"{self.app_server}/v2/things", "device list", page=page, pageSize=50)
            items = (res.get("data") or res.get("list") or []) if isinstance(res, dict) else (res or [])
            out.extend(items)
            total = res.get("total") if isinstance(res, dict) else None
            if not items or total is None or len(out) >= total:
                return out
            page += 1

    def map_backups(self, thing: dict) -> list[dict]:
        server = thing.get("appServerUrl") or self.app_server
        res = self._get(f"{server}/v1/things/{thing['thingName']}/map/detail", "backup list")
        return res if isinstance(res, list) else (res or {}).get("data") or []

    def download(self, url: str) -> bytes:
        # Presigned storage link: no TP-Link auth headers.
        resp = requests.get(url, timeout=TIMEOUT)
        if resp.status_code != 200:
            raise CloudError(f"download: HTTP {resp.status_code}")
        return resp.content


def fetch_backups(client, username: str, password: str, terminal_uuid: str, folder: str,
                  local_reads: bool) -> dict:
    """Blocking: save every cloud map backup of this robot (plus, when the robot is idle,
    its current local getMapData for the same maps) into folder, and summarise."""
    import os
    import time

    info = client.send("get_device_info")["result"]
    cloud = TapoCloud(username, password, terminal_uuid)
    cloud.login()
    things = cloud.things()
    thing = pick_thing(things, info.get("device_id"), info.get("mac"))
    if thing is None:
        raise CloudError("could not find this robot in the TP-Link account (devices seen: " + ", ".join(
            f"{t.get('deviceType')}/{t.get('deviceModel') or t.get('model')}" for t in things) + ")")
    backups = cloud.map_backups(thing)
    os.makedirs(folder, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    out = {"folder": folder, "backups": [], "local": []}
    for b in backups:
        map_id, ts = b.get("mapId"), b.get("timestamp")
        entry = {"map_id": map_id, "timestamp": ts, "cloud_md5": b.get("mapMd5")}
        try:
            data = cloud.download(b["mapUrl"])
            name = f"cloud_{map_id}_{ts}.json"
            with open(os.path.join(folder, name), "wb") as fh:
                fh.write(data)
            entry.update(file=name, size=len(data), md5=hashlib.md5(data).hexdigest())
            entry["md5_matches"] = entry["md5"].lower() == str(b.get("mapMd5", "")).lower()
            try:
                parsed = json.loads(data)
                entry["keys"] = sorted(parsed) if isinstance(parsed, dict) else type(parsed).__name__
            except ValueError:
                entry["keys"] = f"not JSON, starts {data[:16]!r}"
            if b.get("snapshotUrl"):
                snap = cloud.download(b["snapshotUrl"])
                ext = "png" if snap[:4] == b"\x89PNG" else "jpg" if snap[:2] == b"\xff\xd8" else "bin"
                with open(os.path.join(folder, f"cloud_{map_id}_{ts}_snapshot.{ext}"), "wb") as fh:
                    fh.write(snap)
        except (CloudError, requests.RequestException, OSError, KeyError) as exc:
            entry["error"] = str(exc)
        out["backups"].append(entry)
    if local_reads:
        for map_id in sorted({b.get("mapId") for b in backups if b.get("mapId") is not None}):
            try:
                local = client.send("getMapData", {"map_id": map_id})["result"]
                name = f"local_{map_id}_{stamp}.json"
                with open(os.path.join(folder, name), "w") as fh:
                    json.dump(local, fh)
                out["local"].append({"map_id": map_id, "file": name, "keys": sorted(local)})
            except Exception as exc:
                out["local"].append({"map_id": map_id, "error": str(exc)})
    return out


def pick_thing(things: list[dict], device_id: str | None, mac: str | None) -> dict | None:
    """The cloud device that is this robot: by device id, then MAC, then the only robot."""
    norm = lambda s: (s or "").replace(":", "").replace("-", "").upper()
    for t in things:
        if device_id and device_id in (t.get("thingName"), t.get("deviceId")):
            return t
    for t in things:
        if mac and norm(t.get("mac")) == norm(mac):
            return t
    robots = [t for t in things if "ROBOVAC" in str(t.get("deviceType", "")).upper()]
    return robots[0] if len(robots) == 1 else None
