"""TP-Link cloud helpers (no network)."""
import base64
import hashlib
import hmac

from custom_components.tapo_rv30 import cloud


def test_signed_headers_match_app_scheme():
    body = b'{"a":1}'
    h = cloud._signed_headers("/api/v2/account/login", body)
    md5 = base64.b64encode(hashlib.md5(body).digest()).decode()
    assert h["Content-MD5"] == md5
    parts = dict(p.split("=", 1) for p in h["X-Authorization"].split(", "))
    assert parts["Timestamp"] == "9999999999" and parts["AccessKey"] == cloud.ACCESS_KEY
    msg = f"{md5}\n9999999999\n{parts['Nonce']}\n/api/v2/account/login".encode()
    assert parts["Signature"] == hmac.new(cloud.SECRET_KEY.encode(), msg, hashlib.sha1).hexdigest()


def test_pick_thing():
    things = [{"thingName": "A", "deviceType": "SMART.TAPOPLUG", "mac": "AA-BB-CC-DD-EE-FF"},
              {"thingName": "B", "deviceType": "SMART.TAPOROBOVAC", "mac": "11-22-33-44-55-66"}]
    assert cloud.pick_thing(things, "A", None)["thingName"] == "A"
    assert cloud.pick_thing(things, None, "11:22:33:44:55:66")["thingName"] == "B"
    assert cloud.pick_thing(things, "zz", None)["thingName"] == "B"
    assert cloud.pick_thing(things + [dict(things[1], thingName="C")], None, None) is None
