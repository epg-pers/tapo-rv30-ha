"""Device attestation (DAC) on tls 0 robots: the certificate formats the Tapo app accepts
(base64 of PEM, as firmware 1.3.5 sends; plain PEM; base64 DER), the chain to a pinned TP-Link
device root, and the proof over SharedKey + nonce."""
import base64
import datetime as dt

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from custom_components.tapo_rv30 import tpap as T

NOW = dt.datetime.now(dt.UTC)


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject, issuer, key, signer, ca):
    b = (x509.CertificateBuilder().subject_name(_name(subject)).issuer_name(_name(issuer))
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(NOW - dt.timedelta(days=1)).not_valid_after(NOW + dt.timedelta(days=365))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    return b.sign(signer, hashes.SHA256())


@pytest.fixture
def chain(monkeypatch):
    rk, ik, dk = (ec.generate_private_key(ec.SECP256R1()) for _ in range(3))
    root = _cert("Test Device Root", "Test Device Root", rk, rk, True)
    ica = _cert("Test ICA", "Test Device Root", ik, rk, True)
    dac = _cert("Test DAC", "Test ICA", dk, ik, False)
    pem = lambda c: c.public_bytes(serialization.Encoding.PEM).decode()
    monkeypatch.setattr(T, "_DAC_ROOTS_PEM", (T._ROOT_CA_PEM, pem(root)))
    return {"dac": dac, "ica": ica, "key": dk, "pem": pem}


def _client(tmp_path, shared=b"s" * 16, nonce=b"n" * 32):
    c = T.TapoVacuumClient("192.0.2.1", "u", "p", cache_dir=tmp_path)
    c._shared_key, c._dac_nonce = shared, base64.b64encode(nonce).decode()
    return c


def _share(chain, encode, shared=b"s" * 16, nonce=b"n" * 32, key=None):
    proof = (key or chain["key"]).sign(shared + nonce, ec.ECDSA(hashes.SHA256()))
    return {"dac_ca": encode(chain["dac"]), "dac_ica": encode(chain["ica"]),
            "dac_proof": base64.b64encode(proof).decode()}


B64_PEM = lambda c: base64.b64encode(c.public_bytes(serialization.Encoding.PEM)).decode()
PEM = lambda c: c.public_bytes(serialization.Encoding.PEM).decode()
B64_DER = lambda c: base64.b64encode(c.public_bytes(serialization.Encoding.DER)).decode()


@pytest.mark.parametrize("encode", [B64_PEM, PEM, B64_DER], ids=["base64 PEM (fw 1.3.5)", "PEM", "base64 DER"])
def test_dac_formats_verify(tmp_path, chain, encode):
    _client(tmp_path)._verify_dac_proof(_share(chain, encode))


def test_base64_pem_was_read_as_der_before(chain):
    # What issue #70 hit: the decoded PEM text parsed as DER fails on the "-" (tag 13).
    with pytest.raises(ValueError, match=r"Tag \{ value: 13, constructed: true"):
        x509.load_der_x509_certificate(base64.b64decode(B64_PEM(chain["dac"])))
    assert T._load_cert(B64_PEM(chain["dac"])).subject == chain["dac"].subject


def test_wrong_proof_or_root_is_refused(tmp_path, chain, monkeypatch):
    c = _client(tmp_path)
    with pytest.raises(T.AuthError, match="DAC verification failed"):
        c._verify_dac_proof(_share(chain, B64_PEM, key=ec.generate_private_key(ec.SECP256R1())))
    with pytest.raises(T.AuthError, match="DAC verification failed"):
        c._verify_dac_proof(_share(chain, B64_PEM, nonce=b"x" * 32))      # signed a different nonce
    monkeypatch.setattr(T, "_DAC_ROOTS_PEM", (T._ROOT_CA_PEM,))
    with pytest.raises(T.AuthError, match="TP-Link device root"):
        c._verify_dac_proof(_share(chain, B64_PEM))


def test_both_tplink_device_roots_are_pinned():
    names = {x509.load_pem_x509_certificate(p.encode()).subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
             for p in T._DAC_ROOTS_PEM}
    assert names == {"TP-LINK SYSTEMS DEVICE ROOT CA", "TP-LINK GLOBAL DEVICE ROOT CA"}
