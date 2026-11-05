"""Âncoras de confiança: folha (pinning) + raízes autoassinadas; intermediários à parte."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

pytest.importorskip("asn1crypto")

import app.crypto.credentials as credentials  # noqa: E402


def _issue(common_name: str, issuer: x509.Certificate | None = None, issuer_key: Any = None) -> tuple[x509.Certificate, Any]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer.subject if issuer else name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=100))
        .sign(issuer_key or key, hashes.SHA256())
    )
    return certificate, key


def _der(certificate: x509.Certificate) -> bytes:
    return certificate.public_bytes(serialization.Encoding.DER)


def test_chain_is_split_into_anchors_and_intermediates() -> None:
    root, root_key = _issue("Raiz")
    intermediate, intermediate_key = _issue("Intermediária", root, root_key)
    leaf, _ = _issue("Folha", intermediate, intermediate_key)
    roots, intermediates = credentials._build_trust_material(leaf, [intermediate, root])
    assert [item.dump() for item in roots] == [_der(leaf), _der(root)]
    assert [item.dump() for item in intermediates] == [_der(intermediate)]


def test_self_signed_certificate_is_its_own_anchor() -> None:
    certificate, _ = _issue("Autoassinado")
    roots, intermediates = credentials._build_trust_material(certificate, [])
    assert len(roots) == 1 and intermediates == ()


def test_credentials_fall_back_to_signing_cert_when_no_anchors_given() -> None:
    class FakeSigner:
        signing_cert = "fallback"

    fallback = credentials.SigningCredentials(FakeSigner(), None)  # type: ignore[arg-type]
    assert fallback.trust_roots == ("fallback",) and fallback.intermediates == ()
