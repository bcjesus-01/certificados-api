"""Integração REAL com o pyHanko: assina em memória com certificado efêmero e faz a perícia."""

from __future__ import annotations

import asyncio
import io
import re

import pytest

pytest.importorskip("pyhanko")
pytest.importorskip("pyhanko_certvalidator")

from generate_dev_cert import generate_dev_pkcs12  # noqa: E402
from reportlab.lib.pagesizes import A4  # noqa: E402
from reportlab.pdfgen import canvas  # noqa: E402

from app.crypto.credentials import SigningCredentials, load_signing_credentials  # noqa: E402
from app.crypto.inspector import PdfInspection, PyHankoPdfInspector  # noqa: E402
from app.crypto.pades import sign_pdf_pades  # noqa: E402
from app.schemas.validation import ValidationStatus  # noqa: E402
from app.services.validation_service import decide_file_verdict  # noqa: E402

_BYTE_RANGE = re.compile(rb"/ByteRange\s*\[\s*0\s+(\d+)\s+\d+\s+\d+\s*\]")


@pytest.fixture(scope="module")
def credentials() -> SigningCredentials:
    dev = generate_dev_pkcs12()
    return load_signing_credentials(dev.pfx_base64, dev.password)


def _unsigned_pdf() -> bytes:
    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)
    pdf.drawString(72, 760, "Certificado de teste")
    pdf.showPage()
    pdf.save()
    return buffer.getvalue()


@pytest.fixture(scope="module")
def signed(credentials: SigningCredentials) -> bytes:
    return asyncio.run(sign_pdf_pades(_unsigned_pdf(), credentials)).getvalue()


def _inspect(credentials: SigningCredentials, data: bytes) -> PdfInspection:
    return asyncio.run(PyHankoPdfInspector(credentials).inspect(data))


def test_authentic_pdf_is_intact_valid_trusted_and_covers_whole_file(credentials: SigningCredentials, signed: bytes) -> None:
    result = _inspect(credentials, signed)
    assert result.readable and len(result.signatures) == 1
    finding = result.signatures[0]
    assert finding.intact is True and finding.valid is True and finding.trusted is True
    assert finding.covers_entire_file is True
    assert finding.signer_fingerprint == credentials.info.sha256_fingerprint


def test_one_flipped_byte_inside_signed_range_breaks_integrity(credentials: SigningCredentials, signed: bytes) -> None:
    match = _BYTE_RANGE.search(signed)
    assert match is not None
    signed_end = int(match.group(1))
    index = signed.find(b"ReportLab", 0, signed_end)
    assert index != -1
    altered = bytearray(signed)
    altered[index + len(b"ReportLab") - 1] ^= 0x01
    finding = _inspect(credentials, bytes(altered)).signatures[0]
    assert finding.intact is False
    assert decide_file_verdict(_inspect(credentials, bytes(altered)), None)[0] is ValidationStatus.INVALID_TAMPERED


def test_appended_bytes_keep_signature_but_cover_less_than_the_file(credentials: SigningCredentials, signed: bytes) -> None:
    inspection = _inspect(credentials, signed + b"\n% anexado depois da assinatura\n")
    finding = inspection.signatures[0]
    assert finding.intact is True and finding.valid is True and finding.trusted is True
    assert finding.covers_entire_file is False
    # Sem registro com este hash no banco, o veredito é adulteração.
    assert decide_file_verdict(inspection, None)[0] is ValidationStatus.INVALID_TAMPERED


def test_unsigned_pdf_has_no_signatures(credentials: SigningCredentials) -> None:
    inspection = _inspect(credentials, _unsigned_pdf())
    assert inspection.readable and inspection.signatures == ()
    assert decide_file_verdict(inspection, None)[0] is ValidationStatus.INVALID_SIGNATURE


def test_garbage_is_unreadable_not_a_crash(credentials: SigningCredentials) -> None:
    inspection = _inspect(credentials, b"%PDF-1.7 \x00\x01 lixo sem estrutura")
    assert decide_file_verdict(inspection, None)[0] is ValidationStatus.INVALID_SIGNATURE
