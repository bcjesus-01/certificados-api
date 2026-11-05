"""Máscara LGPD, veredito anti-fraude e serviço de validação (com fakes: sem banco, bucket ou pyHanko)."""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any
from uuid import UUID, uuid4

import pytest

from app.crypto.inspector import PdfInspection, SignatureFinding
from app.repositories.errors import RepositoryUnavailableError
from app.repositories.models import AuditContext, AuditEvent, CertificateRecord, RevocationResult
from app.schemas.validation import ValidationStatus as S
from app.schemas.validation import mask_document
from app.services.validation_service import (
    MESSAGES,
    ValidationService,
    ValidationUnavailableError,
    decide_file_verdict,
    parse_cert_uuid,
)

CERT_ID = uuid4()
NOW = datetime(2026, 11, 4, 20, 0, tzinfo=timezone.utc)
FINGERPRINT = ":".join(["AB"] * 32)
CTX = AuditContext(client_ip_hash="h", user_agent="ua")


# --------------------------------------------------------------------------- mask_document
@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("123.456.789-00", "***.456.789-**"),
        ("12345678900", "***.456.789-**"),
        (" 123.456.789-00 ", "***.456.789-**"),
        ("***.456.789-**", "***.456.789-**"),
        ("12.345.678/0001-95", "**.***.678/****-**"),
        ("12345678000195", "**.***.678/****-**"),
        ("Mat. 20230012345", "*" * 13 + "345"),
        ("ab", "**"),
        ("", None),
        ("   ", None),
        (None, None),
    ],
)
def test_mask_document(raw: str | None, expected: str | None) -> None:
    assert mask_document(raw) == expected


def test_mask_document_never_leaks_and_is_bounded() -> None:
    masked = mask_document("123.456.789-09") or ""
    assert "123" not in masked and "09" not in masked
    assert len(mask_document("x" * 500) or "") <= 40


# --------------------------------------------------------------------------- parse_cert_uuid
def test_parse_cert_uuid() -> None:
    value = uuid4()
    assert parse_cert_uuid(str(value)) == value
    assert parse_cert_uuid(str(value).upper()) == value
    for bad in (value.hex, "6ba7b810-9dad-11d1-80b4-00c04fd430c8", "../../etc/passwd", "", "{" + str(value) + "}"):
        assert parse_cert_uuid(bad) is None


# --------------------------------------------------------------------------- fixtures
def make_record(status: str = "valid", fingerprint: str | None = FINGERPRINT, sha: str = "a" * 64) -> CertificateRecord:
    return CertificateRecord(
        id=CERT_ID, participant_name="João da Silva", recipient_doc="***.456.789-**", role="Participante",
        event_name="Evento", event_date_label="10 de novembro de 2026", workload_hours=Decimal("12.50"),
        issued_at=NOW, signed_at=NOW + timedelta(seconds=1), pdf_sha256=sha, storage_bucket="b",
        storage_key="certificates/2026/x.pdf", signer_fingerprint=fingerprint, status=status,
        revoked_at=NOW if status == "revoked" else None,
    )


def sig(**overrides: Any) -> SignatureFinding:
    base: dict[str, Any] = {
        "intact": True, "valid": True, "trusted": True, "covers_entire_file": True,
        "signer_fingerprint": FINGERPRINT, "summary": "INTACT:UNTOUCHED,TRUSTED",
    }
    return SignatureFinding(**{**base, **overrides})


def insp(*sigs: SignatureFinding, readable: bool = True, problem: str | None = None) -> PdfInspection:
    return PdfInspection(readable=readable, signatures=tuple(sigs), problem=problem)


# --------------------------------------------------------------------------- veredito
@pytest.mark.parametrize(
    ("inspection", "record", "expected"),
    [
        (insp(sig()), make_record(), S.VALID),
        (insp(sig()), make_record("revoked"), S.REVOKED),
        (insp(sig(intact=False)), make_record(), S.INVALID_TAMPERED),
        (insp(sig(intact=False)), None, S.INVALID_TAMPERED),
        (insp(sig()), None, S.INVALID_TAMPERED),
        (insp(sig(covers_entire_file=False)), None, S.INVALID_TAMPERED),
        (insp(problem="Nenhuma"), None, S.INVALID_SIGNATURE),
        (insp(readable=False, problem="x"), None, S.INVALID_SIGNATURE),
        (insp(sig(valid=False)), make_record(), S.INVALID_SIGNATURE),
        (insp(sig(trusted=False)), make_record(), S.INVALID_SIGNATURE),
        (insp(SignatureFinding(error="x")), make_record(), S.INVALID_SIGNATURE),
        (insp(sig(signer_fingerprint="CD:" * 31 + "CD")), make_record(), S.INVALID_SIGNATURE),
        (insp(sig()), make_record(fingerprint=None), S.VALID),
        (insp(sig(), sig(intact=False)), make_record(), S.INVALID_TAMPERED),
        (insp(sig(intact=False)), make_record("revoked"), S.INVALID_TAMPERED),
    ],
)
def test_decide_file_verdict(inspection: PdfInspection, record: CertificateRecord | None, expected: S) -> None:
    assert decide_file_verdict(inspection, record)[0] is expected


@pytest.mark.parametrize("unknown", [{"intact": None}, {"valid": None}, {"trusted": None}])
def test_unknown_crypto_state_never_becomes_valid(unknown: dict[str, Any]) -> None:
    assert decide_file_verdict(insp(sig(**unknown)), make_record())[0] is not S.VALID


def test_messages_cover_every_status() -> None:
    assert set(MESSAGES) == set(S)


# --------------------------------------------------------------------------- fakes
class FakeRepo:
    def __init__(self, record: CertificateRecord | None = None, *, fail_audit: bool = False, fail_read: bool = False) -> None:
        self.record, self.fail_audit, self.fail_read = record, fail_audit, fail_read
        self.audits: list[list[AuditEvent]] = []
        self.get_by_id_calls = 0

    async def get_by_id(self, cert_id: UUID) -> CertificateRecord | None:
        self.get_by_id_calls += 1
        if self.fail_read:
            raise RepositoryUnavailableError("db")
        return self.record if self.record and self.record.id == cert_id else None

    async def get_by_sha256(self, file_sha256: str) -> CertificateRecord | None:
        if self.fail_read:
            raise RepositoryUnavailableError("db")
        return self.record if self.record and self.record.pdf_sha256 == file_sha256 else None

    async def record_audit(self, events: Any, context: AuditContext) -> None:
        if self.fail_audit:
            raise RepositoryUnavailableError("db")
        self.audits.append(list(events))

    async def revoke(self, cert_id: UUID, reason: str, context: AuditContext) -> RevocationResult:
        return RevocationResult("revoked", NOW)


class FakeStorage:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.calls: list[tuple[str, int | None, str | None]] = []

    def presign_get(self, key: str, expires_in: int | None = None, download_filename: str | None = None) -> str:
        if self.fail:
            raise RuntimeError("boto")
        self.calls.append((key, expires_in, download_filename))
        return f"https://s3/{key}?sig=1"


class FakeInspector:
    def __init__(self, result: PdfInspection | None = None, delay: float = 0.0) -> None:
        self.result, self.delay = result, delay
        self.moments: list[datetime | None] = []

    async def inspect(self, pdf: bytes, *, moment: datetime | None = None) -> PdfInspection:
        self.moments.append(moment)
        if self.delay:
            await asyncio.sleep(self.delay)
        assert self.result is not None
        return self.result


def run(coro: Any) -> Any:
    return asyncio.run(coro)


# --------------------------------------------------------------------------- por código
def test_code_valid_has_presigned_url_masked_doc_and_two_audit_rows() -> None:
    repo, storage = FakeRepo(make_record()), FakeStorage()
    result = run(ValidationService(repo, storage, FakeInspector(), presign_ttl_seconds=900).validate_code(str(CERT_ID), CTX))
    assert result.status is S.VALID and result.certificate is not None
    assert result.download and result.download.expires_in_seconds == 900
    assert storage.calls == [("certificates/2026/x.pdf", 900, f"certificado-{CERT_ID}.pdf")]
    assert result.certificate.recipient_doc == "***.456.789-**" and result.certificate.workload_hours == 12.5
    assert [e.action for e in repo.audits[0]] == ["validate_code", "presigned_url"]
    body = json.dumps(result.model_dump(mode="json"))
    assert "revoked_reason" not in body and "subject" not in body


def test_code_not_found_and_malformed() -> None:
    repo = FakeRepo(make_record())
    service = ValidationService(repo, FakeStorage(), FakeInspector())
    missing = run(service.validate_code(str(uuid4()), CTX))
    assert missing.status is S.NOT_FOUND and repo.audits[-1][0].outcome == "not_found"
    calls, audits = repo.get_by_id_calls, len(repo.audits)
    assert run(service.validate_code("não-é-uuid", CTX)).status is S.NOT_FOUND
    assert repo.get_by_id_calls == calls and len(repo.audits) == audits  # sem tocar no banco nem auditar


def test_code_revoked_has_no_download() -> None:
    repo, storage = FakeRepo(make_record("revoked")), FakeStorage()
    result = run(ValidationService(repo, storage, FakeInspector()).validate_code(str(CERT_ID), CTX))
    assert result.status is S.REVOKED and result.download is None and result.certificate and result.certificate.revoked
    assert not storage.calls and len(repo.audits[0]) == 1 and repo.audits[0][0].outcome == "invalid"


def test_code_survives_presign_and_audit_failures() -> None:
    result = run(ValidationService(FakeRepo(make_record()), FakeStorage(fail=True), FakeInspector()).validate_code(str(CERT_ID), CTX))
    assert result.status is S.VALID and result.download is None
    result = run(ValidationService(FakeRepo(make_record(), fail_audit=True), FakeStorage(), FakeInspector()).validate_code(str(CERT_ID), CTX))
    assert result.status is S.VALID


def test_code_database_down_propagates_for_503() -> None:
    service = ValidationService(FakeRepo(make_record(), fail_read=True), FakeStorage(), FakeInspector())
    with pytest.raises(RepositoryUnavailableError):
        run(service.validate_code(str(CERT_ID), CTX))


# --------------------------------------------------------------------------- por arquivo
DATA = b"%PDF-1.7 conteudo"
DATA_SHA = hashlib.sha256(DATA).hexdigest()


def test_file_valid_is_evaluated_at_issue_time_and_audited_with_hash_only() -> None:
    record = make_record(sha=DATA_SHA)
    repo, inspector = FakeRepo(record), FakeInspector(insp(sig()))
    result = run(ValidationService(repo, FakeStorage(), inspector).validate_file(DATA, CTX))
    assert result.status is S.VALID and result.crypto.intact and result.crypto.trusted and result.crypto.valid
    assert result.crypto.hash_matches_record and result.crypto.signer_matches_record
    assert result.file_sha256 == DATA_SHA and result.file_size_bytes == len(DATA)
    assert inspector.moments == [record.signed_at]
    event = repo.audits[0][0]
    assert event.action == "validate_file" and event.outcome == "success" and event.certificate_id == CERT_ID
    assert event.details["file_sha256"] == DATA_SHA and "filename" not in event.details


def test_file_tampered_exposes_no_holder_data() -> None:
    repo, inspector = FakeRepo(make_record(sha=DATA_SHA)), FakeInspector(insp(sig(intact=False)))
    result = run(ValidationService(repo, FakeStorage(), inspector).validate_file(b"%PDF-1.7 adulterado", CTX))
    assert result.status is S.INVALID_TAMPERED and result.certificate is None
    assert result.crypto.intact is False and not result.crypto.hash_matches_record and inspector.moments == [None]
    assert repo.audits[-1][0].outcome == "invalid" and repo.audits[-1][0].certificate_id is None


def test_file_without_signature_and_revoked() -> None:
    unsigned = FakeInspector(insp(problem="Nenhuma assinatura digital encontrada"))
    result = run(ValidationService(FakeRepo(), FakeStorage(), unsigned).validate_file(b"%PDF-1.4 sem assinatura", CTX))
    assert result.status is S.INVALID_SIGNATURE and result.crypto.signature_count == 0 and result.crypto.intact is None

    revoked = replace(make_record("revoked"), pdf_sha256=DATA_SHA)
    result = run(ValidationService(FakeRepo(revoked), FakeStorage(), FakeInspector(insp(sig()))).validate_file(DATA, CTX))
    assert result.status is S.REVOKED and result.certificate and result.certificate.revoked


def test_file_slow_inspection_times_out_as_unavailable() -> None:
    service = ValidationService(FakeRepo(), FakeStorage(), FakeInspector(insp(sig()), delay=0.5), timeout_seconds=0.05)
    with pytest.raises(ValidationUnavailableError):
        run(service.validate_file(DATA, CTX))


def test_file_inspections_are_concurrency_limited() -> None:
    state = {"running": 0, "peak": 0}

    class Slow:
        async def inspect(self, pdf: bytes, *, moment: datetime | None = None) -> PdfInspection:
            state["running"] += 1
            state["peak"] = max(state["peak"], state["running"])
            await asyncio.sleep(0.05)
            state["running"] -= 1
            return insp(sig())

    service = ValidationService(FakeRepo(make_record(sha=DATA_SHA)), FakeStorage(), Slow(), concurrency=2)

    async def burst() -> None:
        await asyncio.gather(*(service.validate_file(DATA, CTX) for _ in range(6)))

    run(burst())
    assert state["peak"] == 2
