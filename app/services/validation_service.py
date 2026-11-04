"""Validação pública de certificados: por código (QR Code) e por perícia do arquivo enviado.

Rota por código: consulta o banco, informa se o certificado está ativo ou revogado e, se ativo,
gera uma URL pré-assinada temporária para baixar a via original.

Rota por arquivo: três camadas combinadas, tudo em RAM:
    1. SHA-256 exato dos bytes enviados, cruzado com o banco;
    2. perícia criptográfica PAdES (integridade, validade e confiança da assinatura);
    3. veredito anti-fraude (``decide_file_verdict``).

Auditoria das consultas públicas é "best effort": uma falha ao gravar o log é registrada em
ERROR, mas não impede o cidadão de ver o resultado da validação (rota de leitura). Já a
revogação grava o certificado e a auditoria na mesma transação.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
from collections.abc import Sequence
from datetime import datetime, timedelta, timezone
from typing import Protocol
from uuid import UUID

from app.crypto.inspector import PdfInspection, PdfSignatureInspector, SignatureFinding
from app.repositories.errors import RepositoryError
from app.repositories.models import (
    AuditContext,
    AuditEvent,
    CertificateRecord,
    RevocationResult,
)
from app.schemas.validation import (
    CodeValidationResponse,
    CryptoReport,
    DownloadLink,
    FileValidationResponse,
    PublicCertificate,
    ValidationStatus,
)

logger = logging.getLogger(__name__)

_CANONICAL_UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)

MESSAGES: dict[ValidationStatus, str] = {
    ValidationStatus.VALID: "Certificado autêntico e válido.",
    ValidationStatus.REVOKED: "Este certificado foi emitido, mas foi REVOGADO e não é mais válido.",
    ValidationStatus.NOT_FOUND: "Nenhum certificado foi encontrado para este código.",
    ValidationStatus.INVALID_TAMPERED: (
        "O arquivo foi modificado após a assinatura ou não corresponde a nenhum certificado emitido."
    ),
    ValidationStatus.INVALID_SIGNATURE: (
        "O arquivo não possui uma assinatura digital válida e confiável desta plataforma."
    ),
}


class ValidationUnavailableError(Exception):
    """A validação não pôde ser concluída (tempo excedido). Não é um veredito: tente novamente."""


class ValidationRepositoryPort(Protocol):
    async def get_by_id(self, cert_id: UUID) -> CertificateRecord | None: ...

    async def get_by_sha256(self, file_sha256: str) -> CertificateRecord | None: ...

    async def record_audit(self, events: Sequence[AuditEvent], context: AuditContext) -> None: ...

    async def revoke(self, cert_id: UUID, reason: str, context: AuditContext) -> RevocationResult: ...


class PresignerPort(Protocol):
    def presign_get(
        self, key: str, expires_in: int | None = None, download_filename: str | None = None
    ) -> str: ...


def parse_cert_uuid(raw: str) -> UUID | None:
    """Aceita apenas UUID v4 na forma canônica (36 caracteres); o resto não existe no banco."""
    if not _CANONICAL_UUID_RE.fullmatch(raw):
        return None
    value = UUID(raw)
    return value if value.version == 4 else None


# ---------------------------------------------------------------------------
# Veredito combinado anti-fraude (função pura)
# ---------------------------------------------------------------------------
def decide_file_verdict(
    inspection: PdfInspection, record: CertificateRecord | None
) -> tuple[ValidationStatus, list[str]]:
    """Combina perícia criptográfica e registro do banco em um status canônico.

    Ordem de decisão:
      1. ilegível / sem assinatura / assinatura não verificável      -> INVALID_SIGNATURE
      2. algum byte assinado foi alterado (``intact=False``)         -> INVALID_TAMPERED
      3. assinatura inválida ou de assinante não confiável           -> INVALID_SIGNATURE
      4. assinatura boa, mas SHA-256 desconhecido (bytes diferentes
         do PDF emitido, ex.: conteúdo anexado após a assinatura)    -> INVALID_TAMPERED
      5. assinante diferente do registrado na emissão                -> INVALID_SIGNATURE
      6. registro revogado                                           -> REVOKED
      7. caso contrário                                              -> VALID
    """
    if not inspection.readable:
        return ValidationStatus.INVALID_SIGNATURE, [
            inspection.problem or "O arquivo não pôde ser lido como PDF assinado."
        ]
    signatures = inspection.signatures
    if not signatures:
        return ValidationStatus.INVALID_SIGNATURE, [
            inspection.problem or "Nenhuma assinatura digital foi encontrada no arquivo."
        ]

    findings: list[str] = []
    if any(sig.error for sig in signatures):
        return ValidationStatus.INVALID_SIGNATURE, [
            "A assinatura digital está corrompida ou não pôde ser verificada."
        ]
    if any(sig.intact is not True for sig in signatures):
        return ValidationStatus.INVALID_TAMPERED, [
            "O conteúdo do documento foi alterado após a assinatura (integridade quebrada)."
        ]
    if any(sig.valid is not True for sig in signatures):
        return ValidationStatus.INVALID_SIGNATURE, ["A assinatura digital é criptograficamente inválida."]
    if any(sig.trusted is not True for sig in signatures):
        return ValidationStatus.INVALID_SIGNATURE, [
            "A assinatura não pertence ao certificado de assinatura reconhecido por esta plataforma."
        ]

    if any(sig.covers_entire_file is False for sig in signatures):
        findings.append("Existe conteúdo adicional após a assinatura digital.")

    if record is None:
        findings.insert(
            0,
            "A assinatura é íntegra, mas o SHA-256 do arquivo não corresponde a nenhum certificado "
            "emitido: o arquivo difere do original.",
        )
        return ValidationStatus.INVALID_TAMPERED, findings

    pinned = record.signer_fingerprint
    if pinned is not None and any(sig.signer_fingerprint != pinned for sig in signatures):
        return ValidationStatus.INVALID_SIGNATURE, [
            "O assinante do arquivo não é o mesmo registrado na emissão deste certificado."
        ]

    if record.is_revoked:
        return ValidationStatus.REVOKED, [
            "Assinatura íntegra e confiável, porém o certificado consta como revogado."
        ]

    findings.insert(0, "Assinatura digital íntegra, válida e confiável; arquivo idêntico ao emitido.")
    return ValidationStatus.VALID, findings


def _aggregate(signatures: Sequence[SignatureFinding], attribute: str) -> bool | None:
    """``True`` se todas as assinaturas têm o atributo verdadeiro; ``None`` se desconhecido."""
    if not signatures:
        return None
    values = [getattr(sig, attribute) for sig in signatures]
    if any(value is None for value in values):
        return None
    return all(values)


def build_crypto_report(
    inspection: PdfInspection, record: CertificateRecord | None, findings: list[str]
) -> CryptoReport:
    signatures = inspection.signatures
    signer_match: bool | None = None
    if record is not None and record.signer_fingerprint is not None and signatures:
        signer_match = all(sig.signer_fingerprint == record.signer_fingerprint for sig in signatures)
    return CryptoReport(
        signature_count=len(signatures),
        intact=_aggregate(signatures, "intact"),
        valid=_aggregate(signatures, "valid"),
        trusted=_aggregate(signatures, "trusted"),
        covers_entire_file=_aggregate(signatures, "covers_entire_file"),
        hash_matches_record=record is not None,
        signer_matches_record=signer_match,
        signer_fingerprint=signatures[0].signer_fingerprint if signatures else None,
        evaluated_at=inspection.evaluated_at,
        summary=signatures[0].summary if signatures else None,
        findings=findings,
    )


def _outcome_for(status: ValidationStatus) -> str:
    if status is ValidationStatus.VALID:
        return "success"
    if status is ValidationStatus.NOT_FOUND:
        return "not_found"
    return "invalid"


# ---------------------------------------------------------------------------
# Serviço
# ---------------------------------------------------------------------------
class ValidationService:
    def __init__(
        self,
        repository: ValidationRepositoryPort,
        storage: PresignerPort,
        inspector: PdfSignatureInspector,
        *,
        presign_ttl_seconds: int = 900,
        concurrency: int = 4,
        timeout_seconds: float = 20.0,
    ) -> None:
        self._repository = repository
        self._storage = storage
        self._inspector = inspector
        self._presign_ttl = presign_ttl_seconds
        self._semaphore = asyncio.Semaphore(concurrency)
        self._timeout = timeout_seconds

    # ------------------------------------------------------------------
    # Rota 1: por código / QR Code
    # ------------------------------------------------------------------
    async def validate_code(self, raw_code: str, context: AuditContext) -> CodeValidationResponse:
        verified_at = datetime.now(timezone.utc)
        cert_id = parse_cert_uuid(raw_code)
        if cert_id is None:
            # Código malformado: não consulta nem audita (evita encher o log com lixo).
            return self._code_response(ValidationStatus.NOT_FOUND, verified_at)

        record = await self._repository.get_by_id(cert_id)
        if record is None:
            await self._audit_safely(
                [
                    AuditEvent(
                        "validate_code",
                        "not_found",
                        None,
                        {"status": ValidationStatus.NOT_FOUND.value, "cert_uuid": str(cert_id)},
                    )
                ],
                context,
            )
            return self._code_response(ValidationStatus.NOT_FOUND, verified_at)

        certificate = PublicCertificate.from_record(record)
        if record.is_revoked:
            status = ValidationStatus.REVOKED
            download = None
            events = [
                AuditEvent(
                    "validate_code", "invalid", record.id,
                    {"status": status.value, "cert_uuid": str(record.id)},
                )
            ]
        else:
            status = ValidationStatus.VALID
            download = self._presign(record, verified_at)
            events = [
                AuditEvent(
                    "validate_code", "success", record.id,
                    {"status": status.value, "cert_uuid": str(record.id)},
                )
            ]
            if download is not None:
                events.append(
                    AuditEvent(
                        "presigned_url", "success", record.id,
                        {"cert_uuid": str(record.id), "expires_in_seconds": self._presign_ttl},
                    )
                )
        await self._audit_safely(events, context)
        return self._code_response(status, verified_at, certificate=certificate, download=download)

    # ------------------------------------------------------------------
    # Rota 2: perícia do arquivo enviado
    # ------------------------------------------------------------------
    async def validate_file(self, data: bytes, context: AuditContext) -> FileValidationResponse:
        verified_at = datetime.now(timezone.utc)
        file_sha256 = hashlib.sha256(data).hexdigest()
        record = await self._repository.get_by_sha256(file_sha256)

        # A assinatura é avaliada na data de emissão registrada: um A1 vencido depois não
        # invalida certificados que eram legítimos quando foram assinados.
        inspection = await self._inspect(data, record.signed_at if record else None)
        status, findings = decide_file_verdict(inspection, record)
        crypto = build_crypto_report(inspection, record, findings)

        await self._audit_safely(
            [
                AuditEvent(
                    "validate_file",
                    _outcome_for(status),
                    record.id if record else None,
                    {
                        "status": status.value,
                        "file_sha256": file_sha256,
                        "file_size_bytes": len(data),
                        "signature_count": crypto.signature_count,
                        "intact": crypto.intact,
                        "valid": crypto.valid,
                        "trusted": crypto.trusted,
                        "hash_matches_record": crypto.hash_matches_record,
                    },
                )
            ],
            context,
        )
        expose = record is not None and status in (ValidationStatus.VALID, ValidationStatus.REVOKED)
        return FileValidationResponse(
            status=status,
            message=MESSAGES[status],
            verified_at=verified_at,
            certificate=PublicCertificate.from_record(record) if expose and record else None,
            file_sha256=file_sha256,
            file_size_bytes=len(data),
            crypto=crypto,
        )

    # ------------------------------------------------------------------
    # Revogação (rota administrativa)
    # ------------------------------------------------------------------
    async def revoke(self, cert_id: UUID, reason: str, context: AuditContext) -> RevocationResult:
        return await self._repository.revoke(cert_id, reason, context)

    # ------------------------------------------------------------------
    # Internos
    # ------------------------------------------------------------------
    async def _inspect(self, data: bytes, moment: datetime | None) -> PdfInspection:
        async with self._semaphore:
            try:
                return await asyncio.wait_for(
                    self._inspector.inspect(data, moment=moment), timeout=self._timeout
                )
            except asyncio.TimeoutError as exc:
                logger.error("Perícia do PDF excedeu %.1fs", self._timeout)
                raise ValidationUnavailableError("Tempo excedido na verificação do arquivo") from exc

    def _presign(self, record: CertificateRecord, now: datetime) -> DownloadLink | None:
        try:
            url = self._storage.presign_get(
                record.storage_key,
                expires_in=self._presign_ttl,
                download_filename=f"certificado-{record.id}.pdf",
            )
        except Exception as exc:  # noqa: BLE001 - o download é opcional; a validação segue sem ele
            logger.error("Falha ao gerar URL pré-assinada (cert=%s): %s", record.id, type(exc).__name__)
            return None
        return DownloadLink(
            url=url,
            expires_in_seconds=self._presign_ttl,
            expires_at=now + timedelta(seconds=self._presign_ttl),
        )

    async def _audit_safely(self, events: Sequence[AuditEvent], context: AuditContext) -> None:
        try:
            await self._repository.record_audit(events, context)
        except RepositoryError as exc:
            logger.error(
                "Auditoria NÃO gravada (%s): %s",
                ",".join(event.action for event in events),
                type(exc).__name__,
            )

    @staticmethod
    def _code_response(
        status: ValidationStatus,
        verified_at: datetime,
        *,
        certificate: PublicCertificate | None = None,
        download: DownloadLink | None = None,
    ) -> CodeValidationResponse:
        return CodeValidationResponse(
            status=status,
            message=MESSAGES[status],
            verified_at=verified_at,
            certificate=certificate,
            download=download,
        )
