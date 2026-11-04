"""Contratos das rotas públicas de validação e da revogação (Pydantic v2).

Privacidade (LGPD): nenhuma resposta pública expõe documento completo. ``mask_document``
é aplicada na montagem da resposta, mesmo que o banco já guarde o valor mascarado
(defesa em profundidade). O motivo de revogação e o CN do certificado assinante também
nunca são devolvidos nas rotas abertas.
"""

from __future__ import annotations

import re
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Annotated
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

if TYPE_CHECKING:
    from app.repositories.models import CertificateRecord


# ---------------------------------------------------------------------------
# Mascaramento de documentos
# ---------------------------------------------------------------------------
_MASKED_CPF_RE = re.compile(r"\*{3}\.\d{3}\.\d{3}-\*{2}")
_NON_DIGIT_RE = re.compile(r"\D")
_CPF_DIGITS = 11
_CNPJ_DIGITS = 14
_VISIBLE_TAIL = 3
_MAX_DOC_LENGTH = 40


def mask_document(value: str | None) -> str | None:
    """Mascara CPF/CNPJ/identificadores para exibição pública.

    - CPF (``123.456.789-00`` ou ``12345678900``) -> ``***.456.789-**``;
    - CNPJ (14 dígitos) -> ``**.***.678/****-**``;
    - valor já mascarado no padrão de CPF é devolvido como está (idempotente);
    - qualquer outro formato (matrícula etc.) mantém só os 3 últimos caracteres.

    Nunca levanta exceção para entrada textual: documento ilegível vira ``None`` ou asteriscos.
    """
    if value is None:
        return None
    text = value.strip()[:_MAX_DOC_LENGTH]
    if not text:
        return None
    if _MASKED_CPF_RE.fullmatch(text):
        return text

    digits = _NON_DIGIT_RE.sub("", text)
    letters_or_other = re.sub(r"[\d.\-/\s]", "", text)
    if not letters_or_other:  # só dígitos e pontuação de documento
        if len(digits) == _CPF_DIGITS:
            return f"***.{digits[3:6]}.{digits[6:9]}-**"
        if len(digits) == _CNPJ_DIGITS:
            return f"**.***.{digits[5:8]}/****-**"

    if len(text) <= _VISIBLE_TAIL * 2:
        return "*" * len(text)
    return "*" * (len(text) - _VISIBLE_TAIL) + text[-_VISIBLE_TAIL:]


# ---------------------------------------------------------------------------
# Status canônico
# ---------------------------------------------------------------------------
class ValidationStatus(str, Enum):
    VALID = "VALID"
    REVOKED = "REVOKED"
    NOT_FOUND = "NOT_FOUND"
    INVALID_TAMPERED = "INVALID_TAMPERED"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"


# ---------------------------------------------------------------------------
# Respostas
# ---------------------------------------------------------------------------
class PublicCertificate(BaseModel):
    """Metadados públicos do certificado (sem dados sensíveis)."""

    cert_uuid: UUID
    recipient_name: str
    recipient_doc: str | None = Field(
        default=None, description="Documento do titular SEMPRE mascarado (ex.: ***.456.789-**)."
    )
    role: str
    event_name: str
    event_date: str | None = None
    workload_hours: float | None = None
    issued_at: datetime
    file_sha256: str = Field(description="SHA-256 (hex) do PDF assinado original.")
    signer_fingerprint: str | None = Field(
        default=None, description="SHA-256 do certificado X.509 que assinou o PDF."
    )
    revoked: bool
    revoked_at: datetime | None = None

    @classmethod
    def from_record(cls, record: "CertificateRecord") -> "PublicCertificate":
        return cls(
            cert_uuid=record.id,
            recipient_name=record.participant_name,
            recipient_doc=mask_document(record.recipient_doc),
            role=record.role,
            event_name=record.event_name,
            event_date=record.event_date_label,
            workload_hours=float(record.workload_hours) if record.workload_hours is not None else None,
            issued_at=record.issued_at,
            file_sha256=record.pdf_sha256,
            signer_fingerprint=record.signer_fingerprint,
            revoked=record.is_revoked,
            revoked_at=record.revoked_at,
        )


class DownloadLink(BaseModel):
    """URL pré-assinada temporária para baixar a via original assinada."""

    url: str
    expires_in_seconds: int
    expires_at: datetime


class CryptoReport(BaseModel):
    """Relatório criptográfico da perícia de um arquivo enviado."""

    signature_count: int = Field(description="Assinaturas digitais encontradas no PDF.")
    intact: bool | None = Field(
        default=None, description="Nenhum byte assinado foi alterado (todas as assinaturas)."
    )
    valid: bool | None = Field(default=None, description="Assinaturas criptograficamente válidas.")
    trusted: bool | None = Field(
        default=None, description="Assinado pelo certificado/cadeia desta plataforma."
    )
    covers_entire_file: bool | None = Field(
        default=None, description="A assinatura cobre o arquivo inteiro (sem bytes após ela)."
    )
    hash_matches_record: bool = Field(
        description="O SHA-256 do arquivo consta entre os certificados emitidos."
    )
    signer_matches_record: bool | None = Field(
        default=None, description="O assinante é o mesmo registrado na emissão."
    )
    signer_fingerprint: str | None = None
    evaluated_at: datetime | None = Field(
        default=None,
        description="Momento usado na validação do certificado do assinante (data da emissão registrada).",
    )
    summary: str | None = Field(default=None, description="Resumo técnico do validador (pyHanko).")
    findings: list[str] = Field(default_factory=list, description="Achados em linguagem clara.")


class ValidationResponse(BaseModel):
    """Campos comuns às duas rotas de validação."""

    model_config = ConfigDict(use_enum_values=False)

    status: ValidationStatus
    message: str
    verified_at: datetime
    certificate: PublicCertificate | None = None


class CodeValidationResponse(ValidationResponse):
    """Resposta de ``GET /validate/{cert_uuid}``."""

    download: DownloadLink | None = None


class FileValidationResponse(ValidationResponse):
    """Resposta de ``POST /validate/file``."""

    file_sha256: str
    file_size_bytes: int
    crypto: CryptoReport


# ---------------------------------------------------------------------------
# Revogação (rota administrativa)
# ---------------------------------------------------------------------------
_REASON_FORBIDDEN_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")

RevocationReason = Annotated[str, StringConstraints(strip_whitespace=True, min_length=3, max_length=500)]


class RevokeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: RevocationReason = Field(
        description="Motivo da revogação (texto livre; não é exibido nas rotas públicas)."
    )

    def sanitized_reason(self) -> str:
        return _REASON_FORBIDDEN_RE.sub("", self.reason).strip()


class RevokeResponse(BaseModel):
    cert_uuid: UUID
    status: str = "revoked"
    revoked_at: datetime
