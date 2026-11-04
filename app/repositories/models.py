"""Modelos de dados trocados entre o orquestrador e o repositório."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from typing import Any, Literal
from uuid import UUID


@dataclass(frozen=True, slots=True)
class IssuedCertificate:
    """Certificado emitido, pronto para persistir. ``file_sha256`` = hash do PDF ASSINADO."""

    id: UUID
    batch_id: UUID
    recipient_name: str
    recipient_doc: str | None
    role: str
    event_name: str
    event_date_label: str
    workload_hours: Decimal
    issued_at: datetime
    metadata: dict[str, Any]
    file_sha256: str
    storage_bucket: str
    storage_key: str
    signed_at: datetime
    signer_fingerprint: str
    signer_serial: str


@dataclass(frozen=True, slots=True)
class AuditContext:
    """Quem solicitou a emissão (sem dados pessoais em claro: o IP é guardado só como HMAC)."""

    client_ip_hash: str | None = None
    user_agent: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class CertificateRecord:
    """Linha de ``certificates`` usada pelas rotas de validação (nunca contém CPF em claro)."""

    id: UUID
    participant_name: str
    recipient_doc: str | None
    role: str
    event_name: str
    event_date_label: str | None
    workload_hours: Decimal | None
    issued_at: datetime
    signed_at: datetime
    pdf_sha256: str
    storage_bucket: str
    storage_key: str
    signer_fingerprint: str | None
    status: str  # "valid" | "revoked"
    revoked_at: datetime | None

    @property
    def is_revoked(self) -> bool:
        return self.status == "revoked"


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """Evento de auditoria a gravar. ``details`` nunca deve conter dados pessoais."""

    action: str  # validate_code | validate_file | presigned_url | revoked
    outcome: str  # success | not_found | invalid | error
    certificate_id: UUID | None = None
    details: dict[str, Any] = field(default_factory=dict)


RevocationOutcome = Literal["revoked", "not_found", "already_revoked"]


@dataclass(frozen=True, slots=True)
class RevocationResult:
    outcome: RevocationOutcome
    revoked_at: datetime | None = None
