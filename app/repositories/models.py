"""Modelos de dados trocados entre o orquestrador e o repositório."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal
from typing import Any
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
