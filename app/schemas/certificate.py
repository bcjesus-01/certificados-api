"""Contratos de entrada para a renderização de certificados (Pydantic v2).

Regras de privacidade (LGPD): um CPF informado em claro (11 dígitos, com ou sem
pontuação) é mascarado automaticamente para ``***.456.789-**`` antes de qualquer
uso. Sequências de exatamente 11 dígitos são tratadas como CPF; para matrículas
com 11 dígitos, informe um prefixo (ex.: ``Mat. 20230012345``).
"""

from __future__ import annotations

import json
import re
from datetime import date, datetime, timezone
from decimal import Decimal
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

_MONTHS_PT: tuple[str, ...] = (
    "janeiro", "fevereiro", "março", "abril", "maio", "junho",
    "julho", "agosto", "setembro", "outubro", "novembro", "dezembro",
)
_CPF_RE = re.compile(r"\d{3}\.?\d{3}\.?\d{3}-?\d{2}")
_MAX_EXTRA_METADATA_BYTES = 8 * 1024


# ---------------------------------------------------------------------------
# Utilitários de formatação (pt-BR, sem depender de locale do sistema)
# ---------------------------------------------------------------------------
def mask_cpf(value: str) -> str:
    """``12345678909`` / ``123.456.789-09`` -> ``***.456.789-**``."""
    digits = re.sub(r"\D", "", value)
    if len(digits) != 11:
        raise ValueError("CPF deve ter 11 dígitos")
    return f"***.{digits[3:6]}.{digits[6:9]}-**"


def format_pt_date(value: date) -> str:
    """``date(2026, 11, 4)`` -> ``4 de novembro de 2026``."""
    return f"{value.day} de {_MONTHS_PT[value.month - 1]} de {value.year}"


def format_event_period(start: date, end: date | None = None) -> str:
    """Formata data única ou período (``10 a 14 de novembro de 2026``)."""
    if end is None or end == start:
        return format_pt_date(start)
    if end < start:
        raise ValueError("A data final não pode ser anterior à data inicial")
    if (start.year, start.month) == (end.year, end.month):
        return f"{start.day} a {end.day} de {_MONTHS_PT[end.month - 1]} de {end.year}"
    if start.year == end.year:
        return (
            f"{start.day} de {_MONTHS_PT[start.month - 1]} a "
            f"{end.day} de {_MONTHS_PT[end.month - 1]} de {end.year}"
        )
    return f"{format_pt_date(start)} a {format_pt_date(end)}"


def format_workload(hours: Decimal) -> str:
    """``Decimal('20')`` -> ``20 horas``; ``Decimal('7.50')`` -> ``7,5 horas``."""
    quantized = hours.quantize(Decimal("0.01"))
    if quantized == quantized.to_integral_value():
        number = str(int(quantized))
    else:
        number = f"{quantized:f}".rstrip("0").replace(".", ",")
    return f"{number} {'hora' if quantized == 1 else 'horas'}"


# ---------------------------------------------------------------------------
# Modelo
# ---------------------------------------------------------------------------
class CertificateRenderData(BaseModel):
    """Dados necessários para desenhar um certificado."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid", frozen=True)

    cert_uuid: UUID = Field(default_factory=uuid4, description="UUID v4 do certificado.")
    recipient_name: str = Field(min_length=3, max_length=200)
    recipient_doc: str | None = Field(
        default=None, max_length=40, description="CPF (mascarado automaticamente) ou matrícula."
    )
    event_name: str = Field(min_length=3, max_length=300)
    role: str = Field(default="Participante", min_length=2, max_length=80)
    workload_hours: Decimal = Field(gt=0, le=Decimal("9999.99"), max_digits=6, decimal_places=2)
    event_date: str = Field(
        min_length=3, max_length=100, description="Data ou período já formatado, ou um date."
    )
    issued_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    extra_metadata: dict[str, Any] = Field(default_factory=dict)

    # --- cert_uuid -------------------------------------------------------
    @field_validator("cert_uuid", mode="before")
    @classmethod
    def _generate_uuid_when_missing(cls, value: Any) -> Any:
        if value is None or (isinstance(value, str) and not value.strip()):
            return uuid4()
        return value

    @field_validator("cert_uuid", mode="after")
    @classmethod
    def _require_uuid_v4(cls, value: UUID) -> UUID:
        if value.version != 4:
            raise ValueError("cert_uuid deve ser um UUID v4")
        return value

    # --- recipient_doc ---------------------------------------------------
    @field_validator("recipient_doc", mode="after")
    @classmethod
    def _mask_document(cls, value: str | None) -> str | None:
        if value is None or not value.strip():
            return None
        return mask_cpf(value) if _CPF_RE.fullmatch(value) else value

    # --- event_date ------------------------------------------------------
    @field_validator("event_date", mode="before")
    @classmethod
    def _format_event_date(cls, value: Any) -> Any:
        if isinstance(value, datetime):
            return format_pt_date(value.date())
        if isinstance(value, date):
            return format_pt_date(value)
        return value

    # --- issued_at -------------------------------------------------------
    @field_validator("issued_at", mode="after")
    @classmethod
    def _require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("issued_at deve conter fuso horário (use UTC)")
        return value.astimezone(timezone.utc)

    # --- extra_metadata --------------------------------------------------
    @field_validator("extra_metadata", mode="after")
    @classmethod
    def _limit_metadata(cls, value: dict[str, Any]) -> dict[str, Any]:
        try:
            encoded = json.dumps(value, ensure_ascii=False).encode("utf-8")
        except (TypeError, ValueError):
            raise ValueError("extra_metadata deve ser serializável em JSON") from None
        if len(encoded) > _MAX_EXTRA_METADATA_BYTES:
            raise ValueError("extra_metadata excede 8 KiB")
        return value

    # --- Apresentação ------------------------------------------------------
    @property
    def workload_label(self) -> str:
        return format_workload(self.workload_hours)

    @property
    def issued_at_label(self) -> str:
        return self.issued_at.strftime("%d/%m/%Y %H:%M") + " UTC"
