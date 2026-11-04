"""Contratos da API de emissão em lote (Pydantic v2)."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import date
from decimal import Decimal
from typing import TYPE_CHECKING, Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from app.schemas.certificate import CertificateRenderData, format_pt_date

if TYPE_CHECKING:
    from app.services.batch_issuance import BatchOutcome

_MAX_REPORTED_ERRORS = 50
_ISO_DATE_LENGTH = 10


class EventInfo(BaseModel):
    """Dados do evento, comuns a todos os participantes do lote."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    event_name: str = Field(min_length=3, max_length=300)
    event_date: str = Field(
        min_length=3, max_length=100,
        description="Texto da data/período (ex.: '10 a 14 de novembro de 2026') ou data ISO.",
    )
    workload_hours: Decimal = Field(gt=0, le=Decimal("9999.99"), max_digits=6, decimal_places=2)
    default_role: str = Field(default="Participante", min_length=2, max_length=80)

    @field_validator("event_date", mode="before")
    @classmethod
    def _format_date(cls, value: Any) -> Any:
        if isinstance(value, date):
            return format_pt_date(value)
        if isinstance(value, str) and len(value.strip()) == _ISO_DATE_LENGTH:
            try:
                return format_pt_date(date.fromisoformat(value.strip()))
            except ValueError:
                return value
        return value


class ParticipantInput(BaseModel):
    """Participante do lote. O UUID do certificado é sempre gerado pelo servidor."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    recipient_name: str = Field(min_length=1, max_length=200)
    recipient_doc: str | None = Field(default=None, max_length=40)
    role: str | None = Field(default=None, max_length=80)
    extra_metadata: dict[str, Any] = Field(default_factory=dict)


class BatchIssueRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event: EventInfo
    participants: list[ParticipantInput] = Field(min_length=1, max_length=5000)


class ParticipantValidationError(Exception):
    """Dados de participantes inválidos (detalhes SEM ecoar os valores recebidos)."""

    def __init__(self, errors: list[dict[str, str]]) -> None:
        super().__init__("Dados de participantes inválidos")
        self.errors = errors


def build_render_items(
    event: EventInfo,
    participants: Sequence[ParticipantInput],
    locations: Sequence[str],
) -> list[CertificateRenderData]:
    """Converte participantes em ``CertificateRenderData`` (fonte única das regras de validação).

    ``locations`` identifica cada participante nas mensagens (ex.: ``participants[3]`` ou
    ``linha 7``). Os erros nunca incluem o valor informado (nomes e documentos são pessoais).
    """
    items: list[CertificateRenderData] = []
    errors: list[dict[str, str]] = []
    for participant, location in zip(participants, locations, strict=True):
        try:
            items.append(
                CertificateRenderData(
                    recipient_name=participant.recipient_name,
                    recipient_doc=participant.recipient_doc,
                    event_name=event.event_name,
                    role=participant.role or event.default_role,
                    workload_hours=event.workload_hours,
                    event_date=event.event_date,
                    extra_metadata=participant.extra_metadata,
                )
            )
        except ValidationError as exc:
            for error in exc.errors(include_url=False, include_context=False, include_input=False):
                errors.append(
                    {
                        "location": location,
                        "field": ".".join(str(part) for part in error["loc"]),
                        "message": error["msg"],
                    }
                )
        if len(errors) >= _MAX_REPORTED_ERRORS:
            break
    if errors:
        raise ParticipantValidationError(errors[:_MAX_REPORTED_ERRORS])
    return items


# ---------------------------------------------------------------------------
# Respostas
# ---------------------------------------------------------------------------
class BatchItemResult(BaseModel):
    index: int
    status: Literal["issued", "failed"]
    cert_uuid: UUID
    recipient_name: str
    verification_url: str | None = None
    storage_key: str | None = None
    file_sha256: str | None = None
    presigned_url: str | None = None
    error_code: str | None = None
    error_message: str | None = None


class BatchIssueResponse(BaseModel):
    batch_id: UUID
    total: int
    succeeded: int
    failed: int
    results: list[BatchItemResult]

    @classmethod
    def from_outcome(cls, outcome: "BatchOutcome") -> "BatchIssueResponse":
        return cls(
            batch_id=outcome.batch_id,
            total=outcome.total,
            succeeded=outcome.succeeded,
            failed=outcome.failed,
            results=[
                BatchItemResult(
                    index=item.index,
                    status=item.status,
                    cert_uuid=item.cert_uuid,
                    recipient_name=item.recipient_name,
                    verification_url=item.verification_url,
                    storage_key=item.storage_key,
                    file_sha256=item.file_sha256,
                    presigned_url=item.presigned_url,
                    error_code=item.error_code,
                    error_message=item.error_message,
                )
                for item in outcome.items
            ],
        )
