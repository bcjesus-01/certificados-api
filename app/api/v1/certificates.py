"""Endpoints de emissão de certificados em lote (protegidos por ``X-API-Key``).

Códigos de resposta de ambos os endpoints:
- ``201``: todos os certificados foram emitidos;
- ``207``: houve falhas por item (inspecione ``results``; os demais foram emitidos);
- ``401``/``503``: chave ausente/inválida, ou emissão desabilitada/indisponível;
- ``413``/``415``/``422``: corpo grande demais, arquivo que não é CSV, dados inválidos.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Annotated, Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, Response, UploadFile, status
from pydantic import ValidationError

from app.api.deps import IssuanceServiceDep, SettingsDep, build_audit_context, require_api_key
from app.core.config import Settings
from app.crypto.errors import CertificateValidityError
from app.schemas.certificate import CertificateRenderData
from app.schemas.issuance import (
    BatchIssueRequest,
    BatchIssueResponse,
    EventInfo,
    ParticipantValidationError,
    build_render_items,
)
from app.services.batch_issuance import BatchIssuanceService
from app.services.csv_parser import CsvFormatError, parse_participants_csv

router = APIRouter(
    prefix="/certificates",
    tags=["certificados"],
    dependencies=[Depends(require_api_key)],
    responses={
        401: {"description": "Chave de API ausente ou inválida"},
        503: {"description": "Emissão desabilitada ou certificado de assinatura indisponível"},
    },
)


def _ensure_batch_size(count: int, settings: Settings) -> None:
    if count > settings.batch_max_items:
        raise HTTPException(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            f"O lote excede o limite de {settings.batch_max_items} participantes",
        )


def _unprocessable(message: str, errors: list[dict[str, str]]) -> HTTPException:
    detail: dict[str, Any] = {"message": message, "errors": errors}
    return HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail)


async def _issue(
    items: list[CertificateRenderData],
    request: Request,
    response: Response,
    service: BatchIssuanceService,
    settings: Settings,
) -> BatchIssueResponse:
    context = build_audit_context(request, settings)
    try:
        outcome = await service.issue_batch(items, context=context)
    except CertificateValidityError:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "Certificado de assinatura indisponível (expirado ou ainda não vigente)",
        ) from None
    response.status_code = status.HTTP_201_CREATED if outcome.failed == 0 else status.HTTP_207_MULTI_STATUS
    return BatchIssueResponse.from_outcome(outcome)


@router.post(
    "/batch",
    response_model=BatchIssueResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Emite certificados em lote (JSON)",
)
async def issue_batch_json(
    payload: BatchIssueRequest,
    request: Request,
    response: Response,
    service: IssuanceServiceDep,
    settings: SettingsDep,
) -> BatchIssueResponse:
    _ensure_batch_size(len(payload.participants), settings)
    try:
        items = build_render_items(
            payload.event,
            payload.participants,
            [f"participants[{index}]" for index in range(len(payload.participants))],
        )
    except ParticipantValidationError as exc:
        raise _unprocessable("Há participantes inválidos no lote", exc.errors) from None
    return await _issue(items, request, response, service, settings)


@router.post(
    "/batch-csv",
    response_model=BatchIssueResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Emite certificados em lote (upload de CSV)",
    description=(
        "Envie `multipart/form-data` com os dados do evento e o arquivo CSV. Coluna obrigatória: "
        "`recipient_name` (alias `nome`). Opcionais: `recipient_doc` (`cpf`, `documento`, "
        "`matricula`) e `role` (`papel`). Demais colunas viram metadados. Aceita UTF-8 ou "
        "Windows-1252 e delimitadores `,` `;` ou tab."
    ),
)
async def issue_batch_csv(
    request: Request,
    response: Response,
    service: IssuanceServiceDep,
    settings: SettingsDep,
    file: Annotated[UploadFile, File(description="Arquivo .csv com os participantes")],
    event_name: Annotated[str, Form(min_length=3, max_length=300)],
    event_date: Annotated[str, Form(min_length=3, max_length=100)],
    workload_hours: Annotated[
        Decimal, Form(gt=0, le=Decimal("9999.99"), max_digits=6, decimal_places=2)
    ],
    default_role: Annotated[str, Form(min_length=2, max_length=80)] = "Participante",
) -> BatchIssueResponse:
    if not (file.filename or "").lower().endswith(".csv"):
        raise HTTPException(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, "Envie um arquivo com extensão .csv")

    # O corpo já foi limitado (< 1 MiB) pelo middleware, então o upload ficou em RAM.
    raw = await file.read(settings.batch_max_body_bytes + 1)
    await file.close()
    if len(raw) > settings.batch_max_body_bytes:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "Arquivo CSV grande demais")

    try:
        event = EventInfo(
            event_name=event_name,
            event_date=event_date,
            workload_hours=workload_hours,
            default_role=default_role,
        )
    except ValidationError as exc:
        errors = [
            {"location": "evento", "field": ".".join(str(p) for p in error["loc"]), "message": error["msg"]}
            for error in exc.errors(include_url=False, include_context=False, include_input=False)
        ]
        raise _unprocessable("Dados do evento inválidos", errors) from None

    try:
        parsed = parse_participants_csv(raw, max_rows=settings.batch_max_items)
    except CsvFormatError as exc:
        raise _unprocessable(exc.message, exc.errors) from None

    try:
        items = build_render_items(event, parsed.participants, parsed.locations)
    except ParticipantValidationError as exc:
        raise _unprocessable("Há linhas inválidas no CSV", exc.errors) from None
    return await _issue(items, request, response, service, settings)
