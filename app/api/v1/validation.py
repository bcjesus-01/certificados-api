"""Endpoints PÚBLICOS de validação de certificados (sem X-API-Key).

- ``GET  /validate/{cert_uuid}``: consulta por código / QR Code. ``200`` com ``VALID`` ou
  ``REVOKED``; ``404`` com payload estruturado ``status="NOT_FOUND"``.
- ``POST /validate/file``: perícia de um PDF enviado (multipart, campo ``file``). Sempre ``200``
  quando o arquivo foi examinado (o veredito está em ``status``); ``413``/``415``/``422`` para
  uploads rejeitados antes da perícia; ``503`` se o banco ou a perícia estiverem indisponíveis.

Todas as respostas levam ``Cache-Control: no-store`` (contêm URLs temporárias e vereditos).
O upload é lido em pedaços, direto para a RAM, e descartado ao final da requisição.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, File, HTTPException, Path, Request, UploadFile, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.api.deps import SettingsDep, ValidationServiceDep, build_audit_context
from app.repositories.errors import RepositoryUnavailableError
from app.schemas.validation import (
    CodeValidationResponse,
    FileValidationResponse,
    ValidationStatus,
)
from app.services.validation_service import ValidationUnavailableError

router = APIRouter(
    prefix="/validate",
    tags=["validação pública"],
    responses={503: {"description": "Banco de dados ou perícia indisponíveis; tente novamente"}},
)

_CHUNK_SIZE = 64 * 1024
_PDF_MAGIC = b"%PDF-"
_NO_STORE = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}
# Literais numéricos: o Starlette renomeou HTTP_413/HTTP_422 em versões recentes.
_HTTP_413 = 413
_HTTP_422 = 422


def _json(model: BaseModel, status_code: int = status.HTTP_200_OK) -> JSONResponse:
    return JSONResponse(
        status_code=status_code, content=model.model_dump(mode="json"), headers=_NO_STORE
    )


def _unavailable() -> HTTPException:
    return HTTPException(
        status.HTTP_503_SERVICE_UNAVAILABLE,
        "Serviço temporariamente indisponível. Tente novamente em instantes.",
        headers={"Retry-After": "5", **_NO_STORE},
    )


async def _read_pdf_in_memory(upload: UploadFile, max_bytes: int) -> bytes:
    """Lê o upload em pedaços para a RAM, validando tamanho e cabeçalho ``%PDF-``.

    O corpo já foi limitado pelo middleware (< 1 MiB), então o Starlette manteve o arquivo em
    memória. Esta leitura repete o limite como defesa em profundidade.
    """
    buffer = bytearray()
    try:
        while chunk := await upload.read(_CHUNK_SIZE):
            if not buffer and len(chunk) >= len(_PDF_MAGIC) and not chunk.startswith(_PDF_MAGIC):
                raise HTTPException(
                    status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, "O arquivo enviado não é um PDF"
                )
            buffer.extend(chunk)
            if len(buffer) > max_bytes:
                raise HTTPException(
                    _HTTP_413, f"Arquivo acima do limite de {max_bytes} bytes para validação"
                )
    finally:
        await upload.close()
    if not buffer:
        raise HTTPException(_HTTP_422, "O arquivo enviado está vazio")
    if not buffer.startswith(_PDF_MAGIC):
        raise HTTPException(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, "O arquivo enviado não é um PDF")
    return bytes(buffer)


@router.post(
    "/file",
    response_model=FileValidationResponse,
    summary="Perícia de um PDF enviado (hash + assinatura PAdES)",
    description=(
        "Envie `multipart/form-data` com o campo `file` (PDF). O arquivo é examinado em memória: "
        "SHA-256 cruzado com os certificados emitidos e verificação criptográfica da assinatura. "
        "Veredito em `status`: `VALID`, `REVOKED`, `INVALID_TAMPERED` ou `INVALID_SIGNATURE`."
    ),
    responses={
        413: {"description": "Arquivo acima do limite"},
        415: {"description": "O arquivo não é um PDF"},
        422: {"description": "Arquivo vazio ou campo ausente"},
    },
)
async def validate_file(
    request: Request,
    service: ValidationServiceDep,
    settings: SettingsDep,
    file: Annotated[UploadFile, File(description="PDF do certificado a ser verificado")],
) -> JSONResponse:
    data = await _read_pdf_in_memory(file, settings.validation_max_upload_bytes)
    context = build_audit_context(request, settings)
    try:
        result: FileValidationResponse = await service.validate_file(data, context)
    except (RepositoryUnavailableError, ValidationUnavailableError):
        raise _unavailable() from None
    return _json(result)


@router.get(
    "/{cert_uuid}",
    response_model=CodeValidationResponse,
    summary="Consulta pública por código / QR Code",
    description=(
        "Retorna os metadados públicos do certificado (documento sempre mascarado) e, quando ele "
        "está ativo, uma URL pré-assinada temporária para baixar a via original assinada. "
        "Certificado revogado responde `REVOKED` sem URL de download."
    ),
    responses={404: {"model": CodeValidationResponse, "description": "status=NOT_FOUND"}},
)
async def validate_by_code(
    cert_uuid: Annotated[str, Path(max_length=64, description="UUID v4 do certificado (do QR Code)")],
    request: Request,
    service: ValidationServiceDep,
    settings: SettingsDep,
) -> JSONResponse:
    context = build_audit_context(request, settings)
    try:
        result = await service.validate_code(cert_uuid.strip(), context)
    except RepositoryUnavailableError:
        raise _unavailable() from None
    code = status.HTTP_404_NOT_FOUND if result.status is ValidationStatus.NOT_FOUND else status.HTTP_200_OK
    return _json(result, code)
