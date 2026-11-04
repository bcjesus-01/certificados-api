"""Dependências do FastAPI: configuração, serviço de emissão e autenticação por chave de API."""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from typing import Annotated

from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader

from app.core.config import Settings, get_settings
from app.repositories.models import AuditContext
from app.services.batch_issuance import BatchIssuanceService

SettingsDep = Annotated[Settings, Depends(get_settings)]

_api_key_header = APIKeyHeader(
    name="X-API-Key",
    auto_error=False,
    description="Chave de API de emissão (variável ISSUANCE_API_KEY).",
)
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


async def require_api_key(
    provided: Annotated[str | None, Security(_api_key_header)],
    settings: SettingsDep,
) -> None:
    """Valida o cabeçalho ``X-API-Key`` em tempo constante (``secrets.compare_digest``)."""
    expected = settings.issuance_api_key
    if expected is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Emissão desabilitada: ISSUANCE_API_KEY não configurada",
        )
    if not provided or not secrets.compare_digest(
        provided.encode("utf-8"), expected.get_secret_value().encode("utf-8")
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Chave de API ausente ou inválida",
            headers={"WWW-Authenticate": "ApiKey"},
        )


def get_issuance_service(request: Request) -> BatchIssuanceService:
    service: BatchIssuanceService | None = getattr(request.app.state, "issuance_service", None)
    if service is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Serviço de emissão indisponível")
    return service


IssuanceServiceDep = Annotated[BatchIssuanceService, Depends(get_issuance_service)]


def build_audit_context(request: Request, settings: Settings) -> AuditContext:
    """Contexto de auditoria: IP apenas como HMAC (LGPD) e User-Agent truncado."""
    client_ip = request.client.host if request.client else ""
    ip_hash: str | None = None
    if client_ip and settings.issuance_api_key is not None:
        key = settings.issuance_api_key.get_secret_value().encode("utf-8")
        ip_hash = hmac.new(key, client_ip.encode("utf-8"), hashlib.sha256).hexdigest()
    user_agent = request.headers.get("user-agent")
    if user_agent:
        user_agent = _CONTROL_RE.sub("", user_agent)[:512] or None
    return AuditContext(client_ip_hash=ip_hash, user_agent=user_agent)
