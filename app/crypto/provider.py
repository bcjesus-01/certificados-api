"""Provedor singleton das credenciais de assinatura, ligado às configurações."""

from __future__ import annotations

from functools import lru_cache

from app.core.config import get_settings
from app.crypto.credentials import SigningCredentials, load_signing_credentials


@lru_cache(maxsize=1)
def get_signing_credentials() -> SigningCredentials:
    """Carrega o certificado A1 uma única vez por processo (falhas não são cacheadas).

    Pensado para uso como dependência do FastAPI e no ``lifespan`` da aplicação
    (falha rápida na inicialização se o certificado for inválido).
    """
    settings = get_settings()
    return load_signing_credentials(
        settings.signing_pfx_base64.get_secret_value(),
        settings.signing_pfx_password.get_secret_value(),
    )
