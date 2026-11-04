"""Aplicação FastAPI: ciclo de vida, middlewares e rotas."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import health
from app.api.middleware import MaxBodySizeMiddleware
from app.api.v1 import certificates, validation
from app.core.config import Settings, get_settings
from app.crypto.inspector import PyHankoPdfInspector
from app.crypto.provider import get_signing_credentials
from app.crypto.signing_service import PadesSigningService
from app.repositories.certificate_repository import CertificateRepository
from app.services.batch_issuance import BatchIssuanceService
from app.services.certificate_renderer import CertificateRenderer
from app.services.database import Database
from app.services.storage import ObjectStorage
from app.services.validation_service import ValidationService

logger = logging.getLogger(__name__)

# Folga para delimitadores/cabeçalhos do multipart além dos bytes do arquivo.
_MULTIPART_OVERHEAD_BYTES = 4096


def _configure_logging(level: str) -> None:
    root = logging.getLogger()
    if not root.handlers:
        logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    root.setLevel(level)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Monta as dependências uma única vez. Falha na inicialização = deploy rejeitado."""
    settings = get_settings()
    _configure_logging(settings.log_level)

    database = Database(settings)
    await database.connect()
    try:
        storage = ObjectStorage(settings)
        credentials = get_signing_credentials()  # PKCS#12 inválido derruba a inicialização
        renderer = CertificateRenderer.from_settings(settings)
        signer = PadesSigningService(
            credentials, reason=settings.signing_reason, location=settings.signing_location
        )
        repository = CertificateRepository(database)

        app.state.db = database
        app.state.storage = storage
        app.state.credentials = credentials
        app.state.renderer = renderer
        app.state.signer = signer
        app.state.repository = repository
        app.state.issuance_service = BatchIssuanceService(
            renderer, signer, storage, repository, concurrency=settings.batch_concurrency
        )

        app.state.validation_service = ValidationService(
            repository,
            storage,
            PyHankoPdfInspector(credentials),
            presign_ttl_seconds=settings.validation_presigned_ttl_seconds,
            concurrency=settings.validation_concurrency,
            timeout_seconds=settings.validation_timeout_seconds,
        )

        health_status = credentials.healthcheck()
        if not health_status.ok:
            logger.error("Emissão bloqueada: %s", health_status.message)
        if settings.issuance_api_key is None:
            logger.error("ISSUANCE_API_KEY ausente: os endpoints de emissão respondem 503")
        logger.info("Aplicação pronta (ambiente=%s)", settings.app_env)
        yield
    finally:
        await database.close()


def create_app(settings: Settings | None = None) -> FastAPI:
    resolved = settings or get_settings()
    app = FastAPI(
        title=resolved.app_name,
        version="1.0.0",
        lifespan=lifespan,
        docs_url=None if resolved.is_production else "/docs",
        redoc_url=None,
        openapi_url=None if resolved.is_production else "/openapi.json",
    )
    # Ordem: o último adicionado é o mais externo. O limite de corpo atua primeiro.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=resolved.cors_allowed_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["X-API-Key", "Content-Type"],
    )
    app.add_middleware(
        MaxBodySizeMiddleware,
        max_bytes=resolved.batch_max_body_bytes,
        path_prefix=f"{resolved.api_v1_prefix}/certificates",
    )
    # Upload da perícia pública: corpo = arquivo + pequena sobra de multipart, sempre < 1 MiB (RAM).
    app.add_middleware(
        MaxBodySizeMiddleware,
        max_bytes=resolved.validation_max_upload_bytes + _MULTIPART_OVERHEAD_BYTES,
        path_prefix=f"{resolved.api_v1_prefix}/validate/file",
    )
    app.include_router(health.router)
    app.include_router(certificates.router, prefix=resolved.api_v1_prefix)
    app.include_router(validation.router, prefix=resolved.api_v1_prefix)
    return app


app = create_app()
