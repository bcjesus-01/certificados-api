"""Sondas de saúde (liveness/readiness) para Cloud Run / Render."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

router = APIRouter(tags=["saúde"])


@router.get("/healthz", summary="Liveness: o processo está de pé")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/readyz", summary="Readiness: banco e storage acessíveis")
async def readyz(request: Request) -> JSONResponse:
    state = request.app.state
    database_ok = await state.db.healthcheck()
    storage_ok = await state.storage.healthcheck()
    crypto = state.credentials.healthcheck()
    ready = database_ok and storage_ok
    return JSONResponse(
        status_code=200 if ready else 503,
        content={
            "status": "ready" if ready else "degraded",
            "database": database_ok,
            "storage": storage_ok,
            # O certificado vencido não derruba a leitura/validação; só bloqueia a emissão.
            "signing_certificate": crypto.status,
        },
    )
