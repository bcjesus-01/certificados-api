"""Orquestrador de emissão em massa: renderiza, assina, envia e registra, tudo em RAM.

Pipeline por certificado (concorrência limitada por semáforo global):
    render -> assinatura PAdES -> SHA-256 do PDF ASSINADO -> upload -> gravação no banco
    -> URL pré-assinada

Falhas são isoladas por item: um certificado com erro nunca derruba o lote.

Compensação (consistência storage <-> banco): se o upload ocorreu e a gravação no
banco falhou, o objeto órfão é removido. Quando o resultado da gravação é ambíguo
(conexão perdida, timeout, cancelamento da requisição), o objeto só é removido após
confirmar que o registro NÃO existe; na dúvida ele é mantido e o caso é logado em
nível ERROR. Um objeto órfão em bucket privado é inofensivo; um registro sem PDF não é.
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import logging
from collections.abc import Coroutine, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal, Protocol
from uuid import UUID, uuid4

from app.repositories.errors import DuplicateCertificateError, PersistenceError
from app.repositories.models import AuditContext, IssuedCertificate
from app.schemas.certificate import CertificateRenderData

logger = logging.getLogger(__name__)

ItemStatus = Literal["issued", "failed"]

_ERROR_MESSAGES: dict[str, str] = {
    "render_failed": "Falha ao renderizar o certificado",
    "signing_failed": "Falha ao assinar o PDF",
    "storage_failed": "Falha ao enviar o PDF ao armazenamento",
    "database_failed": "Falha ao registrar o certificado no banco de dados",
    "duplicate_certificate": "Certificado já registrado",
    "duplicate_uuid": "UUID duplicado dentro do lote",
    "internal_error": "Erro interno ao emitir o certificado",
}
_STAGE_ERROR_CODES: dict[str, str] = {
    "render": "render_failed",
    "sign": "signing_failed",
    "upload": "storage_failed",
    "persist": "database_failed",
}


# ---------------------------------------------------------------------------
# Portas (permitem trocar as implementações em testes)
# ---------------------------------------------------------------------------
class RendererPort(Protocol):
    async def render_async(self, data: CertificateRenderData) -> io.BytesIO: ...

    def verification_url(self, data: CertificateRenderData) -> str: ...


class SignerPort(Protocol):
    @property
    def fingerprint(self) -> str: ...

    @property
    def serial_number(self) -> str: ...

    def ensure_ready(self) -> None: ...

    async def sign(self, pdf: io.BytesIO) -> io.BytesIO: ...


class StoragePort(Protocol):
    @property
    def bucket(self) -> str: ...

    def build_key(self, cert_id: UUID, issued_at: datetime | None = None) -> str: ...

    async def upload_pdf(self, key: str, buffer: io.BytesIO, sha256: str | None = None) -> None: ...

    async def delete(self, key: str) -> None: ...

    def presign_get(
        self, key: str, expires_in: int | None = None, download_filename: str | None = None
    ) -> str: ...


class RepositoryPort(Protocol):
    async def insert_issued(self, certificate: IssuedCertificate, context: AuditContext) -> None: ...

    async def exists(self, cert_id: UUID) -> bool: ...

    async def record_failure(self, *, context: AuditContext, details: dict[str, object]) -> None: ...


# ---------------------------------------------------------------------------
# Resultados
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class ItemOutcome:
    index: int
    status: ItemStatus
    cert_uuid: UUID
    recipient_name: str
    verification_url: str | None = None
    storage_key: str | None = None
    file_sha256: str | None = None
    presigned_url: str | None = None
    error_code: str | None = None
    error_message: str | None = None


@dataclass(frozen=True, slots=True)
class BatchOutcome:
    batch_id: UUID
    total: int
    succeeded: int
    failed: int
    items: tuple[ItemOutcome, ...]


# ---------------------------------------------------------------------------
# Serviço
# ---------------------------------------------------------------------------
class BatchIssuanceService:
    """Emite lotes de certificados com isolamento de falhas por item."""

    def __init__(
        self,
        renderer: RendererPort,
        signer: SignerPort,
        storage: StoragePort,
        repository: RepositoryPort,
        *,
        concurrency: int = 4,
        existence_retries: int = 3,
        retry_delay_seconds: float = 0.3,
    ) -> None:
        if concurrency < 1:
            raise ValueError("concurrency deve ser >= 1")
        self._renderer = renderer
        self._signer = signer
        self._storage = storage
        self._repository = repository
        self._semaphore = asyncio.Semaphore(concurrency)  # limite global entre requisições
        self._existence_retries = max(1, existence_retries)
        self._retry_delay = retry_delay_seconds

    async def issue_batch(
        self,
        items: Sequence[CertificateRenderData],
        *,
        context: AuditContext,
        batch_id: UUID | None = None,
    ) -> BatchOutcome:
        """Emite o lote. Levanta ``CertificateValidityError`` se o certificado A1 não for vigente."""
        if not items:
            raise ValueError("O lote não pode ser vazio")
        self._signer.ensure_ready()

        batch = batch_id or uuid4()
        seen: set[UUID] = set()
        coroutines: list[Coroutine[Any, Any, ItemOutcome]] = []
        for index, data in enumerate(items):
            if data.cert_uuid in seen:
                coroutines.append(self._failed_without_work(index, data, "duplicate_uuid"))
            else:
                seen.add(data.cert_uuid)
                coroutines.append(self._guarded(index, data, batch, context))

        outcomes = tuple(await asyncio.gather(*coroutines))
        succeeded = sum(1 for outcome in outcomes if outcome.status == "issued")
        logger.info(
            "Lote %s processado: total=%d emitidos=%d falhas=%d",
            batch, len(outcomes), succeeded, len(outcomes) - succeeded,
        )
        return BatchOutcome(
            batch_id=batch,
            total=len(outcomes),
            succeeded=succeeded,
            failed=len(outcomes) - succeeded,
            items=outcomes,
        )

    # ------------------------------------------------------------------
    # Internos
    # ------------------------------------------------------------------
    async def _failed_without_work(
        self, index: int, data: CertificateRenderData, code: str
    ) -> ItemOutcome:
        return ItemOutcome(
            index=index,
            status="failed",
            cert_uuid=data.cert_uuid,
            recipient_name=data.recipient_name,
            error_code=code,
            error_message=_ERROR_MESSAGES[code],
        )

    async def _guarded(
        self, index: int, data: CertificateRenderData, batch_id: UUID, context: AuditContext
    ) -> ItemOutcome:
        async with self._semaphore:
            return await self._issue_one(index, data, batch_id, context)

    async def _issue_one(
        self, index: int, data: CertificateRenderData, batch_id: UUID, context: AuditContext
    ) -> ItemOutcome:
        stage = "render"
        key: str | None = None
        file_sha256: str | None = None
        uploaded = False
        try:
            pdf = await self._renderer.render_async(data)

            stage = "sign"
            signed = await self._signer.sign(pdf)
            file_sha256 = hashlib.sha256(signed.getvalue()).hexdigest()

            stage = "upload"
            key = self._storage.build_key(data.cert_uuid, data.issued_at)
            await self._storage.upload_pdf(key, signed, file_sha256)
            uploaded = True

            stage = "persist"
            await self._repository.insert_issued(
                IssuedCertificate(
                    id=data.cert_uuid,
                    batch_id=batch_id,
                    recipient_name=data.recipient_name,
                    recipient_doc=data.recipient_doc,
                    role=data.role,
                    event_name=data.event_name,
                    event_date_label=data.event_date,
                    workload_hours=data.workload_hours,
                    issued_at=data.issued_at,
                    metadata=dict(data.extra_metadata),
                    file_sha256=file_sha256,
                    storage_bucket=self._storage.bucket,
                    storage_key=key,
                    signed_at=datetime.now(timezone.utc),
                    signer_fingerprint=self._signer.fingerprint,
                    signer_serial=self._signer.serial_number,
                ),
                context,
            )
        except asyncio.CancelledError:
            # Requisição cancelada (cliente desconectou / encerramento): não deixa órfão.
            if uploaded and key is not None:
                await asyncio.shield(self._compensate(key, data.cert_uuid, definitive=False))
            raise
        except Exception as exc:  # noqa: BLE001 - isolamento de falhas por item
            return await self._handle_failure(
                exc, stage=stage, key=key, file_sha256=file_sha256, uploaded=uploaded,
                index=index, data=data, batch_id=batch_id, context=context,
            )
        if key is None or file_sha256 is None:  # inalcançável: o pipeline preencheu ambos
            raise RuntimeError("Estado inconsistente do pipeline de emissão")
        return self._issued_outcome(index, data, key, file_sha256)

    def _issued_outcome(
        self, index: int, data: CertificateRenderData, key: str, file_sha256: str
    ) -> ItemOutcome:
        return ItemOutcome(
            index=index,
            status="issued",
            cert_uuid=data.cert_uuid,
            recipient_name=data.recipient_name,
            verification_url=self._renderer.verification_url(data),
            storage_key=key,
            file_sha256=file_sha256,
            presigned_url=self._safe_presign(key, data.cert_uuid),
        )

    def _safe_presign(self, key: str, cert_uuid: UUID) -> str | None:
        # O cálculo da URL é local; se falhar, o certificado continua emitido (sem link).
        try:
            return self._storage.presign_get(key, download_filename=f"certificado-{cert_uuid}.pdf")
        except Exception as exc:  # noqa: BLE001
            logger.error("Falha ao gerar URL pré-assinada de %s: %s", cert_uuid, type(exc).__name__)
            return None

    async def _handle_failure(
        self,
        exc: Exception,
        *,
        stage: str,
        key: str | None,
        file_sha256: str | None,
        uploaded: bool,
        index: int,
        data: CertificateRenderData,
        batch_id: UUID,
        context: AuditContext,
    ) -> ItemOutcome:
        if isinstance(exc, DuplicateCertificateError):
            code = "duplicate_certificate"
        else:
            code = _STAGE_ERROR_CODES.get(stage, "internal_error")
        logger.error(
            "Falha na emissão (lote=%s, item=%d, etapa=%s, cert=%s): %s",
            batch_id, index, stage, data.cert_uuid, type(exc).__name__,
        )

        orphan: str | None = None
        if key is not None and stage == "persist" and uploaded:
            if isinstance(exc, DuplicateCertificateError):
                definitive = True
            elif isinstance(exc, PersistenceError):
                definitive = exc.definitive
            else:
                definitive = False  # erro inesperado: resultado ambíguo, confirma antes de remover
            row_exists, orphan = await self._compensate(key, data.cert_uuid, definitive=definitive)
            if row_exists and file_sha256 is not None:
                # A gravação foi confirmada apesar do erro de comunicação: o certificado existe.
                return self._issued_outcome(index, data, key, file_sha256)
        elif key is not None and stage == "upload":
            # Upload com resultado incerto: nenhum registro existe, então remove se ficou algo.
            _, orphan = await self._compensate(key, data.cert_uuid, definitive=True)

        await self._audit_failure(
            context,
            {
                "batch_id": str(batch_id),
                "cert_uuid": str(data.cert_uuid),
                "error_code": code,
                "stage": stage,
                "orphan_object_key": orphan,
            },
        )
        return ItemOutcome(
            index=index,
            status="failed",
            cert_uuid=data.cert_uuid,
            recipient_name=data.recipient_name,
            error_code=code,
            error_message=_ERROR_MESSAGES[code],
        )

    async def _compensate(
        self, key: str, cert_id: UUID, *, definitive: bool
    ) -> tuple[bool, str | None]:
        """Reconcilia storage e banco após uma falha.

        Retorna ``(registro_existe, chave_órfã)``: ``registro_existe`` indica que a gravação foi
        confirmada (objeto mantido); ``chave_órfã`` é a chave de um objeto que deveria ter sido
        removido e não foi (ou ``None``).
        """
        if not definitive:
            state = await self._row_state(cert_id)
            if state == "exists":
                logger.warning("Gravação confirmada apesar do erro: objeto %s mantido", key)
                return True, None
            if state == "unknown":
                logger.error(
                    "Não foi possível confirmar se o registro %s existe; objeto mantido para "
                    "reconciliação manual: %s", cert_id, key,
                )
                return False, key
        try:
            await self._storage.delete(key)
            logger.warning("Objeto órfão removido do storage: %s", key)
            return False, None
        except Exception as exc:  # noqa: BLE001
            logger.error("Objeto órfão NÃO removido (%s): %s", type(exc).__name__, key)
            return False, key

    async def _row_state(self, cert_id: UUID) -> Literal["exists", "absent", "unknown"]:
        for attempt in range(self._existence_retries):
            try:
                return "exists" if await self._repository.exists(cert_id) else "absent"
            except Exception:  # noqa: BLE001 - banco instável: tenta de novo
                if attempt + 1 < self._existence_retries:
                    await asyncio.sleep(self._retry_delay * (attempt + 1))
        return "unknown"

    async def _audit_failure(self, context: AuditContext, details: dict[str, object]) -> None:
        try:
            await self._repository.record_failure(context=context, details=details)
        except Exception as exc:  # noqa: BLE001 - auditoria de falha é best-effort
            logger.warning("Não foi possível auditar a falha: %s", type(exc).__name__)
