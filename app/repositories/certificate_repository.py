"""Repositório de certificados e auditoria (asyncpg / Supabase).

Cada emissão grava o certificado e o registro de auditoria na MESMA transação:
ou os dois existem, ou nenhum. O log de auditoria é append-only (triggers do SQL).
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from typing import Any
from uuid import UUID

import asyncpg
from asyncpg import exceptions as pg_exc

from app.repositories.errors import (
    DuplicateCertificateError,
    PersistenceError,
    RepositoryUnavailableError,
)
from app.repositories.models import (
    AuditContext,
    AuditEvent,
    CertificateRecord,
    IssuedCertificate,
    RevocationResult,
)
from app.services.database import Database, DatabaseError

logger = logging.getLogger(__name__)

_INSERT_CERTIFICATE = """
insert into public.certificates (
    id, batch_id, participant_name, recipient_doc, role, event_name, event_date_label,
    workload_hours, issued_at, metadata, pdf_sha256, storage_bucket, storage_key,
    signed_at, signer_fingerprint, signer_serial
) values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
"""

_INSERT_AUDIT_SUCCESS = """
insert into public.certificate_audit_log
    (certificate_id, action, outcome, client_ip_hash, user_agent, details)
values ($1, 'issued', 'success', $2, $3, $4)
"""

_INSERT_AUDIT_FAILURE = """
insert into public.certificate_audit_log
    (certificate_id, action, outcome, client_ip_hash, user_agent, details)
values (null, 'issued', 'error', $1, $2, $3)
"""

_SELECT_RECORD = """
select id, participant_name, recipient_doc, role, event_name, event_date_label,
       workload_hours, issued_at, signed_at, pdf_sha256, storage_bucket, storage_key,
       signer_fingerprint, status::text as status, revoked_at
from public.certificates
"""

_INSERT_AUDIT_EVENT = """
insert into public.certificate_audit_log
    (certificate_id, action, outcome, client_ip_hash, user_agent, details)
values ($1, $2, $3, $4, $5, $6)
"""

_REVOKE = """
update public.certificates
   set status = 'revoked', revoked_at = now(), revoked_reason = $2
 where id = $1 and status = 'valid'
returning revoked_at
"""

_READ_ERRORS = (pg_exc.PostgresError, asyncpg.InterfaceError, OSError, DatabaseError)


def _to_record(row: asyncpg.Record) -> CertificateRecord:
    return CertificateRecord(
        id=row["id"],
        participant_name=row["participant_name"],
        recipient_doc=row["recipient_doc"],
        role=row["role"],
        event_name=row["event_name"],
        event_date_label=row["event_date_label"],
        workload_hours=row["workload_hours"],
        issued_at=row["issued_at"],
        signed_at=row["signed_at"],
        pdf_sha256=row["pdf_sha256"],
        storage_bucket=row["storage_bucket"],
        storage_key=row["storage_key"],
        signer_fingerprint=row["signer_fingerprint"],
        status=row["status"],
        revoked_at=row["revoked_at"],
    )


class CertificateRepository:
    """Persistência dos certificados emitidos."""

    def __init__(self, database: Database) -> None:
        self._db = database

    async def insert_issued(self, certificate: IssuedCertificate, context: AuditContext) -> None:
        """Insere certificado + auditoria de emissão atomicamente."""
        details: dict[str, Any] = {
            "batch_id": str(certificate.batch_id),
            "storage_key": certificate.storage_key,
            "file_sha256": certificate.file_sha256,
            "signer_fingerprint": certificate.signer_fingerprint,
        }
        try:
            async with self._db.transaction() as conn:
                await conn.execute(
                    _INSERT_CERTIFICATE,
                    certificate.id,
                    certificate.batch_id,
                    certificate.recipient_name,
                    certificate.recipient_doc,
                    certificate.role,
                    certificate.event_name,
                    certificate.event_date_label,
                    certificate.workload_hours,
                    certificate.issued_at,
                    certificate.metadata,
                    certificate.file_sha256,
                    certificate.storage_bucket,
                    certificate.storage_key,
                    certificate.signed_at,
                    certificate.signer_fingerprint,
                    certificate.signer_serial,
                )
                await conn.execute(
                    _INSERT_AUDIT_SUCCESS,
                    certificate.id,
                    context.client_ip_hash,
                    context.user_agent,
                    details,
                )
        except pg_exc.UniqueViolationError as exc:
            raise DuplicateCertificateError("Certificado já registrado") from exc
        except pg_exc.PostgresConnectionError as exc:
            raise PersistenceError("Conexão com o banco perdida durante a gravação", definitive=False) from exc
        except pg_exc.PostgresError as exc:
            logger.error("Banco rejeitou a gravação: %s", type(exc).__name__)
            raise PersistenceError("O banco de dados rejeitou a gravação", definitive=True) from exc
        except DatabaseError as exc:
            raise PersistenceError("Banco de dados indisponível", definitive=True) from exc
        except (OSError, asyncpg.InterfaceError) as exc:
            raise PersistenceError("Falha de comunicação com o banco", definitive=False) from exc

    async def exists(self, cert_id: UUID) -> bool:
        row = await self._db.fetch_one("select 1 from public.certificates where id = $1", cert_id)
        return row is not None

    async def record_failure(self, *, context: AuditContext, details: dict[str, Any]) -> None:
        """Registra uma falha de emissão (sem certificado associado). Pode lançar exceção."""
        await self._db.execute(
            _INSERT_AUDIT_FAILURE, context.client_ip_hash, context.user_agent, details
        )

    # ------------------------------------------------------------------
    # Consultas (Etapa 5)
    # ------------------------------------------------------------------
    async def get_by_id(self, cert_id: UUID) -> CertificateRecord | None:
        try:
            row = await self._db.fetch_one(f"{_SELECT_RECORD} where id = $1", cert_id)
        except _READ_ERRORS as exc:
            logger.error("Falha ao consultar certificado por id: %s", type(exc).__name__)
            raise RepositoryUnavailableError("Banco de dados indisponível") from exc
        return _to_record(row) if row is not None else None

    async def get_by_sha256(self, file_sha256: str) -> CertificateRecord | None:
        """Busca pelo hash do PDF assinado (índice único ``certificates_pdf_sha256_key``)."""
        try:
            row = await self._db.fetch_one(f"{_SELECT_RECORD} where pdf_sha256 = $1", file_sha256)
        except _READ_ERRORS as exc:
            logger.error("Falha ao consultar certificado por hash: %s", type(exc).__name__)
            raise RepositoryUnavailableError("Banco de dados indisponível") from exc
        return _to_record(row) if row is not None else None

    async def record_audit(self, events: Sequence[AuditEvent], context: AuditContext) -> None:
        """Grava eventos de auditoria numa única transação. Pode lançar ``RepositoryUnavailableError``."""
        if not events:
            return
        try:
            async with self._db.transaction() as conn:
                for event in events:
                    await conn.execute(
                        _INSERT_AUDIT_EVENT,
                        event.certificate_id,
                        event.action,
                        event.outcome,
                        context.client_ip_hash,
                        context.user_agent,
                        event.details,
                    )
        except _READ_ERRORS as exc:
            logger.error("Falha ao gravar auditoria: %s", type(exc).__name__)
            raise RepositoryUnavailableError("Banco de dados indisponível") from exc

    async def revoke(
        self, cert_id: UUID, reason: str, context: AuditContext
    ) -> RevocationResult:
        """Revoga o certificado e audita a tentativa na MESMA transação (atômico).

        O motivo fica apenas em ``certificates.revoked_reason``: o log de auditoria é
        append-only e não permitiria corrigir/apagar dados pessoais digitados no texto livre.
        """
        try:
            async with self._db.transaction() as conn:
                revoked_at = await conn.fetchval(_REVOKE, cert_id, reason)
                if revoked_at is not None:
                    result = RevocationResult("revoked", revoked_at)
                else:
                    current = await conn.fetchval(
                        "select status::text from public.certificates where id = $1", cert_id
                    )
                    result = RevocationResult("not_found" if current is None else "already_revoked")
                outcome = {"revoked": "success", "not_found": "not_found"}.get(
                    result.outcome, "invalid"
                )
                await conn.execute(
                    _INSERT_AUDIT_EVENT,
                    cert_id if result.outcome != "not_found" else None,
                    "revoked",
                    outcome,
                    context.client_ip_hash,
                    context.user_agent,
                    {"result": result.outcome, "cert_uuid": str(cert_id)},
                )
        except _READ_ERRORS as exc:
            logger.error("Falha ao revogar certificado: %s", type(exc).__name__)
            raise RepositoryUnavailableError("Banco de dados indisponível") from exc
        return result
