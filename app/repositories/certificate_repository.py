"""Repositório de certificados e auditoria (asyncpg / Supabase).

Cada emissão grava o certificado e o registro de auditoria na MESMA transação:
ou os dois existem, ou nenhum. O log de auditoria é append-only (triggers do SQL).
"""

from __future__ import annotations

import logging
from typing import Any
from uuid import UUID

import asyncpg
from asyncpg import exceptions as pg_exc

from app.repositories.errors import DuplicateCertificateError, PersistenceError
from app.repositories.models import AuditContext, IssuedCertificate
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
