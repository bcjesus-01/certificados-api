"""Smoke test E2E da Etapa 4: API de emissão em lote + Supabase + bucket + assinatura PAdES.

Uso (na raiz do projeto, com .env completo, incluindo ISSUANCE_API_KEY):
    python scripts/smoke_step4.py

ATENÇÃO: usa o banco e o bucket REAIS configurados no .env. Todo dado criado leva a marca
``metadata.smoke_test = <run_id>`` e é removido ao final (objetos do bucket e linhas do banco).
Como o log de auditoria é append-only (triggers), a limpeza desabilita UM trigger dentro de
uma única transação, apaga apenas as linhas desta execução e o reabilita antes do commit.
Isso exige que a conexão seja a do dono das tabelas (o usuário ``postgres`` do Supabase).

Retorna código de saída 0 somente se todas as verificações passarem.
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import re
import sys
from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import httpx  # noqa: E402
import smoke_step3 as s3  # noqa: E402
from smoke_step2 import Report, validate  # noqa: E402

from app.core.config import get_settings  # noqa: E402

BATCH_URL = "/api/v1/certificates/batch"
CSV_URL = "/api/v1/certificates/batch-csv"
_HEX64 = re.compile(r"[0-9a-f]{64}")

EVENT_FORM = {
    "event_name": "Smoke Test — Semana de Informática",
    "event_date": "10 a 14 de novembro de 2026",
    "workload_hours": "12.5",
    "default_role": "Participante",
}


def build_csv(run_id: str) -> bytes:
    text = (
        "﻿Nome;CPF;Papel;smoke_test\r\n"
        f"Carlos Eduardo Pereira;987.654.321-00;Palestrante;{run_id}\r\n"
        f"Joana D'Arc Álvares;;;{run_id}\r\n"
    )
    return text.encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


async def scenario(app: Any, report: Report, api_key: str, run_id: str, batch_ids: set[str]) -> None:
    from app.repositories.errors import PersistenceError
    from app.repositories.models import AuditContext
    from app.schemas.certificate import CertificateRenderData
    from app.services.batch_issuance import BatchIssuanceService

    db, storage, creds = app.state.db, app.state.storage, app.state.credentials
    headers = {"X-API-Key": api_key}
    wrong_key = api_key[:-1] + ("A" if api_key[-1] != "A" else "B")
    meta = {"smoke_test": run_id}

    json_payload: dict[str, Any] = {
        "event": {
            "event_name": EVENT_FORM["event_name"],
            "event_date": "2026-11-10",
            "workload_hours": "20",
            "default_role": "Participante",
        },
        "participants": [
            {"recipient_name": "João da Silva Conceição Júnior", "recipient_doc": "123.456.789-09", "extra_metadata": meta},
            {"recipient_name": "Maria Aparecida Albuquerque", "role": "Organização", "extra_metadata": meta},
            {"recipient_name": "Łukasz Żółć Müller", "extra_metadata": meta},
        ],
    }

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver", timeout=180) as client:
        # 1. Autenticação ------------------------------------------------------------------
        print("--- Autenticação e validação de entrada ---")
        r = await client.post(BATCH_URL, json=json_payload)
        report.check("JSON sem X-API-Key -> 401", r.status_code == 401, str(r.status_code))
        r = await client.post(BATCH_URL, json=json_payload, headers={"X-API-Key": wrong_key})
        report.check("JSON com chave errada -> 401", r.status_code == 401, str(r.status_code))
        r = await client.post(CSV_URL, data=EVENT_FORM, files={"file": ("p.csv", build_csv(run_id), "text/csv")})
        report.check("CSV sem X-API-Key -> 401", r.status_code == 401, str(r.status_code))

        # 2. Validação (sem eco de dados pessoais) ----------------------------------------------
        empty = {"event": json_payload["event"], "participants": []}
        r = await client.post(BATCH_URL, json=empty, headers=headers)
        report.check("Lote vazio -> 422", r.status_code == 422, str(r.status_code))
        invalid = {"event": json_payload["event"], "participants": [{"recipient_name": "Al", "recipient_doc": "111.222.333-44"}]}
        r = await client.post(BATCH_URL, json=invalid, headers=headers)
        report.check(
            "Participante inválido -> 422 com localização e SEM ecoar o CPF",
            r.status_code == 422 and "participants[0]" in r.text and "111.222" not in r.text,
            str(r.status_code),
        )
        r = await client.post(CSV_URL, data=EVENT_FORM, headers=headers, files={"file": ("p.txt", b"nome\nAna Lima\n", "text/plain")})
        report.check("Arquivo que não é .csv -> 415", r.status_code == 415, str(r.status_code))
        r = await client.post(CSV_URL, data=EVENT_FORM, headers=headers, files={"file": ("p.csv", b"cpf;papel\r\n1;2\r\n", "text/csv")})
        report.check("CSV sem coluna de nome -> 422", r.status_code == 422, str(r.status_code))

        # 3. Emissão via JSON e via CSV ----------------------------------------------------------------
        print("\n--- Emissão em lote ---")
        r = await client.post(BATCH_URL, json=json_payload, headers=headers)
        body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
        report.check("POST /batch -> 201 com 3 emitidos", r.status_code == 201 and body.get("succeeded") == 3, f"{r.status_code} {r.text[:200] if r.status_code != 201 else ''}")
        issued: list[dict[str, Any]] = [x for x in body.get("results", []) if x["status"] == "issued"]
        if body.get("batch_id"):
            batch_ids.add(body["batch_id"])

        r = await client.post(
            CSV_URL, data=EVENT_FORM, headers=headers,
            files={"file": ("participantes.csv", build_csv(run_id), "text/csv")},
        )
        body_csv = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
        report.check("POST /batch-csv -> 201 com 2 emitidos", r.status_code == 201 and body_csv.get("succeeded") == 2, f"{r.status_code} {r.text[:200] if r.status_code != 201 else ''}")
        issued += [x for x in body_csv.get("results", []) if x["status"] == "issued"]
        if body_csv.get("batch_id"):
            batch_ids.add(body_csv["batch_id"])

    report.check("Todos os itens têm URL pré-assinada, hash e URL pública", all(
        x["presigned_url"] and _HEX64.fullmatch(x["file_sha256"] or "") and x["verification_url"].endswith(x["cert_uuid"])
        for x in issued) and len(issued) == 5)
    if not issued:
        return

    # 4. Banco de dados -------------------------------------------------------------------------------
    print("\n--- Supabase ---")
    ids = [UUID(x["cert_uuid"]) for x in issued]
    rows = await db.fetch_all(
        "select id, pdf_sha256, storage_key, storage_bucket, signer_fingerprint, recipient_doc, "
        "participant_name, role, status from public.certificates where id = any($1::uuid[])", ids,
    )
    by_id = {str(row["id"]): row for row in rows}
    report.check("5 certificados gravados", len(rows) == 5, str(len(rows)))
    report.check("file_sha256 do banco == hash informado pela API", all(
        by_id.get(x["cert_uuid"]) is not None and by_id[x["cert_uuid"]]["pdf_sha256"] == x["file_sha256"] for x in issued))
    report.check("Fingerprint do certificado assinante gravado", all(
        row["signer_fingerprint"] == creds.info.sha256_fingerprint for row in rows))
    docs = {row["participant_name"]: row["recipient_doc"] for row in rows}
    report.check("CPFs gravados apenas MASCARADOS", (
        docs.get("João da Silva Conceição Júnior") == "***.456.789-**"
        and docs.get("Carlos Eduardo Pereira") == "***.654.321-**"
        and not any("123.456.789" in (d or "") or "987.654.321" in (d or "") for d in docs.values())))
    report.check("Papéis gravados (Organização, Palestrante, Participante)", {row["role"] for row in rows} == {"Organização", "Palestrante", "Participante"})
    audit = await db.fetch_all(
        "select certificate_id from public.certificate_audit_log "
        "where certificate_id = any($1::uuid[]) and action = 'issued' and outcome = 'success'", ids,
    )
    report.check("5 registros de auditoria de emissão", len(audit) == 5, str(len(audit)))

    # 5. Download direto do bucket para a RAM + verificação PAdES ----------------------------------------------------
    print("\n--- Bucket e assinatura ---")
    hashes_ok = signatures_ok = pages_ok = True
    for item in issued:
        data = await storage.download(item["storage_key"])
        hashes_ok &= sha256_hex(data) == item["file_sha256"] == by_id[item["cert_uuid"]]["pdf_sha256"]
        # O validador síncrono do pyHanko usa asyncio.run: roda em thread para não colidir com o loop.
        status = await asyncio.to_thread(validate, io.BytesIO(data), creds)
        signatures_ok &= bool(status.intact) and bool(status.valid)
        pages_ok &= s3.page_count(data) == 1 and data.startswith(b"%PDF-")
    report.check("sha256 do PDF baixado == file_sha256 do Supabase (5/5)", hashes_ok)
    report.check("Assinatura PAdES do PDF baixado: intact=True e valid=True (5/5)", signatures_ok)
    report.check("PDFs baixados têm 1 página", pages_ok)

    async with httpx.AsyncClient(timeout=60) as web:
        try:
            response = await web.get(issued[0]["presigned_url"])
            ok = response.status_code == 200 and sha256_hex(response.content) == issued[0]["file_sha256"]
            report.check("URL pré-assinada baixa o mesmo PDF", ok, f"HTTP {response.status_code}")
        except httpx.HTTPError as exc:
            report.check("URL pré-assinada baixa o mesmo PDF", False, type(exc).__name__)

    # 6. Compensação storage <-> banco -----------------------------------------------------------------------------------
    print("\n--- Compensação (falhas simuladas no banco) ---")
    repository = app.state.repository

    class DefinitiveFailure:
        async def insert_issued(self, certificate: Any, context: Any) -> None:
            raise PersistenceError("falha simulada: banco rejeitou", definitive=True)

        async def exists(self, cert_id: UUID) -> bool:
            return await repository.exists(cert_id)

        async def record_failure(self, *, context: Any, details: dict[str, Any]) -> None:
            await repository.record_failure(context=context, details=details)

    class CommitThenConnectionLost(DefinitiveFailure):
        async def insert_issued(self, certificate: Any, context: Any) -> None:
            await repository.insert_issued(certificate, context)
            raise PersistenceError("falha simulada: conexão perdida após o commit", definitive=False)

    def sample() -> CertificateRenderData:
        return CertificateRenderData(
            recipient_name="Teste de Compensação", event_name="Smoke Test Compensação",
            workload_hours=Decimal("1"), event_date="2026", extra_metadata=meta,
        )

    context = AuditContext(client_ip_hash=None, user_agent="smoke_step4")
    data_a = sample()
    service_a = BatchIssuanceService(app.state.renderer, app.state.signer, storage, DefinitiveFailure(), concurrency=2, retry_delay_seconds=0.2)
    outcome_a = await service_a.issue_batch([data_a], context=context)
    batch_ids.add(str(outcome_a.batch_id))
    key_a = storage.build_key(data_a.cert_uuid, data_a.issued_at)
    report.check("Falha definitiva no banco: item falhou sem derrubar o lote", outcome_a.failed == 1 and outcome_a.items[0].error_code == "database_failed")
    report.check("Falha definitiva no banco: objeto órfão REMOVIDO do bucket", not await storage.exists(key_a))
    failure_rows = await db.fetch_all(
        "select id from public.certificate_audit_log where certificate_id is null and details->>'batch_id' = $1",
        str(outcome_a.batch_id),
    )
    report.check("Falha registrada na auditoria", len(failure_rows) == 1, str(len(failure_rows)))

    data_b = sample()
    service_b = BatchIssuanceService(app.state.renderer, app.state.signer, storage, CommitThenConnectionLost(), concurrency=2, retry_delay_seconds=0.2)
    outcome_b = await service_b.issue_batch([data_b], context=context)
    batch_ids.add(str(outcome_b.batch_id))
    key_b = storage.build_key(data_b.cert_uuid, data_b.issued_at)
    report.check("Commit confirmado + conexão perdida: certificado reportado como emitido", outcome_b.succeeded == 1)
    report.check("Commit confirmado + conexão perdida: objeto MANTIDO e registro existe", await storage.exists(key_b) and await repository.exists(data_b.cert_uuid))


async def cleanup(app: Any, report: Report, run_id: str, batch_ids: set[str]) -> None:
    print("\n--- Limpeza dos dados de teste ---")
    db, storage = app.state.db, app.state.storage
    rows = await db.fetch_all(
        "select id, storage_key from public.certificates where metadata->>'smoke_test' = $1", run_id
    )
    ids = [row["id"] for row in rows]
    keys = [row["storage_key"] for row in rows]

    delete_failures = 0
    for key in keys:
        try:
            await storage.delete(key)
        except Exception:  # noqa: BLE001
            delete_failures += 1
    report.check(f"Objetos de teste removidos do bucket ({len(keys)})", delete_failures == 0)

    try:
        async with db.transaction() as conn:
            trigger = "certificate_audit_log_no_update_delete"
            await conn.execute(f"alter table public.certificate_audit_log disable trigger {trigger}")
            await conn.execute(
                "delete from public.certificate_audit_log "
                "where certificate_id = any($1::uuid[]) or details->>'batch_id' = any($2::text[])",
                ids, sorted(batch_ids),
            )
            await conn.execute(
                "delete from public.certificates where id = any($1::uuid[]) and metadata->>'smoke_test' = $2",
                ids, run_id,
            )
            await conn.execute(f"alter table public.certificate_audit_log enable trigger {trigger}")
        report.check("Linhas de teste removidas do banco", True)
    except Exception as exc:  # noqa: BLE001
        report.check("Linhas de teste removidas do banco", False, f"{type(exc).__name__}: {exc}")
        print(
            f"        Remova manualmente no SQL Editor (run_id={run_id}): desabilite o trigger "
            "certificate_audit_log_no_update_delete, apague as linhas de auditoria e de "
            "certificates com metadata->>'smoke_test' = run_id e reabilite o trigger."
        )

    left = await db.fetch_one("select count(*) as total from public.certificates where metadata->>'smoke_test' = $1", run_id)
    report.check("Nenhum certificado de teste restante", left is not None and left["total"] == 0)
    gone = True
    for key in keys:
        gone &= not await storage.exists(key)
    report.check("Nenhum objeto de teste restante no bucket", gone)
    trig = await db.fetch_one(
        "select tgenabled::text as state from pg_trigger where tgname = 'certificate_audit_log_no_update_delete'"
    )
    report.check("Trigger append-only da auditoria reabilitado", trig is not None and trig["state"] == "O")


async def main_async() -> int:
    settings = get_settings()
    if settings.issuance_api_key is None:
        print(
            "ISSUANCE_API_KEY não está definida no .env. Gere uma e cole no .env:\n"
            '  python -c "import secrets; print(secrets.token_urlsafe(48))"'
        )
        return 1
    api_key = settings.issuance_api_key.get_secret_value()

    from app.main import app  # importado depois da validação do .env

    report = Report()
    run_id = f"smoke-{uuid4().hex[:12]}"
    batch_ids: set[str] = set()
    before = s3._snapshot(Path.cwd(), ROOT)
    sys.addaudithook(s3._audit_hook)
    s3._audit_active = True
    try:
        async with app.router.lifespan_context(app):
            columns = await app.state.db.fetch_all(
                "select column_name from information_schema.columns "
                "where table_schema = 'public' and table_name = 'certificates' and column_name = 'signer_fingerprint'"
            )
            if not columns:
                print("A migração sql/002_issuance.sql ainda não foi aplicada no Supabase. Execute-a no SQL Editor.")
                return 1
            print(f"run_id: {run_id}\n")
            try:
                await scenario(app, report, api_key, run_id, batch_ids)
            except Exception as exc:  # noqa: BLE001 - o resumo e a limpeza precisam rodar sempre
                report.check("Cenário executado sem exceções", False, f"{type(exc).__name__}: {exc}")
            finally:
                await cleanup(app, report, run_id, batch_ids)
    finally:
        s3._audit_active = False

    after = s3._snapshot(Path.cwd(), ROOT)
    print()
    report.check("Nenhuma escrita/arquivo temporário detectado (auditoria do Python)", not s3._disk_events, "; ".join(s3._disk_events[:3]))
    report.check("Nenhum arquivo novo no diretório do projeto", after == before, ", ".join(sorted(after - before)[:3]))

    print("\n" + ("Etapa 4 validada." if report.failures == 0 else f"{report.failures} verificação(ões) falharam."))
    return 0 if report.failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main_async()))
