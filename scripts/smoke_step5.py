"""Smoke test E2E ANTI-FRAUDE da Etapa 5: validação pública (QR/UUID e upload), perícia PAdES e revogação.

Uso (na raiz do projeto, com .env completo, incluindo ISSUANCE_API_KEY):
    python scripts/smoke_step5.py

ATENÇÃO: usa o banco e o bucket REAIS do .env. O certificado de teste leva a marca
``metadata.smoke_test = <run_id>`` e tudo é removido ao final. A auditoria é append-only
(triggers): a limpeza desabilita UM trigger dentro de uma única transação, apaga somente as
linhas desta execução (por certificado, lote, hash de arquivo ou UUID usados no teste) e o
reabilita antes do commit. Isso exige a conexão do dono das tabelas (usuário ``postgres``).

Cenários (tudo em memória, sem arquivos temporários):
    0. Emissão base de 1 certificado (via POST /batch)
    1. Consulta por UUID / QR Code (VALID, CPF mascarado, URL pré-assinada, auditoria)
    2. Upload do PDF autêntico (VALID, intact/valid/trusted)
    3. Adulteração: 1 byte alterado no trecho assinado e bytes anexados ao final
    4. PDF renderizado SEM assinatura (INVALID_SIGNATURE)
    5. Revogação: consulta por UUID e upload passam a responder REVOKED

Retorna código de saída 0 somente se todas as verificações passarem.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import sys
from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import UUID, uuid1, uuid4

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import httpx  # noqa: E402
import smoke_step3 as s3  # noqa: E402
from smoke_step2 import Report  # noqa: E402

from app.core.config import get_settings  # noqa: E402

BATCH_URL = "/api/v1/certificates/batch"
VALIDATE_URL = "/api/v1/validate"
FILE_URL = "/api/v1/validate/file"
RAW_CPF = "123.456.789-09"
MASKED_CPF = "***.456.789-**"
REVOKE_REASON = "Smoke test: revogação de teste (dado fictício)"
_BYTE_RANGE_RE = re.compile(rb"/ByteRange\s*\[\s*0\s+(\d+)\s+(\d+)\s+(\d+)\s*\]")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tamper_in_place(pdf: bytes) -> tuple[bytes, str]:
    """Altera 1 byte dentro do trecho ASSINADO, mantendo o PDF legível (troca o último caractere
    de uma string de metadados, ex.: o produtor ReportLab). O resultado tem o mesmo tamanho."""
    match = _BYTE_RANGE_RE.search(pdf)
    signed_end = int(match.group(1)) if match else len(pdf) // 2
    altered = bytearray(pdf)
    for token in (b"ReportLab", b"anonymous", b"Producer"):
        index = pdf.find(token, 0, signed_end)
        if index != -1:
            position = index + len(token) - 1
            altered[position] ^= 0x01
            return bytes(altered), f"byte {position} (fim de {token.decode()!r})"
    position = max(signed_end // 2, 1)
    altered[position] ^= 0x01
    return bytes(altered), f"byte {position} (meio do trecho assinado)"


def append_bytes(pdf: bytes) -> bytes:
    return pdf + b"\n% conteudo espurio anexado depois da assinatura\n"


def body(response: httpx.Response) -> dict[str, Any]:
    try:
        data = response.json()
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def brief(response: httpx.Response) -> str:
    data = body(response)
    crypto = data.get("crypto") or {}
    return (
        f"HTTP {response.status_code} status={data.get('status')} intact={crypto.get('intact')} "
        f"valid={crypto.get('valid')} trusted={crypto.get('trusted')} "
        f"hash={crypto.get('hash_matches_record')} sigs={crypto.get('signature_count')} "
        f"findings={crypto.get('findings')}"
    )


async def post_file(client: httpx.AsyncClient, data: bytes, name: str = "certificado.pdf") -> httpx.Response:
    return await client.post(FILE_URL, files={"file": (name, data, "application/pdf")})


async def scenario(
    app: Any,
    report: Report,
    api_key: str,
    run_id: str,
    batch_ids: set[str],
    tracked_shas: set[str],
    tracked_uuids: set[str],
) -> None:
    from app.schemas.certificate import CertificateRenderData

    settings = get_settings()
    db, storage = app.state.db, app.state.storage
    key_header = {"X-API-Key": api_key}
    meta = {"smoke_test": run_id}

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver", timeout=180) as client:
        # ------------------------------------------------------------------ 0. emissão base
        print("--- Cenário 0: emissão base ---")
        payload = {
            "event": {
                "event_name": "Smoke Test — Validação Pública",
                "event_date": "2026-11-10",
                "workload_hours": "8",
                "default_role": "Participante",
            },
            "participants": [
                {"recipient_name": "Maria Clara Teixeira Souza", "recipient_doc": RAW_CPF, "extra_metadata": meta}
            ],
        }
        r = await client.post(BATCH_URL, json=payload, headers=key_header)
        data = body(r)
        if data.get("batch_id"):
            batch_ids.add(data["batch_id"])
        issued = [x for x in data.get("results", []) if x.get("status") == "issued"]
        if not report.check("Emissão de 1 certificado válido via lote", r.status_code == 201 and len(issued) == 1, brief(r)):
            return
        cert_uuid: str = issued[0]["cert_uuid"]
        cert_sha: str = issued[0]["file_sha256"]
        storage_key: str = issued[0]["storage_key"]
        tracked_uuids.add(cert_uuid)
        authentic = await storage.download(storage_key)
        report.check("PDF autêntico baixado do bucket para a RAM (hash confere)", sha256_hex(authentic) == cert_sha)

        # ------------------------------------------------------------------ 1. consulta por UUID
        print("\n--- Cenário 1: consulta por UUID / QR Code (rota pública, sem X-API-Key) ---")
        r = await client.get(f"{VALIDATE_URL}/{cert_uuid}")
        data = body(r)
        cert = data.get("certificate") or {}
        download = data.get("download") or {}
        report.check("GET /validate/{uuid} -> 200 com status=VALID", r.status_code == 200 and data.get("status") == "VALID", brief(r))
        report.check("Documento mascarado pela LGPD (***.456.789-**)", cert.get("recipient_doc") == MASKED_CPF, str(cert.get("recipient_doc")))
        report.check(
            "Resposta NÃO contém o CPF completo",
            RAW_CPF not in r.text and "12345678909" not in r.text and "123.456.789" not in r.text,
        )
        report.check("Metadados públicos (nome, evento, file_sha256 original)", (
            cert.get("recipient_name") == "Maria Clara Teixeira Souza"
            and cert.get("event_name") == "Smoke Test — Validação Pública"
            and cert.get("file_sha256") == cert_sha and cert.get("revoked") is False))
        report.check("Presigned URL presente com validade de 900 s", bool(download.get("url")) and download.get("expires_in_seconds") == 900, str(download.get("expires_in_seconds")))
        report.check("Resposta com Cache-Control: no-store", r.headers.get("cache-control") == "no-store")
        report.check("Resposta não vaza motivo de revogação nem CN do assinante", "revoked_reason" not in r.text and "subject" not in r.text)
        async with httpx.AsyncClient(timeout=60) as web:
            try:
                downloaded = await web.get(download["url"])
                report.check(
                    "Presigned URL baixa o PDF original (hash idêntico)",
                    downloaded.status_code == 200 and sha256_hex(downloaded.content) == cert_sha,
                    f"HTTP {downloaded.status_code}",
                )
            except (httpx.HTTPError, KeyError) as exc:
                report.check("Presigned URL baixa o PDF original (hash idêntico)", False, type(exc).__name__)

        missing = str(uuid4())
        tracked_uuids.add(missing)
        r = await client.get(f"{VALIDATE_URL}/{missing}")
        report.check("UUID inexistente -> 404 com status=NOT_FOUND", r.status_code == 404 and body(r).get("status") == "NOT_FOUND", brief(r))
        r = await client.get(f"{VALIDATE_URL}/nao-e-um-uuid")
        report.check("Código malformado -> 404 NOT_FOUND (sem consultar o banco)", r.status_code == 404 and body(r).get("status") == "NOT_FOUND")
        r = await client.get(f"{VALIDATE_URL}/{uuid1()}")
        report.check("UUID que não é v4 -> 404 NOT_FOUND", r.status_code == 404 and body(r).get("status") == "NOT_FOUND")

        rows = await db.fetch_all(
            "select action, outcome from public.certificate_audit_log "
            "where certificate_id = $1::uuid and action in ('validate_code', 'presigned_url')", UUID(cert_uuid))
        actions = sorted((row["action"], row["outcome"]) for row in rows)
        report.check("Auditoria: validate_code + presigned_url gravados", actions == [("presigned_url", "success"), ("validate_code", "success")], str(actions))
        miss_rows = await db.fetch_all(
            "select outcome from public.certificate_audit_log "
            "where action = 'validate_code' and certificate_id is null and details->>'cert_uuid' = $1", missing)
        report.check("Auditoria: consulta de UUID inexistente registrada (not_found)", [row["outcome"] for row in miss_rows] == ["not_found"])

        # ------------------------------------------------------------------ 2. upload autêntico
        print("\n--- Cenário 2: upload do PDF autêntico ---")
        r = await post_file(client, authentic)
        data = body(r)
        crypto = data.get("crypto") or {}
        report.check("POST /validate/file (autêntico) -> status=VALID", r.status_code == 200 and data.get("status") == "VALID", brief(r))
        report.check("Perícia: intact=True, valid=True, trusted=True", crypto.get("intact") is True and crypto.get("valid") is True and crypto.get("trusted") is True, brief(r))
        report.check("Hash do arquivo consta no banco e o assinante confere", crypto.get("hash_matches_record") is True and crypto.get("signer_matches_record") is True)
        report.check("Assinatura cobre o arquivo inteiro (nada após ela)", crypto.get("covers_entire_file") is True)
        report.check("Certificado identificado pelo hash (UUID e CPF mascarado)", (data.get("certificate") or {}).get("cert_uuid") == cert_uuid and RAW_CPF not in r.text)
        report.check("Hash devolvido == SHA-256 enviado", data.get("file_sha256") == cert_sha and data.get("file_size_bytes") == len(authentic))
        valid_rows = await db.fetch_all(
            "select outcome from public.certificate_audit_log where certificate_id = $1::uuid and action = 'validate_file'", UUID(cert_uuid))
        report.check("Auditoria: validate_file (success) gravado", [row["outcome"] for row in valid_rows] == ["success"])

        # ------------------------------------------------------------------ 3. adulteração
        print("\n--- Cenário 3: detecção de fraude / adulteração binária ---")
        altered, where = tamper_in_place(authentic)
        tracked_shas.add(sha256_hex(altered))
        r = await post_file(client, altered)
        data = body(r)
        crypto = data.get("crypto") or {}
        print(f"        1 byte alterado em {where}")
        report.check(
            "1 byte alterado no trecho assinado: fraude detectada (nunca VALID)",
            r.status_code == 200 and data.get("status") in ("INVALID_TAMPERED", "INVALID_SIGNATURE")
            and crypto.get("hash_matches_record") is False and data.get("certificate") is None,
            brief(r),
        )
        report.check("1 byte alterado: INVALID_TAMPERED com intact=False", data.get("status") == "INVALID_TAMPERED" and crypto.get("intact") is False, brief(r))

        appended = append_bytes(authentic)
        tracked_shas.add(sha256_hex(appended))
        r = await post_file(client, appended)
        data = body(r)
        crypto = data.get("crypto") or {}
        report.check(
            "Bytes anexados após a assinatura: fraude detectada (nunca VALID)",
            r.status_code == 200 and data.get("status") in ("INVALID_TAMPERED", "INVALID_SIGNATURE")
            and crypto.get("hash_matches_record") is False and data.get("certificate") is None,
            brief(r),
        )
        report.check("Bytes anexados: INVALID_TAMPERED (assinatura boa, hash divergente)", data.get("status") == "INVALID_TAMPERED", brief(r))

        # ------------------------------------------------------------------ 4. sem assinatura
        print("\n--- Cenário 4: PDF sem assinatura digital ---")
        unsigned = (await app.state.renderer.render_async(CertificateRenderData(
            recipient_name="Fulano Sem Assinatura", event_name="Smoke Test Sem Assinatura",
            workload_hours=Decimal("1"), event_date="2026", extra_metadata=meta,
        ))).getvalue()
        tracked_shas.add(sha256_hex(unsigned))
        r = await post_file(client, unsigned)
        data = body(r)
        crypto = data.get("crypto") or {}
        report.check("PDF renderizado e NÃO assinado -> INVALID_SIGNATURE", r.status_code == 200 and data.get("status") == "INVALID_SIGNATURE", brief(r))
        report.check("Relatório: 0 assinaturas e hash desconhecido", crypto.get("signature_count") == 0 and crypto.get("hash_matches_record") is False)

        # ------------------------------------------------------------------ 4b. limites do upload
        print("\n--- Limites e validações do upload ---")
        r = await post_file(client, b"isto nao e um pdf", "x.pdf")
        report.check("Arquivo sem cabeçalho %PDF- -> 415", r.status_code == 415, str(r.status_code))
        r = await post_file(client, b"", "vazio.pdf")
        report.check("Arquivo vazio -> 422", r.status_code == 422, str(r.status_code))
        r = await client.post(FILE_URL, data={"x": "1"})
        report.check("Campo 'file' ausente -> 422", r.status_code == 422, str(r.status_code))
        oversize = b"%PDF-" + b"0" * (settings.validation_max_upload_bytes + 10_000)
        r = await post_file(client, oversize, "grande.pdf")
        report.check("Upload acima do limite -> 413 (barrado antes da leitura)", r.status_code == 413, str(r.status_code))

        # ------------------------------------------------------------------ 5. revogação
        print("\n--- Cenário 5: ciclo de vida (revogação) ---")
        revoke_url = f"/api/v1/certificates/{cert_uuid}/revoke"
        r = await client.post(revoke_url, json={"reason": REVOKE_REASON})
        report.check("Revogar sem X-API-Key -> 401", r.status_code == 401, str(r.status_code))
        wrong = api_key[:-1] + ("A" if api_key[-1] != "A" else "B")
        r = await client.post(revoke_url, json={"reason": REVOKE_REASON}, headers={"X-API-Key": wrong})
        report.check("Revogar com chave errada -> 401", r.status_code == 401, str(r.status_code))
        r = await client.post(revoke_url, json={"reason": "x"}, headers=key_header)
        report.check("Motivo curto demais -> 422", r.status_code == 422, str(r.status_code))
        unknown = str(uuid4())
        tracked_uuids.add(unknown)
        r = await client.post(f"/api/v1/certificates/{unknown}/revoke", json={"reason": REVOKE_REASON}, headers=key_header)
        report.check("Revogar certificado inexistente -> 404", r.status_code == 404, str(r.status_code))
        still = await db.fetch_one("select status::text as s from public.certificates where id = $1::uuid", UUID(cert_uuid))
        report.check("Tentativas rejeitadas não alteraram o certificado", still is not None and still["s"] == "valid")

        r = await client.post(revoke_url, json={"reason": REVOKE_REASON}, headers=key_header)
        data = body(r)
        report.check("Revogar com X-API-Key -> 200", r.status_code == 200 and data.get("status") == "revoked" and bool(data.get("revoked_at")), f"{r.status_code} {r.text[:150]}")
        row = await db.fetch_one(
            "select status::text as s, revoked_at, revoked_reason from public.certificates where id = $1::uuid", UUID(cert_uuid))
        report.check("Banco: status=revoked, revoked_at e motivo gravados", row is not None and row["s"] == "revoked" and row["revoked_at"] is not None and row["revoked_reason"] == REVOKE_REASON)
        r = await client.post(revoke_url, json={"reason": REVOKE_REASON}, headers=key_header)
        report.check("Revogar de novo -> 409", r.status_code == 409, str(r.status_code))

        r = await client.get(f"{VALIDATE_URL}/{cert_uuid}")
        data = body(r)
        report.check("Consulta por UUID após revogar -> status=REVOKED", r.status_code == 200 and data.get("status") == "REVOKED", brief(r))
        report.check("REVOKED: sem URL de download e com revoked=true", data.get("download") is None and (data.get("certificate") or {}).get("revoked") is True)
        report.check("REVOKED: motivo interno NÃO é exposto publicamente", REVOKE_REASON not in r.text and "Smoke test: revoga" not in r.text)

        r = await post_file(client, authentic)
        data = body(r)
        crypto = data.get("crypto") or {}
        report.check("Upload do arquivo autêntico após revogar -> status=REVOKED", r.status_code == 200 and data.get("status") == "REVOKED", brief(r))
        report.check("REVOKED: assinatura segue íntegra e confiável (só o registro mudou)", crypto.get("intact") is True and crypto.get("trusted") is True)

        revoked_rows = await db.fetch_all(
            "select outcome from public.certificate_audit_log where action = 'revoked' and "
            "(certificate_id = $1::uuid or details->>'cert_uuid' = any($2::text[]))", UUID(cert_uuid), [cert_uuid, unknown])
        outcomes = sorted(row["outcome"] for row in revoked_rows)
        report.check("Auditoria da revogação: success, invalid (409) e not_found (404)", outcomes == ["invalid", "not_found", "success"], str(outcomes))
        reason_leak = await db.fetch_one(
            "select count(*) as n from public.certificate_audit_log where certificate_id = $1::uuid and details::text like $2", UUID(cert_uuid), "%Smoke test: revoga%")
        report.check("Auditoria não guarda o texto livre do motivo (LGPD)", reason_leak is not None and reason_leak["n"] == 0)


async def cleanup(
    app: Any, report: Report, run_id: str, batch_ids: set[str], tracked_shas: set[str], tracked_uuids: set[str]
) -> None:
    print("\n--- Limpeza dos dados de teste ---")
    db, storage = app.state.db, app.state.storage
    rows = await db.fetch_all(
        "select id, storage_key from public.certificates where metadata->>'smoke_test' = $1", run_id)
    ids = [row["id"] for row in rows]
    keys = [row["storage_key"] for row in rows]
    uuids = sorted(tracked_uuids | {str(i) for i in ids})
    shas = sorted(tracked_shas)

    delete_failures = 0
    for key in keys:
        try:
            await storage.delete(key)
        except Exception:  # noqa: BLE001
            delete_failures += 1
    report.check(f"Objetos de teste removidos do bucket ({len(keys)})", delete_failures == 0)

    match_audit = (
        "certificate_id = any($1::uuid[]) or details->>'batch_id' = any($2::text[]) "
        "or details->>'file_sha256' = any($3::text[]) or details->>'cert_uuid' = any($4::text[])"
    )
    try:
        async with db.transaction() as conn:
            trigger = "certificate_audit_log_no_update_delete"
            await conn.execute(f"alter table public.certificate_audit_log disable trigger {trigger}")
            await conn.execute(
                f"delete from public.certificate_audit_log where {match_audit}", ids, sorted(batch_ids), shas, uuids)
            await conn.execute(
                "delete from public.certificates where id = any($1::uuid[]) and metadata->>'smoke_test' = $2", ids, run_id)
            await conn.execute(f"alter table public.certificate_audit_log enable trigger {trigger}")
        report.check("Linhas de teste removidas do banco (certificados e auditoria)", True)
    except Exception as exc:  # noqa: BLE001
        report.check("Linhas de teste removidas do banco", False, f"{type(exc).__name__}: {exc}")
        print(
            f"        Remova manualmente no SQL Editor (run_id={run_id}): desabilite o trigger "
            "certificate_audit_log_no_update_delete, apague as linhas de auditoria e de "
            "certificates com metadata->>'smoke_test' = run_id e reabilite o trigger."
        )

    left = await db.fetch_one(
        "select count(*) as total from public.certificates where metadata->>'smoke_test' = $1", run_id)
    report.check("Nenhum certificado de teste restante", left is not None and left["total"] == 0)
    audit_left = await db.fetch_one(
        f"select count(*) as total from public.certificate_audit_log where {match_audit}", ids, sorted(batch_ids), shas, uuids)
    report.check("Nenhum registro de auditoria de teste restante", audit_left is not None and audit_left["total"] == 0)
    gone = True
    for key in keys:
        gone &= not await storage.exists(key)
    report.check("Nenhum objeto de teste restante no bucket", gone)
    trig = await db.fetch_one(
        "select tgenabled::text as state from pg_trigger where tgname = 'certificate_audit_log_no_update_delete'")
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
    tracked_shas: set[str] = set()
    tracked_uuids: set[str] = set()
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
                await scenario(app, report, api_key, run_id, batch_ids, tracked_shas, tracked_uuids)
            except Exception as exc:  # noqa: BLE001 - o resumo e a limpeza precisam rodar sempre
                report.check("Cenário executado sem exceções", False, f"{type(exc).__name__}: {exc}")
            finally:
                await cleanup(app, report, run_id, batch_ids, tracked_shas, tracked_uuids)
    finally:
        s3._audit_active = False

    after = s3._snapshot(Path.cwd(), ROOT)
    print()
    report.check("Nenhuma escrita/arquivo temporário detectado (auditoria do Python)", not s3._disk_events, "; ".join(s3._disk_events[:3]))
    report.check("Nenhum arquivo novo no diretório do projeto", after == before, ", ".join(sorted(after - before)[:3]))

    print("\n" + ("Etapa 5 validada." if report.failures == 0 else f"{report.failures} verificação(ões) falharam."))
    return 0 if report.failures == 0 else 1


def main() -> int:
    return asyncio.run(main_async())


if __name__ == "__main__":
    sys.exit(main())
