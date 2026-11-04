"""Smoke test da Etapa 1: valida configuração, banco e object storage.

Uso (na raiz do projeto, com .env preenchido):
    python scripts/smoke_step1.py

O teste de storage envia um objeto minúsculo a partir de um BytesIO, gera a URL
pré-assinada, confirma a existência e remove o objeto em seguida.
"""

from __future__ import annotations

import asyncio
import io
import sys
from pathlib import Path
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.config import get_settings  # noqa: E402
from app.services.database import Database, DatabaseError  # noqa: E402
from app.services.storage import ObjectStorage, StorageError  # noqa: E402


async def check_database() -> bool:
    db = Database()
    try:
        await db.connect()
        ok = await db.healthcheck()
        row = await db.fetch_one("select count(*) as total from public.certificates")
        total = row["total"] if row else "?"
        print(f"[db]      healthcheck={ok} | certificados na tabela={total}")
        return ok
    except DatabaseError as exc:
        print(f"[db]      FALHA: {exc}")
        return False
    except Exception as exc:  # noqa: BLE001 - relatório de diagnóstico
        print(f"[db]      FALHA ({type(exc).__name__}): {exc}")
        return False
    finally:
        await db.close()


async def check_storage() -> bool:
    storage = ObjectStorage()
    key = f"smoke-tests/{uuid4()}.pdf"
    try:
        print(f"[storage] bucket acessível={await storage.healthcheck()}")
        payload = io.BytesIO(b"%PDF-1.4\n% smoke test\n%%EOF\n")
        await storage.upload_pdf(key, payload, sha256="0" * 64)
        existed = await storage.exists(key)
        url = storage.presign_get(key, expires_in=60, download_filename="smoke.pdf")
        print(f"[storage] upload ok | exists={existed} | presigned_url gerada={url.startswith('http')}")
        return existed
    except StorageError as exc:
        print(f"[storage] FALHA: {exc} ({exc.__cause__})")
        return False
    except Exception as exc:  # noqa: BLE001 - relatório de diagnóstico
        print(f"[storage] FALHA ({type(exc).__name__}): {exc}")
        return False
    finally:
        try:
            await storage.delete(key)
        except StorageError:
            pass


async def main() -> int:
    settings = get_settings()
    print(f"[config]  ambiente={settings.app_env} | bucket={settings.s3_bucket} | qr_base={settings.public_validation_base_url}")
    results = await asyncio.gather(check_database(), check_storage())
    return 0 if all(results) else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
