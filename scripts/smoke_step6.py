"""Smoke test da Etapa 6 (final): auditoria do repositório e prontidão para ``git push``.

Uso (na raiz do projeto):
    python scripts/smoke_step6.py

Verifica, sem rede, sem banco e sem segredos reais:
  1. Arquivos de infraestrutura, CI/CD, frontend e documentação existem e têm conteúdo.
  2. Varredura recursiva: nenhum arquivo proibido (.pfx/.p12/.pem/.key/.pdf/.env) em disco
     fora do que o .gitignore protege; ``git ls-files`` (se houver git) não lista nenhum.
  3. ``httpx.AsyncClient`` sobre a própria aplicação ASGI: /healthz e cabeçalhos do CORSMiddleware.
  4. Relatório final e código de saída 0 somente se tudo passou.
"""

from __future__ import annotations

import asyncio
import base64
import fnmatch
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

IGNORED_DIRS = {".git", ".venv", "venv", "node_modules", ".next", "__pycache__", ".ruff_cache", ".pytest_cache"}
FORBIDDEN_PATTERNS = ("*.pfx", "*.p12", "*.pem", "*.key", "*.pdf", ".env", ".env.*")
ALLOWED_FORBIDDEN_NAMES = {".env.example"}
GITIGNORE_REQUIRED = ("*.pfx", "*.p12", "*.pem", "*.key", "*.pdf", ".env", "node_modules/", ".next/")
DEV_ORIGIN = "http://localhost:3000"
FOREIGN_ORIGIN = "https://evil.example"

# arquivo -> trechos que precisam aparecer (sanidade de conteúdo, não só existência)
REQUIRED_FILES: dict[str, tuple[str, ...]] = {
    "Dockerfile": ("python:", "USER appuser", "HEALTHCHECK", "PYTHONDONTWRITEBYTECODE=1", "${PORT"),
    ".dockerignore": (".git", ".env", "*.pfx", "*.p12", "*.pem", "*.key", "__pycache__", "frontend"),
    ".github/workflows/ci.yml": ("pull_request", "ruff", "generate_dev_cert.py", "smoke_step2.py", "docker"),
    "README.md": ("```mermaid", "CORS_ORIGINS", "Cloud Run", "Vercel", "smoke_step6.py"),
    ".env.example": ("CORS_ORIGINS",),
    "requirements.txt": ("fastapi", "pyhanko"),
    "frontend/package.json": ('"next"', '"tailwindcss"', '"typescript"'),
    "frontend/.env.example": ("NEXT_PUBLIC_API_BASE_URL",),
    "frontend/next.config.mjs": ("Content-Security-Policy",),
    "frontend/src/app/page.tsx": ("VerifyPortal",),
    "frontend/src/app/validar/[uuid]/page.tsx": ("CodeResult",),
    "frontend/src/components/FileDropzone.tsx": ("onDrop",),
    "frontend/src/components/FileVerifier.tsx": ("validateFile",),
    "frontend/src/components/CryptoReport.tsx": ("intact", "trusted"),
    "frontend/src/components/TamperAlert.tsx": ("INVALID_TAMPERED",),
    "frontend/src/components/CodeResult.tsx": ("validateByCode",),
    "frontend/src/lib/api.ts": ("/api/v1/validate",),
}

# arquivos do README que precisam citar cada smoke test
SMOKE_SCRIPTS = tuple(f"scripts/smoke_step{n}.py" for n in range(1, 7))


@dataclass
class Report:
    passed: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)

    def check(self, ok: bool, label: str, detail: str = "") -> bool:
        line = f"{label}" + (f" — {detail}" if detail and not ok else "")
        (self.passed if ok else self.failed).append(line)
        print(f"  [{'OK' if ok else 'FALHOU'}] {line}")
        return ok


def section(title: str) -> None:
    print(f"\n== {title}")


# --- 1. Arquivos -------------------------------------------------------------------
def check_required_files(report: Report) -> None:
    section("1. Infraestrutura, CI/CD, frontend e documentação")
    for relative, needles in REQUIRED_FILES.items():
        path = ROOT / relative
        if not path.is_file():
            report.check(False, relative, "arquivo ausente")
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if not text.strip():
            report.check(False, relative, "arquivo vazio")
            continue
        missing = [needle for needle in needles if needle not in text]
        report.check(not missing, f"{relative} ({len(text):,} caracteres)", f"faltam trechos: {missing}")

    for relative in SMOKE_SCRIPTS:
        report.check((ROOT / relative).is_file(), relative, "script ausente")
    readme = (ROOT / "README.md").read_text(encoding="utf-8", errors="replace") if (ROOT / "README.md").is_file() else ""
    uncited = [name for name in SMOKE_SCRIPTS if Path(name).name not in readme]
    report.check(not uncited, "README cita smoke_step1..6", f"não citados: {uncited}")

    package = ROOT / "frontend" / "package.json"
    if package.is_file():
        try:
            data = json.loads(package.read_text(encoding="utf-8"))
            scripts = data.get("scripts", {})
            report.check(
                all(key in scripts for key in ("dev", "build", "typecheck")),
                "frontend/package.json válido com scripts dev/build/typecheck",
            )
        except json.JSONDecodeError as exc:
            report.check(False, "frontend/package.json é JSON válido", str(exc))


# --- 2. Varredura de segurança ------------------------------------------------------
def walk_files() -> list[Path]:
    found: list[Path] = []
    for current, dirs, files in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]
        found.extend(Path(current) / name for name in files)
    return found


def is_forbidden(name: str) -> bool:
    lowered = name.lower()
    return lowered not in ALLOWED_FORBIDDEN_NAMES and any(fnmatch.fnmatch(lowered, p) for p in FORBIDDEN_PATTERNS)


def git_output(*args: str) -> str | None:
    if not shutil.which("git") or not (ROOT / ".git").exists():
        return None
    try:
        done = subprocess.run(  # noqa: S603 - argumentos fixos, sem entrada externa
            ["git", *args], cwd=ROOT, capture_output=True, text=True, timeout=30, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return done.stdout if done.returncode == 0 else None


def is_ignored(relative: str, gitignore_lines: set[str]) -> bool:
    """Usa o git quando há repositório; senão, confere os padrões do .gitignore."""
    if (ROOT / ".git").exists() and shutil.which("git"):
        code = subprocess.run(  # noqa: S603 - argumentos fixos
            ["git", "check-ignore", "-q", relative], cwd=ROOT, check=False, capture_output=True
        ).returncode
        return code == 0
    name = Path(relative).name
    return any(fnmatch.fnmatch(name, pattern) for pattern in gitignore_lines if pattern and not pattern.startswith(("#", "!")))


def check_security_scan(report: Report) -> None:
    section("2. Varredura de segurança do repositório")
    gitignore = ROOT / ".gitignore"
    lines = {ln.strip() for ln in gitignore.read_text(encoding="utf-8").splitlines()} if gitignore.is_file() else set()
    missing = [p for p in GITIGNORE_REQUIRED if p not in lines]
    report.check(not missing, ".gitignore protege chaves, certificados, PDFs e .env", f"faltam: {missing}")

    on_disk = [p for p in walk_files() if is_forbidden(p.name)]
    if not on_disk:
        report.check(True, "nenhum arquivo proibido no disco (varredura recursiva)")
    else:
        # Presentes no disco só são aceitáveis se o git os ignora (ex.: seu .env local).
        for path in on_disk:
            relative = path.relative_to(ROOT).as_posix()
            ignored = is_ignored(relative, lines)
            report.check(ignored, f"arquivo sensível local protegido pelo .gitignore: {relative}", "NÃO está ignorado!")

    tracked = git_output("ls-files")
    if tracked is None:
        print("  [--] repositório git não inicializado: pulei a checagem de `git ls-files`")
    else:
        bad = [f for f in tracked.splitlines() if is_forbidden(Path(f).name)]
        report.check(not bad, "git ls-files não lista arquivo proibido", f"versionados: {bad}")

    private_marker = re.compile("-----BEGIN (?:[A-Z]+ )?PRIVATE " + "KEY-----")
    leaks: list[str] = []
    for path in walk_files():
        if path.suffix.lower() in {".py", ".md", ".yml", ".yaml", ".json", ".txt", ".ts", ".tsx", ".mjs", ".sql"} or (
            path.name.startswith(".env") and path.name in ALLOWED_FORBIDDEN_NAMES
        ):
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if private_marker.search(text) or re.search(r"SIGNING_PFX_BASE64=[A-Za-z0-9+/]{100,}", text):
                leaks.append(path.relative_to(ROOT).as_posix())
    report.check(not leaks, "nenhuma chave privada ou PFX embutido no texto dos arquivos", f"suspeitos: {leaks}")


# --- 3. HTTP / CORS -----------------------------------------------------------------
def _prepare_environment() -> None:
    """Valores neutros só para instanciar a aplicação; não usados para conectar a nada."""
    defaults = {
        "APP_ENV": "development",
        "PUBLIC_VALIDATION_BASE_URL": "http://localhost:3000/validar",
        "DATABASE_URL": "postgresql://user:pass@127.0.0.1:5432/smoke",
        "DB_SSL": "disable",
        "S3_ENDPOINT_URL": "http://127.0.0.1:9000",
        "S3_ACCESS_KEY_ID": "smoke-access-key",
        "S3_SECRET_ACCESS_KEY": "smoke-secret-key",
        "S3_BUCKET": "smoke-bucket",
        "SIGNING_PFX_BASE64": base64.b64encode(b"not-a-real-pfx").decode("ascii"),
        "SIGNING_PFX_PASSWORD": "smoke",
        "ISSUANCE_API_KEY": "smoke-only-api-key-0123456789abcdef0123456789",
        "CORS_ORIGINS": DEV_ORIGIN,
    }
    for key, value in defaults.items():
        os.environ.setdefault(key, value)


async def check_http(report: Report) -> None:
    section("3. Healthcheck e CORS (httpx.AsyncClient sobre a aplicação ASGI)")
    try:
        import httpx

        from app.core.config import get_settings
        from app.main import create_app
    except Exception as exc:  # noqa: BLE001 - qualquer falha de import precisa aparecer no relatório
        report.check(False, "importar a aplicação FastAPI e o httpx", f"{type(exc).__name__}: {exc}")
        return

    settings = get_settings()
    origins = list(settings.allowed_origins)
    report.check(bool(origins), f"CORS_ORIGINS resolvido: {origins}")
    report.check("*" not in origins, "CORS nunca usa curinga '*'")
    if not origins:
        return
    allowed = origins[0]

    # Sem lifespan: o healthcheck é liveness puro e não exige banco nem S3.
    transport = httpx.ASGITransport(app=create_app(settings))
    async with httpx.AsyncClient(transport=transport, base_url="http://smoke.local") as client:
        health = await client.get("/healthz")
        report.check(health.status_code == 200, "GET /healthz responde 200", f"status {health.status_code}")
        report.check(health.json() == {"status": "ok"}, "corpo do /healthz é {'status': 'ok'}", str(health.text))

        preflight = await client.options(
            "/api/v1/validate/file",
            headers={
                "Origin": allowed,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type",
            },
        )
        report.check(preflight.status_code == 200, "preflight OPTIONS aceito", f"status {preflight.status_code}")
        report.check(
            preflight.headers.get("access-control-allow-origin") == allowed,
            "preflight devolve Access-Control-Allow-Origin da origem permitida",
            str(preflight.headers.get("access-control-allow-origin")),
        )
        report.check(
            "POST" in preflight.headers.get("access-control-allow-methods", ""),
            "preflight libera o método POST",
        )
        report.check(
            "access-control-allow-credentials" not in preflight.headers,
            "preflight não habilita credenciais (API pública sem cookies)",
        )

        simple = await client.get("/healthz", headers={"Origin": allowed})
        report.check(
            simple.headers.get("access-control-allow-origin") == allowed,
            "requisição simples com Origin permitida recebe Allow-Origin",
        )

        foreign_pre = await client.options(
            "/api/v1/validate/file",
            headers={
                "Origin": FOREIGN_ORIGIN,
                "Access-Control-Request-Method": "POST",
            },
        )
        report.check(
            "access-control-allow-origin" not in foreign_pre.headers,
            "origem desconhecida NÃO recebe Allow-Origin no preflight",
        )
        foreign = await client.get("/healthz", headers={"Origin": FOREIGN_ORIGIN})
        report.check(
            "access-control-allow-origin" not in foreign.headers,
            "origem desconhecida NÃO recebe Allow-Origin em requisição simples",
        )


# --- 4. Relatório ---------------------------------------------------------------------
def print_final(report: Report) -> int:
    total = len(report.passed) + len(report.failed)
    print("\n" + "=" * 64)
    print(f"RELATÓRIO FINAL DE PRONTIDÃO: {len(report.passed)}/{total} verificações OK")
    if report.failed:
        print("\nCorrija antes do `git push`:")
        for item in report.failed:
            print(f"  - {item}")
        print("=" * 64)
        return 1
    print("\nEtapa 6 validada. O repositório está pronto para `git push`.")
    print("Antes de enviar, confirme: `git status --short` não pode listar .env, *.pfx, *.pem, *.key nem *.pdf.")
    print("=" * 64)
    return 0


def main() -> int:
    print("Smoke test da Etapa 6: auditoria final do repositório")
    _prepare_environment()
    report = Report()
    check_required_files(report)
    check_security_scan(report)
    asyncio.run(check_http(report))
    return print_final(report)


if __name__ == "__main__":
    raise SystemExit(main())
