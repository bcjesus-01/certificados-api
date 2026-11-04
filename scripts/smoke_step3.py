"""Smoke test da Etapa 3: QR Code + renderização do certificado + assinatura PAdES.

Uso (na raiz do projeto):
    python scripts/smoke_step3.py                 # certificado A1 e URL base do .env
    python scripts/smoke_step3.py --ephemeral     # certificado efêmero (CI, sem .env)
    python scripts/smoke_step3.py --out teste.pdf # opcional: grava o PDF assinado p/ inspeção visual

Tudo ocorre em RAM. Um gancho de auditoria do Python registra qualquer abertura de
arquivo para escrita ou criação de temporários durante a renderização e a assinatura.
Retorna código de saída 0 somente se todas as verificações passarem.
"""

from __future__ import annotations

import argparse
import asyncio
import io
import os
import re
import sys
from decimal import Decimal
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from smoke_step2 import Report, load_credentials, validate  # noqa: E402

from app.crypto.credentials import SigningCredentials  # noqa: E402
from app.crypto.pades import sign_pdf_pades  # noqa: E402
from app.schemas.certificate import CertificateRenderData  # noqa: E402
from app.services.certificate_renderer import CertificateRenderer  # noqa: E402
from app.services.qr import build_validation_url, generate_qr_png  # noqa: E402

from PIL import Image  # noqa: E402
from pyhanko.pdf_utils.reader import PdfFileReader  # noqa: E402

DEFAULT_BASE_URL = "http://localhost:3000/validar"
_MEDIABOX_RE = re.compile(rb"/MediaBox\s*\[\s*([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s*\]")
_IGNORED_DIRS = {"__pycache__", ".git", ".venv", "venv", "node_modules", ".mypy_cache", ".ruff_cache"}

# --- Auditoria de escrita em disco ---------------------------------------------
_audit_active = False
_disk_events: list[str] = []


def _audit_hook(event: str, args: tuple) -> None:  # type: ignore[type-arg]
    if not _audit_active:
        return
    if event in ("tempfile.mkstemp", "tempfile.mkdtemp"):
        _disk_events.append(f"{event}: {args[0] if args else ''}")
        return
    if event != "open" or len(args) < 3:
        return
    path, mode, flags = args[0], args[1], args[2]
    if not isinstance(path, (str, bytes, os.PathLike)):
        return
    text = os.fsdecode(path)
    if "__pycache__" in text or text.startswith(("/dev/", "/proc/")):
        return
    writes = isinstance(mode, str) and any(ch in mode for ch in "wax+")
    if isinstance(flags, int) and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC):
        writes = True
    if writes:
        _disk_events.append(f"open({text!r}, mode={mode!r})")


def _snapshot(*roots: Path) -> set[str]:
    found: set[str] = set()
    for root in {r.resolve() for r in roots}:
        for current, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs if d not in _IGNORED_DIRS]
            found.update(os.path.join(current, name) for name in files)
    return found


# --- Utilidades de PDF ------------------------------------------------------------
def page_count(raw: bytes) -> int:
    try:
        reader = PdfFileReader(io.BytesIO(raw))
        return int(reader.root["/Pages"]["/Count"])
    except Exception:  # noqa: BLE001 - alternativa estrutural para PDFs gerados pelo ReportLab
        return len(re.findall(rb"/Type\s*/Page(?![A-Za-z])", raw))


def is_landscape_a4(raw: bytes) -> bool:
    match = _MEDIABOX_RE.search(raw)
    if not match:
        return False
    x0, y0, x1, y1 = (float(group) for group in match.groups())
    width, height = x1 - x0, y1 - y0
    return abs(width - 841.89) < 1 and abs(height - 595.28) < 1


def sign_and_validate(
    report: Report, label: str, pdf: io.BytesIO, creds: SigningCredentials
) -> io.BytesIO:
    original = pdf.getvalue()
    signed = asyncio.run(sign_pdf_pades(pdf, creds, reason="Smoke test Etapa 3", location="Ilhéus, BA"))
    raw = signed.getvalue()
    report.check(f"[{label}] Buffer de entrada preservado após assinar", pdf.getvalue() == original and not pdf.closed)
    report.check(f"[{label}] Escrita incremental (assinado começa com o PDF original)", raw.startswith(original))
    status = validate(signed, creds)
    coverage = getattr(status.coverage, "name", str(status.coverage))
    report.check(f"[{label}] Assinatura íntegra (intact=True)", bool(status.intact))
    report.check(f"[{label}] Assinatura válida (valid=True)", bool(status.valid))
    report.check(f"[{label}] Cobertura do arquivo inteiro", coverage == "ENTIRE_FILE", coverage)
    report.check(f"[{label}] Continua com 1 página após assinar", page_count(raw) == 1)
    return signed


def main(argv: list[str] | None = None) -> int:
    global _audit_active

    parser = argparse.ArgumentParser(description="Smoke test da Etapa 3")
    parser.add_argument("--ephemeral", action="store_true", help="usa certificado efêmero")
    parser.add_argument("--base-url", default=None, help="URL base de validação (sobrescreve o .env)")
    parser.add_argument("--out", default=None, help="grava o PDF assinado (depuração visual)")
    args = parser.parse_args(argv)
    report = Report()

    creds, _, _ = load_credentials(args)
    if args.base_url:
        base_url = args.base_url
    elif args.ephemeral:
        base_url = DEFAULT_BASE_URL
    else:
        from app.core.config import get_settings

        base_url = get_settings().public_validation_base_url
    print(f"URL base de validação: {base_url}\n")

    before = _snapshot(Path.cwd(), ROOT)
    sys.addaudithook(_audit_hook)
    _audit_active = True

    # 1. Schema ------------------------------------------------------------------
    data = CertificateRenderData(
        recipient_name="João da Silva Conceição Júnior",
        recipient_doc="123.456.789-09",
        event_name=(
            "XXIII Semana de Informática da UESC (Sinform): Inteligência Artificial, Ciência de "
            "Dados e Computação Quântica aplicadas à Saúde, à Educação e à Sustentabilidade "
            "na Região Cacaueira"
        ),
        role="Palestrante",
        workload_hours=Decimal("20"),
        event_date="10 a 14 de novembro de 2026",
        extra_metadata={"turma": "2026.2", "modalidade": "Presencial"},
    )
    report.check("UUID v4 gerado automaticamente", data.cert_uuid.version == 4, str(data.cert_uuid))
    report.check("CPF mascarado automaticamente", data.recipient_doc == "***.456.789-**", str(data.recipient_doc))

    # 2. URL e QR Code -------------------------------------------------------------
    url = build_validation_url(base_url, data.cert_uuid)
    report.check("URL pública termina com o UUID", url.endswith(f"/{data.cert_uuid}"), url)
    report.check("URL sem barras duplicadas", "//" not in url.split("://", 1)[1])
    report.check("Base com barra final gera a mesma URL", build_validation_url(base_url + "/", data.cert_uuid) == url)
    qr = generate_qr_png(url)
    png_bytes = qr.getvalue()
    image = Image.open(io.BytesIO(png_bytes))
    report.check("QR Code em PNG, em memória", png_bytes.startswith(b"\x89PNG\r\n\x1a\n"), f"{len(png_bytes)} bytes")
    report.check("QR Code quadrado", image.width == image.height and image.width > 100, f"{image.width}x{image.height}px")

    # 3. Renderização --------------------------------------------------------------
    renderer = CertificateRenderer(base_url)
    pdf = renderer.render(data)
    raw = pdf.getvalue()
    report.check("Cabeçalho mágico %PDF-", raw.startswith(b"%PDF-"))
    report.check("Tamanho em bytes > 0", len(raw) > 0, f"{len(raw)} bytes")
    report.check("Ponteiro rebobinado (seek 0) e buffer aberto", pdf.tell() == 0 and not pdf.closed)
    report.check("Exatamente 1 página", page_count(raw) == 1)
    report.check("A4 paisagem", is_landscape_a4(raw))
    plain = CertificateRenderer(base_url, compress=False).render(data).getvalue()
    report.check(
        "Acentos em WinAnsi no conteúdo (João, Conceição, Júnior)",
        all(token in plain for token in (b"Jo\\343o", b"Concei\\347\\343o", b"J\\372nior")),
    )

    # 4. Casos extremos --------------------------------------------------------------
    stress = CertificateRenderData(
        recipient_name=("Maria Aparecida dos Santos Albuquerque Cavalcanti de Oliveira " * 4)[:200],
        recipient_doc="Mat. 2023.0012345-X",
        event_name=("Congresso Internacional de Inteligência Artificial e Computação Quântica " * 5)[:300],
        role="Coordenação Geral da Comissão Organizadora",
        workload_hours=Decimal("7.5"),
        event_date="28 de outubro a 2 de novembro de 2026, Ilhéus (BA)",
    )
    stress_pdf = renderer.render(stress)
    report.check("Textos longos cabem em 1 página (quebra/redução automática)", page_count(stress_pdf.getvalue()) == 1)
    hostile = CertificateRenderData(
        recipient_name='Łukasz <img src="file:///etc/passwd"/> <b>&</b>',
        event_name="Evento <font color=red>X</font> &amp; Y",
        workload_hours=Decimal("1"),
        event_date="2026",
    )
    report.check("Marcação hostil neutralizada (renderiza como texto)", page_count(renderer.render(hostile).getvalue()) == 1)

    # 5. Integração Etapa 3 + Etapa 2 ---------------------------------------------------
    print()
    signed = sign_and_validate(report, "certificado", pdf, creds)
    sign_and_validate(report, "texto longo", stress_pdf, creds)

    # 6. Nada foi gravado em disco -----------------------------------------------------------
    _audit_active = False
    after = _snapshot(Path.cwd(), ROOT)
    report.check("Nenhuma escrita/arquivo temporário detectado (auditoria do Python)", not _disk_events, "; ".join(_disk_events[:3]))
    report.check("Nenhum arquivo novo no diretório do projeto", after == before, ", ".join(sorted(after - before)[:3]))

    if args.out:
        Path(args.out).write_bytes(signed.getvalue())
        print(f"\n[depuração] PDF assinado gravado em {args.out} por opção explícita (--out).")

    print("\n" + ("Etapa 3 validada." if report.failures == 0 else f"{report.failures} verificação(ões) falharam."))
    return 0 if report.failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
