"""Smoke test da Etapa 2: certificado A1 em memória + assinatura PAdES.

Uso (na raiz do projeto):
    python scripts/smoke_step2.py               # usa SIGNING_PFX_* do .env
    python scripts/smoke_step2.py --ephemeral   # gera certificado efêmero (CI, sem .env)

Tudo ocorre em RAM. Retorna código de saída 0 somente se todas as verificações passarem.
"""

from __future__ import annotations

import argparse
import asyncio
import io
import pickle
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from generate_dev_cert import generate_dev_pkcs12  # noqa: E402
from reportlab.lib.pagesizes import A4  # noqa: E402
from reportlab.pdfgen import canvas  # noqa: E402

from app.crypto.credentials import SigningCredentials, load_signing_credentials  # noqa: E402
from app.crypto.errors import CertificateLoadError, CertificateValidityError  # noqa: E402
from app.crypto.pades import sign_pdf_pades  # noqa: E402

from pyhanko.pdf_utils.reader import PdfFileReader  # noqa: E402
from pyhanko.sign.validation import validate_pdf_signature  # noqa: E402
from pyhanko_certvalidator import ValidationContext  # noqa: E402


class Report:
    def __init__(self) -> None:
        self.failures = 0

    def check(self, name: str, ok: bool, detail: str = "") -> bool:
        print(f"[{' OK ' if ok else 'FALHA'}] {name}" + (f" — {detail}" if detail else ""))
        if not ok:
            self.failures += 1
        return ok


def build_demo_pdf() -> io.BytesIO:
    buf = io.BytesIO()
    pdf = canvas.Canvas(buf, pagesize=A4)
    pdf.setTitle("Smoke test - Etapa 2")
    pdf.drawString(72, 760, "Certificado de teste (smoke test da Etapa 2)")
    pdf.showPage()
    pdf.save()
    buf.seek(0)
    return buf


def validate(signed: io.BytesIO, creds: SigningCredentials):  # noqa: ANN201
    reader = PdfFileReader(io.BytesIO(signed.getvalue()))
    signatures = reader.embedded_signatures
    if len(signatures) != 1:
        raise AssertionError(f"esperada 1 assinatura embutida, encontradas {len(signatures)}")
    roots = [creds.signer.signing_cert] if creds.info.self_signed else []
    context = ValidationContext(trust_roots=roots)
    return validate_pdf_signature(signatures[0], signer_validation_context=context)


def load_credentials(args: argparse.Namespace) -> tuple[SigningCredentials, str, str]:
    if args.ephemeral:
        dev = generate_dev_pkcs12()
        print("Fonte do certificado: EFÊMERO (gerado agora, em memória)")
        pfx_b64, password = dev.pfx_base64, dev.password
    else:
        from app.core.config import get_settings

        settings = get_settings()
        print("Fonte do certificado: SIGNING_PFX_BASE64 / SIGNING_PFX_PASSWORD (.env)")
        pfx_b64 = settings.signing_pfx_base64.get_secret_value()
        password = settings.signing_pfx_password.get_secret_value()
    return load_signing_credentials(pfx_b64, password), pfx_b64, password


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Smoke test da Etapa 2")
    parser.add_argument("--ephemeral", action="store_true", help="usa certificado efêmero")
    args = parser.parse_args(argv)
    report = Report()

    # 1. Carregamento em RAM -------------------------------------------------
    try:
        creds, pfx_b64, password = load_credentials(args)
    except CertificateLoadError as exc:
        print(f"[FALHA] Carregamento do certificado — {exc}")
        return 1
    info = creds.info
    report.check("PKCS#12 carregado em memória", True, f"{info.key_algorithm}, cadeia={info.chain_length}")

    # 2. Metadados e healthcheck ---------------------------------------------
    print("\n--- Metadados do certificado ---")
    print(f"Subject CN : {info.subject_cn}")
    print(f"Subject    : {info.subject}")
    print(f"Issuer     : {info.issuer}")
    print(f"Serial     : {info.serial_number}")
    print(f"Válido de  : {info.not_valid_before.isoformat()}")
    print(f"Válido até : {info.not_valid_after.isoformat()}")
    print(f"SHA-256    : {info.sha256_fingerprint}")
    print(f"Autoassin. : {info.self_signed}\n")
    health = creds.healthcheck()
    report.check("Healthcheck criptográfico", health.ok, f"{health.status}: {health.message}")

    # 3. Blindagem de segredos -------------------------------------------------
    leaked = any(s in text for s in (password, pfx_b64) for text in (repr(creds), str(creds)))
    report.check("repr/str sem senha nem Base64", not leaked)
    try:
        pickle.dumps(creds)
        report.check("Serialização (pickle) bloqueada", False)
    except TypeError:
        report.check("Serialização (pickle) bloqueada", True)
    try:
        load_signing_credentials(pfx_b64, password + "x")
        report.check("Senha incorreta rejeitada", False)
    except CertificateLoadError as exc:
        report.check("Senha incorreta rejeitada sem vazar segredos", password not in str(exc))

    # 4. Assinatura PAdES em memória --------------------------------------------
    pdf = build_demo_pdf()
    original = pdf.getvalue()
    signed = asyncio.run(
        sign_pdf_pades(pdf, creds, reason="Smoke test", location="Ilhéus, BA")
    )
    report.check("PDF assinado em memória", signed.getvalue().startswith(b"%PDF-"), f"{len(original)} -> {len(signed.getvalue())} bytes")
    report.check("Buffer de entrada preservado", pdf.getvalue() == original and not pdf.closed)

    # 5. Verificação com o pyHanko --------------------------------------------------
    status = validate(signed, creds)
    coverage = getattr(status.coverage, "name", str(status.coverage))
    report.check("Assinatura íntegra (intact=True)", bool(status.intact))
    report.check("Assinatura válida (valid=True)", bool(status.valid))
    report.check("Cobertura do arquivo inteiro", coverage == "ENTIRE_FILE", coverage)
    print(f"        trusted={status.trusted} (esperado True só para autoassinado/raiz confiável)")

    # 6. Adulteração deve ser detectada -----------------------------------------------
    tampered = bytearray(signed.getvalue())
    tampered[7] = ord("0") if tampered[7] != ord("0") else ord("1")
    try:
        bad = validate(io.BytesIO(bytes(tampered)), creds)
        report.check("Adulteração detectada (intact=False)", not bad.intact)
    except Exception:  # noqa: BLE001 - arquivo adulterado ilegível também conta como rejeitado
        report.check("Adulteração detectada (arquivo rejeitado)", True)

    # 7. Certificado expirado deve bloquear a assinatura --------------------------------
    expired = generate_dev_pkcs12(
        valid_days=30, not_before=datetime.now(timezone.utc) - timedelta(days=400)
    )
    expired_creds = load_signing_credentials(expired.pfx_base64, expired.password)
    report.check("Healthcheck acusa certificado expirado", not expired_creds.healthcheck().ok)
    try:
        asyncio.run(sign_pdf_pades(build_demo_pdf(), expired_creds))
        report.check("Assinatura bloqueada com certificado expirado", False)
    except CertificateValidityError:
        report.check("Assinatura bloqueada com certificado expirado", True)

    print("\n" + ("Etapa 2 validada." if report.failures == 0 else f"{report.failures} verificação(ões) falharam."))
    return 0 if report.failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
