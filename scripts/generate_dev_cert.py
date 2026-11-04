"""Gera, em memória, um certificado A1 de DESENVOLVIMENTO/CI (autoassinado).

Sem OpenSSL e sem gravar arquivos: chave RSA 2048 + X.509 autoassinado com
``digital_signature`` e ``non_repudiation`` (content_commitment), empacotados em
PKCS#12 na RAM. As linhas prontas para o ``.env`` saem no stdout; os metadados
saem no stderr.

    python scripts/generate_dev_cert.py                 # imprime no terminal
    python scripts/generate_dev_cert.py --days 90 --cn "Meu Dev"

Em CI (GitHub Actions) prefira ``python scripts/smoke_step2.py --ephemeral``, que
gera o certificado em memória e nem precisa de secrets.

ATENÇÃO: este certificado NÃO é ICP-Brasil e nunca deve ser usado em produção.
"""

from __future__ import annotations

import argparse
import base64
import secrets
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID


@dataclass(frozen=True)
class DevCertificate:
    pfx: bytes
    password: str

    @property
    def pfx_base64(self) -> str:
        return base64.b64encode(self.pfx).decode("ascii")


def generate_dev_pkcs12(
    *,
    common_name: str = "Dev Signer - certificados-api",
    organization: str = "Certificados API (DEV/CI)",
    valid_days: int = 365,
    password: str | None = None,
    not_before: datetime | None = None,
) -> DevCertificate:
    """Cria o PKCS#12 efêmero. ``not_before`` permite simular certificado expirado."""
    if valid_days < 1:
        raise ValueError("valid_days deve ser >= 1")
    secret = password or secrets.token_urlsafe(18)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "BR"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ]
    )
    start = not_before or (datetime.now(timezone.utc) - timedelta(minutes=5))
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(start + timedelta(days=valid_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,  # non_repudiation
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    pfx = pkcs12.serialize_key_and_certificates(
        name=b"dev-signer",
        key=key,
        cert=cert,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(secret.encode("utf-8")),
    )
    return DevCertificate(pfx=pfx, password=secret)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--cn", default="Dev Signer - certificados-api", help="Common Name")
    parser.add_argument("--days", type=int, default=365, help="validade em dias (padrão 365)")
    parser.add_argument("--password", default=None, help="senha do PKCS#12 (padrão: aleatória)")
    args = parser.parse_args(argv)

    dev = generate_dev_pkcs12(common_name=args.cn, valid_days=args.days, password=args.password)

    print(f"SIGNING_PFX_BASE64={dev.pfx_base64}")
    print(f"SIGNING_PFX_PASSWORD={dev.password}")
    print(
        "\n[!] Certificado AUTOASSINADO de desenvolvimento (não é ICP-Brasil).\n"
        "    Cole as duas linhas acima no .env (não versione). Nenhum arquivo foi gravado.",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
