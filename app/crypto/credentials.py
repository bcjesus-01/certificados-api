"""Credenciais de assinatura (certificado A1 / PKCS#12) 100% em memória.

Fluxo: Base64 (variável de ambiente) -> ``bytes`` em RAM -> ``cryptography``
(``pkcs12.load_key_and_certificates``) -> objetos ``asn1crypto`` -> ``SimpleSigner``
do pyHanko. Nenhum arquivo temporário é criado em nenhum ponto.

Blindagem de segredos:
- ``SigningCredentials`` redefine ``__repr__``/``__str__`` e bloqueia pickle/cópia;
- exceções usam mensagens fixas (``from None`` descarta a causa original);
- logs registram apenas fingerprint, serial e validade, nunca CN, senha ou chave.
  (O CN de um A1 e-CPF/e-CNPJ costuma conter CPF/CNPJ, dado pessoal pela LGPD.)

Limite honesto: o Python não permite apagar ``bytes`` imutáveis da memória; os
segredos vivem em RAM enquanto o processo vive, como em qualquer serviço que
assina documentos.
"""

from __future__ import annotations

import base64
import binascii
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Literal, NoReturn

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from app.crypto.errors import CertificateLoadError, CertificateValidityError

if TYPE_CHECKING:
    from pyhanko.sign import signers

logger = logging.getLogger(__name__)

EXPIRY_WARNING_DAYS = 30

HealthStatus = Literal["ok", "expiring_soon", "expired", "not_yet_valid"]

_SUPPORTED_KEY_TYPES = (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Metadados públicos do certificado
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class CertificateInfo:
    """Metadados seguros (públicos) do certificado X.509 de assinatura."""

    subject_cn: str
    subject: str
    issuer: str
    serial_number: str
    not_valid_before: datetime
    not_valid_after: datetime
    sha256_fingerprint: str
    key_algorithm: str
    chain_length: int
    self_signed: bool

    def is_valid_at(self, moment: datetime | None = None) -> bool:
        now = moment or _utcnow()
        return self.not_valid_before <= now <= self.not_valid_after

    def days_until_expiry(self, moment: datetime | None = None) -> int:
        """Dias inteiros até expirar (negativo se já expirou)."""
        return (self.not_valid_after - (moment or _utcnow())).days

    def to_dict(self, moment: datetime | None = None) -> dict[str, Any]:
        """Representação serializável em JSON (ex.: endpoint de healthcheck)."""
        return {
            "subject_cn": self.subject_cn,
            "subject": self.subject,
            "issuer": self.issuer,
            "serial_number": self.serial_number,
            "not_valid_before": self.not_valid_before.isoformat(),
            "not_valid_after": self.not_valid_after.isoformat(),
            "sha256_fingerprint": self.sha256_fingerprint,
            "key_algorithm": self.key_algorithm,
            "chain_length": self.chain_length,
            "self_signed": self.self_signed,
            "valid_now": self.is_valid_at(moment),
            "days_until_expiry": self.days_until_expiry(moment),
        }


@dataclass(frozen=True, slots=True)
class CryptoHealth:
    """Resultado do healthcheck criptográfico."""

    ok: bool
    status: HealthStatus
    message: str
    info: CertificateInfo


def _common_name(name: x509.Name) -> str:
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(attrs[0].value) if attrs else ""


def _fingerprint(cert: x509.Certificate) -> str:
    raw = cert.fingerprint(hashes.SHA256()).hex().upper()
    return ":".join(raw[i : i + 2] for i in range(0, len(raw), 2))


def _key_algorithm(key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey) -> str:
    if isinstance(key, rsa.RSAPrivateKey):
        return f"RSA-{key.key_size}"
    return f"EC-{key.curve.name}"


def _build_info(
    cert: x509.Certificate,
    key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
    chain_length: int,
) -> CertificateInfo:
    return CertificateInfo(
        subject_cn=_common_name(cert.subject),
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        serial_number=format(cert.serial_number, "X"),
        not_valid_before=cert.not_valid_before_utc,
        not_valid_after=cert.not_valid_after_utc,
        sha256_fingerprint=_fingerprint(cert),
        key_algorithm=_key_algorithm(key),
        chain_length=chain_length,
        self_signed=cert.issuer == cert.subject,
    )


# ---------------------------------------------------------------------------
# Credenciais
# ---------------------------------------------------------------------------
class SigningCredentials:
    """Assinador pyHanko + metadados, sem expor chave, senha ou Base64."""

    __slots__ = ("_signer", "_info", "_trust_roots", "_intermediates")

    def __init__(
        self,
        signer: "signers.SimpleSigner",
        info: CertificateInfo,
        trust_roots: tuple[Any, ...] = (),
        intermediates: tuple[Any, ...] = (),
    ) -> None:
        self._signer = signer
        self._info = info
        self._trust_roots = trust_roots
        self._intermediates = intermediates

    @property
    def trust_roots(self) -> tuple[Any, ...]:
        """Âncoras de confiança (``asn1crypto.x509.Certificate``) para validar assinaturas.

        Contém o próprio certificado de assinatura (pinning) e as raízes autoassinadas da
        cadeia do PKCS#12. Nunca inclui certificados vindos de PDFs enviados por terceiros.
        """
        return self._trust_roots or (self._signer.signing_cert,)

    @property
    def intermediates(self) -> tuple[Any, ...]:
        """Certificados intermediários da cadeia (``asn1crypto.x509.Certificate``)."""
        return self._intermediates

    @property
    def signer(self) -> "signers.SimpleSigner":
        return self._signer

    @property
    def info(self) -> CertificateInfo:
        return self._info

    def get_certificate_info(self) -> CertificateInfo:
        return self._info

    def ensure_valid(self, moment: datetime | None = None) -> None:
        """Bloqueia o uso do certificado fora do período de validade."""
        now = moment or _utcnow()
        if now < self._info.not_valid_before:
            raise CertificateValidityError(
                "Certificado de assinatura ainda não é válido "
                f"(início em {self._info.not_valid_before.isoformat()})"
            )
        if now > self._info.not_valid_after:
            raise CertificateValidityError(
                "Certificado de assinatura expirado "
                f"(em {self._info.not_valid_after.isoformat()}); assinatura bloqueada"
            )

    def healthcheck(self, moment: datetime | None = None) -> CryptoHealth:
        """Verifica o prazo de validade; não executa nenhuma operação de assinatura."""
        now = moment or _utcnow()
        info = self._info
        if now < info.not_valid_before:
            return CryptoHealth(
                False, "not_yet_valid",
                f"Certificado só é válido a partir de {info.not_valid_before.isoformat()}", info,
            )
        if now > info.not_valid_after:
            return CryptoHealth(
                False, "expired",
                f"Certificado expirou em {info.not_valid_after.isoformat()}", info,
            )
        days = info.days_until_expiry(now)
        if days < EXPIRY_WARNING_DAYS:
            return CryptoHealth(
                True, "expiring_soon", f"Certificado expira em {days} dia(s): renove", info
            )
        return CryptoHealth(True, "ok", f"Certificado válido por mais {days} dia(s)", info)

    # --- Blindagem -----------------------------------------------------
    def __repr__(self) -> str:
        return (
            f"<SigningCredentials fingerprint={self._info.sha256_fingerprint[:23]}… "
            "[chave e senha ocultas]>"
        )

    __str__ = __repr__

    def __reduce__(self) -> NoReturn:
        raise TypeError("SigningCredentials não pode ser serializado")

    def __copy__(self) -> NoReturn:
        raise TypeError("SigningCredentials não pode ser copiado")

    def __deepcopy__(self, memo: dict[int, Any]) -> NoReturn:
        raise TypeError("SigningCredentials não pode ser copiado")


# ---------------------------------------------------------------------------
# Carregamento
# ---------------------------------------------------------------------------
def _check_key_matches_certificate(
    key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey, cert: x509.Certificate
) -> None:
    spki = serialization.PublicFormat.SubjectPublicKeyInfo
    der = serialization.Encoding.DER
    if key.public_key().public_bytes(der, spki) != cert.public_key().public_bytes(der, spki):
        raise CertificateLoadError("A chave privada não corresponde ao certificado do PKCS#12")


def _check_key_usage(cert: x509.Certificate) -> None:
    try:
        usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        return
    if not (usage.digital_signature or usage.content_commitment):
        raise CertificateLoadError(
            "O certificado não permite assinatura digital (digitalSignature/nonRepudiation)"
        )


def _build_signer(
    key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey,
    cert: x509.Certificate,
    chain: list[x509.Certificate],
) -> "signers.SimpleSigner":
    """Converte os objetos ``cryptography`` para ``asn1crypto`` e cria o ``SimpleSigner``.

    Importações tardias isolam a dependência do pyHanko/asn1crypto neste ponto.
    """
    from asn1crypto import keys as asn1_keys
    from asn1crypto import x509 as asn1_x509
    from pyhanko.sign import signers
    from pyhanko_certvalidator.registry import SimpleCertificateStore

    der = serialization.Encoding.DER
    asn1_cert = asn1_x509.Certificate.load(cert.public_bytes(der))
    asn1_key = asn1_keys.PrivateKeyInfo.load(
        key.private_bytes(
            der, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    registry = SimpleCertificateStore()
    for extra in chain:
        registry.register(asn1_x509.Certificate.load(extra.public_bytes(der)))
    return signers.SimpleSigner(
        signing_cert=asn1_cert,
        signing_key=asn1_key,
        cert_registry=registry,
    )


def _build_trust_material(
    cert: x509.Certificate, chain: list[x509.Certificate]
) -> tuple[tuple[Any, ...], tuple[Any, ...]]:
    """Separa a cadeia em âncoras (certificado de assinatura + raízes) e intermediários."""
    from asn1crypto import x509 as asn1_x509

    der = serialization.Encoding.DER

    def load(item: x509.Certificate) -> Any:
        return asn1_x509.Certificate.load(item.public_bytes(der))

    roots = [load(cert)]
    intermediates: list[Any] = []
    for extra in chain:
        (roots if extra.issuer == extra.subject else intermediates).append(load(extra))
    return tuple(roots), tuple(intermediates)


def load_signing_credentials_from_bytes(
    pfx_data: bytes, password: bytes | None
) -> SigningCredentials:
    """Carrega o PKCS#12 a partir de bytes em RAM (sem tocar o disco)."""
    try:
        key, cert, additional = pkcs12.load_key_and_certificates(pfx_data, password)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        raise CertificateLoadError(
            "Não foi possível abrir o PKCS#12: senha incorreta ou arquivo inválido"
        ) from None

    if key is None or cert is None:
        raise CertificateLoadError("O PKCS#12 precisa conter chave privada e certificado")
    if not isinstance(key, _SUPPORTED_KEY_TYPES):
        raise CertificateLoadError("Tipo de chave não suportado (use RSA ou ECDSA)")

    _check_key_matches_certificate(key, cert)
    _check_key_usage(cert)

    chain = [c for c in additional if c != cert]
    try:
        signer = _build_signer(key, cert, chain)
    except CertificateLoadError:
        raise
    except Exception:  # noqa: BLE001 - nada do material de chave pode vazar na mensagem
        raise CertificateLoadError("Falha ao inicializar o assinador com o certificado") from None

    try:
        trust_roots, intermediates = _build_trust_material(cert, chain)
    except Exception:  # noqa: BLE001 - nada do material de chave pode vazar na mensagem
        raise CertificateLoadError("Falha ao preparar a cadeia de confiança do certificado") from None

    credentials = SigningCredentials(
        signer, _build_info(cert, key, len(chain)), trust_roots, intermediates
    )
    info = credentials.info
    logger.info(
        "Certificado de assinatura carregado: serial=%s sha256=%s validade=%s..%s cadeia=%d",
        info.serial_number,
        info.sha256_fingerprint,
        info.not_valid_before.date(),
        info.not_valid_after.date(),
        info.chain_length,
    )
    health = credentials.healthcheck()
    if not health.ok:
        logger.error("Certificado de assinatura inutilizável: %s", health.status)
    elif health.status == "expiring_soon":
        logger.warning("Certificado de assinatura próximo do vencimento: %s", health.message)
    return credentials


def load_signing_credentials(pfx_base64: str, password: str) -> SigningCredentials:
    """Decodifica o Base64 (variável de ambiente) em RAM e carrega o PKCS#12."""
    try:
        pfx_data = base64.b64decode("".join(pfx_base64.split()), validate=True)
    except (binascii.Error, ValueError):
        raise CertificateLoadError("SIGNING_PFX_BASE64 não é um Base64 válido") from None
    return load_signing_credentials_from_bytes(pfx_data, password.encode("utf-8") or None)
