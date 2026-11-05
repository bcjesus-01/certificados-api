"""Configuração da aplicação via variáveis de ambiente (pydantic-settings).

Nenhum segredo é logado: credenciais usam ``SecretStr``.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_WHITESPACE_RE = re.compile(r"\s+")
# esquema://host[:porta] (inclui IPv6 entre colchetes), sem caminho, query ou barra final.
_ORIGIN_RE = re.compile(r"https?://(?:[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?|\[[0-9A-Fa-f:]+\])(?::\d{1,5})?")
DEFAULT_DEV_ORIGINS: tuple[str, ...] = ("http://localhost:3000",)


def parse_origins(raw: str) -> list[str]:
    """Converte ``CORS_ORIGINS`` (lista separada por vírgula ou JSON) em origens normalizadas.

    Rejeita ``*`` e qualquer valor que não seja ``esquema://host[:porta]``: origens
    explícitas são o que impede um site qualquer de consumir a API pelo navegador.
    """
    text = raw.strip()
    if not text:
        return []
    items: list[object]
    if text.startswith("["):
        try:
            decoded = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError("CORS_ORIGINS: JSON inválido") from exc
        if not isinstance(decoded, list):
            raise ValueError("CORS_ORIGINS: esperado uma lista JSON de strings")
        items = decoded
    else:
        items = list(text.split(","))
    origins: list[str] = []
    for item in items:
        if not isinstance(item, str):
            raise ValueError("CORS_ORIGINS: todos os itens devem ser strings")
        origin = item.strip().rstrip("/")
        if not origin:
            continue
        if origin == "*":
            raise ValueError("CORS_ORIGINS não pode conter '*': liste cada origem explicitamente")
        if not _ORIGIN_RE.fullmatch(origin):
            raise ValueError(
                f"CORS_ORIGINS: origem inválida {origin!r} (use esquema://host[:porta], sem caminho)"
            )
        if origin not in origins:
            origins.append(origin)
    return origins


class Settings(BaseSettings):
    """Configurações tipadas e validadas na inicialização (fail-fast)."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- Aplicação ---
    app_name: str = "certificados-api"
    app_env: Literal["development", "staging", "production"] = "development"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    api_v1_prefix: str = "/api/v1"
    # Origens do portal (Next.js) autorizadas a chamar a API pelo navegador. Aceita lista separada
    # por vírgula ou JSON. Em desenvolvimento, vazio equivale a http://localhost:3000.
    cors_origins: str = ""
    # Nome antigo da variável (Etapas 1 a 5, lista JSON). Mantido para não quebrar .env existentes.
    cors_allowed_origins: str = ""
    public_validation_base_url: str = Field(
        ..., description="URL base do portal de validação (usada no QR Code)."
    )
    batch_max_items: int = Field(default=500, ge=1, le=5000)

    # --- API de emissão em lote (Etapa 4) ---
    # Sem a chave, os endpoints de emissão respondem 503 (falham fechados).
    issuance_api_key: SecretStr | None = None
    batch_concurrency: int = Field(default=4, ge=1, le=32)
    # Corpo máximo das requisições de lote. Mantido abaixo de 1 MiB: acima disso o Starlette
    # grava o upload em arquivo temporário (SpooledTemporaryFile), violando o "zero disco".
    batch_max_body_bytes: int = Field(default=900_000, ge=10_000, le=1_000_000)

    # --- Validação pública (Etapa 5) ---
    # Teto do PDF enviado em POST /validate/file. Mantido abaixo de 1 MiB: acima disso o Starlette
    # gravaria o upload em arquivo temporário (SpooledTemporaryFile), violando o "zero disco".
    validation_max_upload_bytes: int = Field(default=1_000_000, ge=10_000, le=1_000_000)
    # Validade da URL pré-assinada devolvida pela consulta por código/QR Code.
    validation_presigned_ttl_seconds: int = Field(default=900, ge=30, le=3600)
    # Perícias de PDF simultâneas (trabalho de CPU em threads) e tempo máximo de cada uma.
    validation_concurrency: int = Field(default=4, ge=1, le=32)
    validation_timeout_seconds: float = Field(default=20.0, ge=1.0, le=120.0)

    # --- Banco de dados (Supabase / PostgreSQL) ---
    database_url: SecretStr
    db_ssl: Literal["disable", "prefer", "require", "verify-ca", "verify-full"] = "require"
    db_pool_min_size: int = Field(default=2, ge=1, le=50)
    db_pool_max_size: int = Field(default=10, ge=1, le=100)
    db_command_timeout: float = Field(default=30.0, gt=0)
    # 0 é obrigatório atrás do pooler em modo transaction (Supavisor/pgbouncer).
    db_statement_cache_size: int = Field(default=0, ge=0)

    # --- Object Storage (Cloudflare R2 / AWS S3) ---
    s3_endpoint_url: str | None = None
    s3_region: str = "auto"
    s3_access_key_id: SecretStr
    s3_secret_access_key: SecretStr
    s3_bucket: str = Field(..., min_length=3, max_length=63)
    s3_key_prefix: str = "certificates"
    s3_addressing_style: Literal["auto", "path", "virtual"] = "auto"
    s3_presigned_ttl_seconds: int = Field(default=300, ge=30, le=3600)

    # --- Certificado A1 ICP-Brasil (consumido a partir da Etapa 2) ---
    signing_pfx_base64: SecretStr
    signing_pfx_password: SecretStr
    # Metadados gravados no dicionário da assinatura PAdES (campos /Reason e /Location).
    signing_reason: str = Field(default="Certificado emitido e assinado digitalmente", max_length=200)
    signing_location: str | None = Field(default=None, max_length=200)
    # Gera aviso (healthcheck "expiring_soon") quando faltar menos que N dias para expirar.
    signing_expiry_warning_days: int = Field(default=30, ge=0, le=365)

    # ------------------------------------------------------------------
    # Validadores
    # ------------------------------------------------------------------
    @field_validator("public_validation_base_url")
    @classmethod
    def _validate_public_url(cls, value: str) -> str:
        value = value.strip().rstrip("/")
        if not value.startswith(("http://", "https://")):
            raise ValueError("PUBLIC_VALIDATION_BASE_URL deve começar com http:// ou https://")
        return value

    @field_validator("cors_origins", "cors_allowed_origins")
    @classmethod
    def _validate_cors_origins(cls, value: str) -> str:
        parse_origins(value)  # falha rápido na inicialização se a lista for inválida
        return value.strip()

    @field_validator("database_url")
    @classmethod
    def _validate_database_url(cls, value: SecretStr) -> SecretStr:
        raw = value.get_secret_value().strip()
        if not raw.startswith(("postgresql://", "postgres://")):
            raise ValueError("DATABASE_URL deve usar o esquema postgresql:// ou postgres://")
        return SecretStr(raw)

    @field_validator("s3_endpoint_url", "signing_location", mode="before")
    @classmethod
    def _empty_endpoint_is_none(cls, value: object) -> object:
        # Permite deixar S3_ENDPOINT_URL vazio para usar a AWS S3 padrão.
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @field_validator("issuance_api_key", mode="before")
    @classmethod
    def _empty_issuance_key_is_none(cls, value: object) -> object:
        if isinstance(value, str):
            value = value.strip()
            return value or None
        return value

    @field_validator("issuance_api_key", mode="after")
    @classmethod
    def _validate_issuance_key(cls, value: SecretStr | None) -> SecretStr | None:
        if value is not None and len(value.get_secret_value()) < 32:
            raise ValueError(
                "ISSUANCE_API_KEY deve ter ao menos 32 caracteres "
                '(gere com: python -c "import secrets; print(secrets.token_urlsafe(48))")'
            )
        return value

    @field_validator("s3_key_prefix")
    @classmethod
    def _validate_key_prefix(cls, value: str) -> str:
        value = value.strip().strip("/")
        if not value or ".." in value:
            raise ValueError("S3_KEY_PREFIX inválido")
        return value

    @field_validator("signing_pfx_base64")
    @classmethod
    def _validate_pfx_base64(cls, value: SecretStr) -> SecretStr:
        # Variáveis de ambiente costumam trazer quebras de linha; normaliza antes de validar.
        normalized = _WHITESPACE_RE.sub("", value.get_secret_value())
        if not normalized:
            raise ValueError("SIGNING_PFX_BASE64 não pode ser vazio")
        try:
            base64.b64decode(normalized, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("SIGNING_PFX_BASE64 não é um Base64 válido") from exc
        return SecretStr(normalized)

    @model_validator(mode="after")
    def _cross_validate(self) -> "Settings":
        if self.db_pool_min_size > self.db_pool_max_size:
            raise ValueError("DB_POOL_MIN_SIZE não pode ser maior que DB_POOL_MAX_SIZE")
        if self.app_env == "production":
            if self.db_ssl in ("disable", "prefer"):
                raise ValueError("Em produção DB_SSL deve ser require, verify-ca ou verify-full")
            if not self.public_validation_base_url.startswith("https://"):
                raise ValueError("Em produção PUBLIC_VALIDATION_BASE_URL deve usar https://")
            if self.issuance_api_key is None:
                raise ValueError("Em produção ISSUANCE_API_KEY é obrigatória")
            origins = self.allowed_origins
            if not origins:
                raise ValueError("Em produção CORS_ORIGINS é obrigatória (origem do portal de validação)")
            if any(not origin.startswith("https://") for origin in origins):
                raise ValueError("Em produção todas as origens de CORS_ORIGINS devem usar https://")
        return self

    @property
    def allowed_origins(self) -> list[str]:
        """Origens CORS efetivas: ``CORS_ORIGINS``, senão o nome antigo, senão o padrão de dev."""
        origins = parse_origins(self.cors_origins) or parse_origins(self.cors_allowed_origins)
        if not origins and not self.is_production:
            return list(DEFAULT_DEV_ORIGINS)
        return origins

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Retorna a instância única de configurações (cache em processo)."""
    return Settings()  # type: ignore[call-arg]
