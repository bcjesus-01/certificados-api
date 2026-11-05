"""Configuração: CORS_ORIGINS (CSV/JSON), nome antigo, regras de produção e limites do upload público."""

from __future__ import annotations

import base64
from typing import Any

import pydantic
import pytest

from app.core.config import Settings, parse_origins

BASE: dict[str, Any] = {
    "public_validation_base_url": "http://localhost:3000/validar",
    "database_url": "postgresql://u:p@h/db",
    "s3_access_key_id": "k",
    "s3_secret_access_key": "s",
    "s3_bucket": "certificados",
    "signing_pfx_base64": base64.b64encode(b"x").decode(),
    "signing_pfx_password": "p",
}
PROD: dict[str, Any] = {
    "app_env": "production",
    "db_ssl": "require",
    "public_validation_base_url": "https://validar.example.com/validar",
    "issuance_api_key": "a" * 48,
}


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("CORS_ORIGINS", "CORS_ALLOWED_ORIGINS", "APP_ENV"):
        monkeypatch.delenv(name, raising=False)


def make(**overrides: Any) -> Settings:
    return Settings(_env_file=None, **{**BASE, **overrides})  # type: ignore[call-arg]


def test_parse_origins_csv_json_and_normalization() -> None:
    assert parse_origins("http://a.com, https://b.com/ ,http://a.com") == ["http://a.com", "https://b.com"]
    assert parse_origins('["http://localhost:3000", "https://x.io"]') == ["http://localhost:3000", "https://x.io"]
    assert parse_origins("") == []
    assert parse_origins("http://[::1]:3000") == ["http://[::1]:3000"]


@pytest.mark.parametrize(
    "raw",
    ["*", "http://a.com,*", "a.com", "http://a.com/path", "ftp://a.com", "[not json", '{"a": 1}', "[1, 2]", "http://"],
)
def test_parse_origins_rejects_wildcards_and_garbage(raw: str) -> None:
    with pytest.raises(ValueError):
        parse_origins(raw)


def test_dev_default_is_localhost_3000() -> None:
    assert make().allowed_origins == ["http://localhost:3000"]


def test_cors_origins_overrides_default_and_legacy_name_still_works() -> None:
    assert make(cors_origins="https://p.example.com").allowed_origins == ["https://p.example.com"]
    assert make(cors_allowed_origins='["http://localhost:5173"]').allowed_origins == ["http://localhost:5173"]
    both = make(cors_origins="http://a.com", cors_allowed_origins="http://b.com")
    assert both.allowed_origins == ["http://a.com"]


def test_invalid_origins_fail_at_startup() -> None:
    with pytest.raises(pydantic.ValidationError):
        make(cors_origins="*")


def test_production_requires_https_origins() -> None:
    assert make(**PROD, cors_origins="https://validar.example.com").allowed_origins == ["https://validar.example.com"]
    with pytest.raises(pydantic.ValidationError):
        make(**PROD)  # sem origem
    with pytest.raises(pydantic.ValidationError):
        make(**PROD, cors_origins="http://validar.example.com")
    with pytest.raises(pydantic.ValidationError):
        make(**PROD, cors_origins="https://ok.example.com,http://localhost:3000")


def test_public_upload_limit_stays_below_starlette_spool_threshold() -> None:
    settings = make()
    assert settings.validation_max_upload_bytes + 4096 < 1024 * 1024
    for bad in (10 * 1024 * 1024, 100):
        with pytest.raises(pydantic.ValidationError):
            make(validation_max_upload_bytes=bad)
