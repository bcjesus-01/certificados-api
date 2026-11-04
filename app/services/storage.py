"""Cliente de Object Storage (Cloudflare R2 / AWS S3) 100% em memória.

O PDF assinado é enviado diretamente de um ``io.BytesIO``; nada é gravado em disco.
As chamadas bloqueantes do boto3 rodam em threads (``asyncio.to_thread``) para
não bloquear o event loop do FastAPI.
"""

from __future__ import annotations

import asyncio
import io
import logging
import re
import unicodedata
from datetime import datetime, timezone
from uuid import UUID

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import BotoCoreError, ClientError

from app.core.config import Settings, get_settings

logger = logging.getLogger(__name__)

PDF_CONTENT_TYPE = "application/pdf"
_NOT_FOUND_CODES = {"404", "NoSuchKey", "NotFound"}
_FILENAME_SAFE_RE = re.compile(r"[^A-Za-z0-9._-]+")


class StorageError(Exception):
    """Falha em operação de object storage."""


class ObjectStorage:
    """Fachada assíncrona sobre o boto3 para R2/S3."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()
        cfg = BotoConfig(
            signature_version="s3v4",
            s3={"addressing_style": self._settings.s3_addressing_style},
            retries={"max_attempts": 5, "mode": "standard"},
            connect_timeout=5,
            read_timeout=60,
            # Evita checksums CRC32 automáticos (boto3>=1.36) que o R2 pode rejeitar.
            request_checksum_calculation="when_required",
            response_checksum_validation="when_required",
        )
        self._client = boto3.client(
            "s3",
            endpoint_url=self._settings.s3_endpoint_url,
            region_name=self._settings.s3_region,
            aws_access_key_id=self._settings.s3_access_key_id.get_secret_value(),
            aws_secret_access_key=self._settings.s3_secret_access_key.get_secret_value(),
            config=cfg,
        )
        self._bucket = self._settings.s3_bucket

    # ------------------------------------------------------------------
    # Chaves de objeto
    # ------------------------------------------------------------------
    @property
    def bucket(self) -> str:
        return self._bucket

    def build_key(self, cert_id: UUID, issued_at: datetime | None = None) -> str:
        """Gera a chave determinística ``<prefixo>/<ano>/<uuid>.pdf``."""
        year = (issued_at or datetime.now(timezone.utc)).year
        return f"{self._settings.s3_key_prefix}/{year}/{cert_id}.pdf"

    @staticmethod
    def _validate_key(key: str) -> str:
        if not key or key.startswith("/") or ".." in key.split("/"):
            raise StorageError(f"Chave de objeto inválida: {key!r}")
        return key

    # ------------------------------------------------------------------
    # Operações
    # ------------------------------------------------------------------
    def _upload_sync(
        self,
        key: str,
        data: bytes,
        content_type: str,
        metadata: dict[str, str] | None,
    ) -> None:
        params: dict[str, object] = {
            "Bucket": self._bucket,
            "Key": key,
            "Body": data,
            "ContentType": content_type,
            "CacheControl": "private, no-store",
        }
        if metadata:
            params["Metadata"] = metadata
        self._client.put_object(**params)

    async def upload_pdf(
        self,
        key: str,
        buffer: io.BytesIO,
        sha256: str | None = None,
    ) -> None:
        """Envia o PDF assinado, a partir da RAM, para o bucket.

        Usa ``put_object`` com os bytes do buffer (certificados são pequenos).
        Diferente de ``upload_fileobj``, não fecha nem move o cursor do
        ``BytesIO`` do chamador, que continua utilizável (hash, persistência).
        """
        self._validate_key(key)
        metadata = {"sha256": sha256} if sha256 else None
        data = buffer.getvalue()
        try:
            await asyncio.to_thread(self._upload_sync, key, data, PDF_CONTENT_TYPE, metadata)
        except (BotoCoreError, ClientError) as exc:
            logger.error("Falha no upload para o storage: key=%s", key)
            raise StorageError("Falha ao enviar o objeto para o storage") from exc

    def presign_get(
        self,
        key: str,
        expires_in: int | None = None,
        download_filename: str | None = None,
    ) -> str:
        """Gera URL pré-assinada de leitura (cálculo local, sem I/O de rede)."""
        self._validate_key(key)
        params: dict[str, str] = {
            "Bucket": self._bucket,
            "Key": key,
            "ResponseContentType": PDF_CONTENT_TYPE,
        }
        if download_filename:
            params["ResponseContentDisposition"] = (
                f'inline; filename="{self._safe_filename(download_filename)}"'
            )
        ttl = expires_in or self._settings.s3_presigned_ttl_seconds
        try:
            return self._client.generate_presigned_url(
                "get_object", Params=params, ExpiresIn=ttl, HttpMethod="GET"
            )
        except (BotoCoreError, ClientError) as exc:
            raise StorageError("Falha ao gerar URL pré-assinada") from exc

    def _download_sync(self, key: str, max_bytes: int) -> bytes:
        response = self._client.get_object(Bucket=self._bucket, Key=key)
        try:
            if int(response.get("ContentLength", 0)) > max_bytes:
                raise StorageError("Objeto maior que o limite permitido")
            return bytes(response["Body"].read())
        finally:
            response["Body"].close()

    async def download(self, key: str, max_bytes: int = 25 * 1024 * 1024) -> bytes:
        """Baixa o objeto direto para a RAM (sem arquivo temporário)."""
        self._validate_key(key)
        try:
            return await asyncio.to_thread(self._download_sync, key, max_bytes)
        except StorageError:
            raise
        except (BotoCoreError, ClientError) as exc:
            raise StorageError("Falha ao baixar o objeto do storage") from exc

    async def exists(self, key: str) -> bool:
        self._validate_key(key)
        try:
            await asyncio.to_thread(self._client.head_object, Bucket=self._bucket, Key=key)
            return True
        except ClientError as exc:
            code = str(exc.response.get("Error", {}).get("Code", ""))
            if code in _NOT_FOUND_CODES:
                return False
            raise StorageError("Falha ao consultar o objeto no storage") from exc
        except BotoCoreError as exc:
            raise StorageError("Falha ao consultar o objeto no storage") from exc

    async def delete(self, key: str) -> None:
        self._validate_key(key)
        try:
            await asyncio.to_thread(self._client.delete_object, Bucket=self._bucket, Key=key)
        except (BotoCoreError, ClientError) as exc:
            raise StorageError("Falha ao remover o objeto do storage") from exc

    async def healthcheck(self) -> bool:
        """Retorna True se o bucket está acessível com as credenciais atuais."""
        try:
            await asyncio.to_thread(self._client.head_bucket, Bucket=self._bucket)
            return True
        except (BotoCoreError, ClientError):
            logger.warning("Healthcheck do storage falhou")
            return False

    @staticmethod
    def _safe_filename(name: str) -> str:
        ascii_name = (
            unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode("ascii")
        )
        cleaned = _FILENAME_SAFE_RE.sub("_", ascii_name).strip("._") or "certificado"
        return cleaned[:120]
