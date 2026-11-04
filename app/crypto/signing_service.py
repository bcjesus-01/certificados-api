"""Adaptador do assinador PAdES para o orquestrador de emissão."""

from __future__ import annotations

import io

from app.crypto.credentials import SigningCredentials
from app.crypto.pades import sign_pdf_pades


class PadesSigningService:
    """Assina PDFs em memória com o certificado A1 carregado (Etapa 2)."""

    def __init__(
        self,
        credentials: SigningCredentials,
        *,
        reason: str | None = None,
        location: str | None = None,
    ) -> None:
        self._credentials = credentials
        self._reason = reason
        self._location = location

    @property
    def fingerprint(self) -> str:
        return self._credentials.info.sha256_fingerprint

    @property
    def serial_number(self) -> str:
        return self._credentials.info.serial_number

    def ensure_ready(self) -> None:
        """Levanta ``CertificateValidityError`` se o certificado estiver expirado/não vigente."""
        self._credentials.ensure_valid()

    async def sign(self, pdf: io.BytesIO) -> io.BytesIO:
        return await sign_pdf_pades(
            pdf, self._credentials, reason=self._reason, location=self._location
        )
