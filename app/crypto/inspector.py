"""Perícia criptográfica de PDFs assinados (PAdES) 100% em memória.

Entrada: ``bytes`` do PDF enviado por um terceiro (NÃO CONFIÁVEL). Saída: ``PdfInspection``
com o resultado por assinatura (íntegra? válida? confiável?). A decisão final (VALID,
INVALID_TAMPERED...) é tomada pelo serviço de validação, que também cruza o hash com o banco.

Pontos de segurança:
- as âncoras de confiança vêm SOMENTE de ``SigningCredentials`` (Etapa 2); certificados
  embutidos no PDF enviado nunca viram âncora;
- ``allow_fetching=False``: nenhuma consulta de rede (CRL/OCSP/AIA) é disparada por um PDF hostil;
- o parsing e a verificação rodam numa thread própria (``asyncio.to_thread`` + ``asyncio.run``),
  para o trabalho de CPU não bloquear o event loop; usa a API assíncrona do pyHanko
  (``async_validate_pdf_signature``);
- limite de assinaturas por arquivo, para impedir PDFs forjados com milhares de assinaturas;
- nenhum CN/subject do assinante é devolvido (em A1 e-CPF/e-CNPJ pode conter CPF/CNPJ).
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from app.crypto.credentials import SigningCredentials

logger = logging.getLogger(__name__)

MAX_SIGNATURES_PER_FILE = 5


@dataclass(frozen=True, slots=True)
class SignatureFinding:
    """Resultado da verificação de UMA assinatura embutida."""

    intact: bool | None = None
    valid: bool | None = None
    trusted: bool | None = None
    covers_entire_file: bool | None = None
    signer_fingerprint: str | None = None
    summary: str | None = None
    error: str | None = None  # preenchido quando a assinatura não pôde ser verificada


@dataclass(frozen=True, slots=True)
class PdfInspection:
    """Resultado da perícia de um PDF."""

    readable: bool
    signatures: tuple[SignatureFinding, ...] = ()
    problem: str | None = None  # motivo curto quando ``readable`` é False ou há excesso de assinaturas
    evaluated_at: datetime | None = None


class PdfSignatureInspector(Protocol):
    async def inspect(self, pdf: bytes, *, moment: datetime | None = None) -> PdfInspection: ...


def _format_fingerprint(der: bytes) -> str:
    raw = hashlib.sha256(der).hexdigest().upper()
    return ":".join(raw[i : i + 2] for i in range(0, len(raw), 2))


class PyHankoPdfInspector:
    """Implementação baseada em pyHanko (``async_validate_pdf_signature``)."""

    def __init__(self, credentials: SigningCredentials) -> None:
        self._credentials = credentials

    async def inspect(self, pdf: bytes, *, moment: datetime | None = None) -> PdfInspection:
        """Inspeciona o PDF numa thread dedicada. ``moment`` = instante da validação do certificado.

        Informar a data de emissão registrada no banco evita que todos os certificados
        passem a ser rejeitados quando o A1 vence: a assinatura é avaliada como estava na emissão.
        """
        return await asyncio.to_thread(self._inspect_in_thread, pdf, moment)

    # ------------------------------------------------------------------
    def _inspect_in_thread(self, pdf: bytes, moment: datetime | None) -> PdfInspection:
        return asyncio.run(self._inspect_async(pdf, moment))

    async def _inspect_async(self, pdf: bytes, moment: datetime | None) -> PdfInspection:
        from pyhanko.pdf_utils.reader import PdfFileReader
        from pyhanko.sign.validation import async_validate_pdf_signature
        from pyhanko_certvalidator import ValidationContext

        try:
            reader = PdfFileReader(io.BytesIO(pdf), strict=False)
            embedded = list(reader.embedded_signatures)
        except Exception as exc:  # noqa: BLE001 - PDF hostil/corrompido: qualquer falha = ilegível
            logger.info("PDF enviado não pôde ser lido: %s", type(exc).__name__)
            return PdfInspection(readable=False, problem="Arquivo PDF corrompido ou ilegível")

        if not embedded:
            return PdfInspection(readable=True, problem="Nenhuma assinatura digital encontrada")
        if len(embedded) > MAX_SIGNATURES_PER_FILE:
            return PdfInspection(
                readable=True, problem="Quantidade anormal de assinaturas digitais no arquivo"
            )

        findings: list[SignatureFinding] = []
        for signature in embedded:
            # Um contexto por assinatura: o cache interno do validador não é compartilhado.
            context = ValidationContext(
                trust_roots=list(self._credentials.trust_roots),
                other_certs=list(self._credentials.intermediates),
                allow_fetching=False,
                moment=moment,
            )
            try:
                status = await async_validate_pdf_signature(
                    signature, signer_validation_context=context
                )
            except Exception as exc:  # noqa: BLE001 - CMS malformado etc.: assinatura não verificável
                logger.info("Assinatura não verificável: %s", type(exc).__name__)
                findings.append(SignatureFinding(error="Assinatura corrompida ou não verificável"))
                continue
            findings.append(self._to_finding(status))
        return PdfInspection(readable=True, signatures=tuple(findings), evaluated_at=moment)

    @staticmethod
    def _to_finding(status: Any) -> SignatureFinding:
        signing_cert = getattr(status, "signing_cert", None)
        fingerprint: str | None = None
        if signing_cert is not None:
            fingerprint = _format_fingerprint(signing_cert.dump())
        coverage = getattr(status, "coverage", None)
        covers_entire = None if coverage is None else getattr(coverage, "name", "") == "ENTIRE_FILE"
        try:
            summary = str(status.summary())[:200]
        except Exception:  # noqa: BLE001 - o resumo é apenas informativo
            summary = None
        return SignatureFinding(
            intact=bool(status.intact),
            valid=bool(status.valid),
            trusted=bool(status.trusted),
            covers_entire_file=covers_entire,
            signer_fingerprint=fingerprint,
            summary=summary,
        )
