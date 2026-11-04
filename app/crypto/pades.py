"""Assinatura PAdES (baseline B-B) de PDFs inteiramente em memória.

``io.BytesIO`` de entrada -> ``IncrementalPdfFileWriter`` + ``PdfSignatureMetadata``
(``SigSeedSubFilter.PADES``) -> ``io.BytesIO`` assinado de saída.

Escopo: assinatura PAdES-B-B com cadeia embutida. Carimbo do tempo (PAdES-T/LTA)
e política de assinatura ICP-Brasil (AD-RB) não são aplicados aqui.
"""

from __future__ import annotations

import io
import logging
import re

from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import fields, signers

from app.crypto.credentials import SigningCredentials
from app.crypto.errors import CryptoError, PdfSigningError

logger = logging.getLogger(__name__)

MAX_PDF_BYTES = 25 * 1024 * 1024
_FIELD_NAME_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")


async def sign_pdf_pades(
    pdf: io.BytesIO | bytes,
    credentials: SigningCredentials,
    *,
    field_name: str = "Signature1",
    reason: str | None = None,
    location: str | None = None,
) -> io.BytesIO:
    """Assina o PDF e devolve um novo ``BytesIO`` posicionado no início.

    O buffer de entrada não é fechado nem alterado. Levanta
    ``CertificateValidityError`` se o certificado estiver fora da validade e
    ``PdfSigningError`` para entrada inválida ou falha do assinador.
    """
    if not _FIELD_NAME_RE.fullmatch(field_name):
        raise PdfSigningError("Nome do campo de assinatura inválido")

    credentials.ensure_valid()

    source = io.BytesIO(pdf) if isinstance(pdf, (bytes, bytearray)) else pdf
    source.seek(0, io.SEEK_END)
    size = source.tell()
    source.seek(0)
    if size == 0 or size > MAX_PDF_BYTES:
        raise PdfSigningError("PDF vazio ou acima do tamanho máximo permitido")
    if source.read(5) != b"%PDF-":
        raise PdfSigningError("A entrada não é um PDF válido")
    source.seek(0)

    output = io.BytesIO()
    try:
        writer = IncrementalPdfFileWriter(source)
        metadata = signers.PdfSignatureMetadata(
            field_name=field_name,
            subfilter=fields.SigSeedSubFilter.PADES,
            md_algorithm="sha256",
            reason=reason,
            location=location,
        )
        pdf_signer = signers.PdfSigner(metadata, signer=credentials.signer)
        await pdf_signer.async_sign_pdf(writer, output=output, in_place=False)
    except CryptoError:
        raise
    except Exception as exc:  # noqa: BLE001 - encapsula erros do pyHanko/asn1crypto
        logger.error("Falha na assinatura PAdES: %s", type(exc).__name__)
        raise PdfSigningError("Falha ao assinar o PDF") from exc
    finally:
        source.seek(0)

    output.seek(0)
    return output
