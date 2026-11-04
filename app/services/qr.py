"""URL pública de verificação e QR Code gerado 100% em memória.

Nenhum arquivo é criado: o PNG é escrito diretamente em um ``io.BytesIO``.
"""

from __future__ import annotations

import io
from urllib.parse import urlsplit, urlunsplit
from uuid import UUID

import qrcode
from qrcode.constants import ERROR_CORRECT_Q

_MAX_QR_PAYLOAD_CHARS = 1000


def build_validation_url(base_url: str, cert_uuid: UUID) -> str:
    """Combina a URL base do portal com o UUID, sem barras duplicadas.

    ``http://x/validar/`` + uuid -> ``http://x/validar/<uuid>``. A base não pode
    conter query string nem fragmento.
    """
    parts = urlsplit(base_url.strip())
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ValueError("A URL base de validação deve ser http(s) com host")
    if parts.query or parts.fragment:
        raise ValueError("A URL base de validação não pode conter query string ou fragmento")
    segments = [segment for segment in parts.path.split("/") if segment]
    path = "/" + "/".join([*segments, str(cert_uuid)])
    return urlunsplit((parts.scheme, parts.netloc, path, "", ""))


def generate_qr_png(data: str, *, box_size: int = 10, border: int = 2) -> io.BytesIO:
    """Gera o QR Code (correção de erro Q, ~25%) como PNG em ``BytesIO`` (cursor em 0)."""
    if not data or len(data) > _MAX_QR_PAYLOAD_CHARS:
        raise ValueError("Conteúdo do QR Code vazio ou grande demais")
    qr = qrcode.QRCode(
        version=None,
        error_correction=ERROR_CORRECT_Q,
        box_size=box_size,
        border=border,
    )
    qr.add_data(data)
    qr.make(fit=True)
    image = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    buffer.seek(0)
    return buffer
