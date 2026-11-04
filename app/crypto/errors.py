"""Exceções do módulo criptográfico.

As mensagens são deliberadamente genéricas: nunca incluem senha, Base64,
bytes do PKCS#12 ou qualquer material de chave.
"""

from __future__ import annotations


class CryptoError(Exception):
    """Erro base do módulo criptográfico."""


class CertificateLoadError(CryptoError):
    """O PKCS#12 não pôde ser carregado ou o certificado é inadequado para assinar."""


class CertificateValidityError(CryptoError):
    """O certificado está expirado ou ainda não é válido (assinatura bloqueada)."""


class PdfSigningError(CryptoError):
    """Falha ao assinar o PDF (entrada inválida ou erro interno do assinador)."""
