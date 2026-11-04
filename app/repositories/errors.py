"""Erros da camada de persistência (sem dependência de asyncpg)."""

from __future__ import annotations


class RepositoryError(Exception):
    """Erro base da camada de persistência."""


class DuplicateCertificateError(RepositoryError):
    """Violação de unicidade (UUID, hash do PDF ou chave do objeto já registrados)."""


class PersistenceError(RepositoryError):
    """Falha ao gravar no banco.

    ``definitive=True``: o banco respondeu com erro, a transação foi revertida e NADA
    foi gravado. ``definitive=False``: o resultado é ambíguo (conexão perdida, timeout,
    cancelamento) e a gravação pode ter sido confirmada antes da falha.
    """

    def __init__(self, message: str, *, definitive: bool) -> None:
        super().__init__(message)
        self.definitive = definitive


class RepositoryUnavailableError(RepositoryError):
    """Banco de dados inacessível ou com falha numa operação de leitura/escrita simples."""
