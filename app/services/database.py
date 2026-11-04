"""Cliente assíncrono de PostgreSQL (Supabase) baseado em asyncpg.

Mantém um pool de conexões e expõe helpers finos. Erros específicos do
asyncpg (ex.: ``UniqueViolationError``) propagam intactos para que as camadas
superiores possam tratá-los; apenas a falha de conexão é encapsulada.
"""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator, Sequence
from contextlib import asynccontextmanager
from typing import Any

import asyncpg

from app.core.config import Settings, get_settings

logger = logging.getLogger(__name__)


class DatabaseError(Exception):
    """Falha ao conectar ou usar o pool de banco de dados."""


def _json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)


class Database:
    """Pool de conexões com ciclo de vida explícito (connect/close)."""

    def __init__(self, settings: Settings | None = None) -> None:
        self._settings = settings or get_settings()
        self._pool: asyncpg.Pool | None = None

    @staticmethod
    async def _init_connection(conn: asyncpg.Connection) -> None:
        # jsonb/json <-> dict/list de forma transparente.
        for type_name in ("jsonb", "json"):
            await conn.set_type_codec(
                type_name,
                encoder=_json_dumps,
                decoder=json.loads,
                schema="pg_catalog",
            )

    async def connect(self) -> None:
        if self._pool is not None:
            return
        s = self._settings
        try:
            self._pool = await asyncpg.create_pool(
                dsn=s.database_url.get_secret_value(),
                min_size=s.db_pool_min_size,
                max_size=s.db_pool_max_size,
                command_timeout=s.db_command_timeout,
                ssl=s.db_ssl,
                statement_cache_size=s.db_statement_cache_size,
                init=self._init_connection,
            )
        except (OSError, asyncpg.PostgresError, asyncpg.InterfaceError) as exc:
            # Mensagens do asyncpg/SO não incluem a senha; o motivo ajuda o diagnóstico.
            logger.error("Falha ao criar o pool de conexões do banco: %s", type(exc).__name__)
            raise DatabaseError(
                f"Não foi possível conectar ao banco de dados ({type(exc).__name__}: {exc})"
            ) from exc
        logger.info("Pool de banco inicializado (min=%s, max=%s)", s.db_pool_min_size, s.db_pool_max_size)

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None
            logger.info("Pool de banco encerrado")

    @property
    def pool(self) -> asyncpg.Pool:
        if self._pool is None:
            raise DatabaseError("Pool não inicializado: chame connect() antes de usar o banco")
        return self._pool

    @asynccontextmanager
    async def acquire(self) -> AsyncIterator[asyncpg.Connection]:
        async with self.pool.acquire() as conn:
            yield conn

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[asyncpg.Connection]:
        """Conexão dentro de uma transação (commit/rollback automáticos)."""
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                yield conn

    async def fetch_one(self, query: str, *args: Any) -> asyncpg.Record | None:
        async with self.pool.acquire() as conn:
            return await conn.fetchrow(query, *args)

    async def fetch_all(self, query: str, *args: Any) -> list[asyncpg.Record]:
        async with self.pool.acquire() as conn:
            return list(await conn.fetch(query, *args))

    async def execute(self, query: str, *args: Any) -> str:
        async with self.pool.acquire() as conn:
            return await conn.execute(query, *args)

    async def execute_many(self, query: str, args: Sequence[Sequence[Any]]) -> None:
        """Executa a mesma query para vários conjuntos de parâmetros (atômico)."""
        async with self.transaction() as conn:
            await conn.executemany(query, args)

    async def healthcheck(self) -> bool:
        try:
            async with self.pool.acquire() as conn:
                return await conn.fetchval("select 1") == 1
        except (asyncpg.PostgresError, asyncpg.InterfaceError, OSError, DatabaseError):
            logger.warning("Healthcheck do banco falhou")
            return False
