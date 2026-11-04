"""Middleware ASGI que limita o tamanho do corpo das requisições (anti-DoS e zero disco).

Por que existe: o Starlette grava uploads multipart acima de 1 MiB em arquivo temporário
(``SpooledTemporaryFile``), o que violaria o requisito de zero escrita em disco. Limitar o
corpo abaixo disso mantém todo o upload em RAM e protege a API de corpos gigantes enviados
por clientes não autenticados (o FastAPI lê o corpo ANTES de resolver a autenticação).

- ``Content-Length`` acima do limite -> 413 imediato, sem ler o corpo.
- Sem ``Content-Length`` (chunked) ou com valor mentiroso -> a leitura é interrompida ao
  exceder o limite (o FastAPI converte a interrupção em 400).
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

_BODY_METHODS = frozenset({"POST", "PUT", "PATCH"})


class _BodyTooLarge(Exception):
    """Sinaliza que o corpo ultrapassou o limite durante a leitura."""


class MaxBodySizeMiddleware:
    def __init__(self, app: ASGIApp, *, max_bytes: int, path_prefix: str) -> None:
        self._app = app
        self._max_bytes = max_bytes
        self._path_prefix = path_prefix

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (
            scope["type"] != "http"
            or scope.get("method") not in _BODY_METHODS
            or not str(scope.get("path", "")).startswith(self._path_prefix)
        ):
            await self._app(scope, receive, send)
            return

        for name, value in scope.get("headers", []):
            if name == b"content-length":
                try:
                    declared = int(value)
                except ValueError:
                    await self._respond(send, 400, "Cabeçalho Content-Length inválido")
                    return
                if declared > self._max_bytes:
                    await self._respond(send, 413, self._too_large_message())
                    return

        received = 0
        response_started = False

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self._max_bytes:
                    raise _BodyTooLarge
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self._app(scope, limited_receive, tracking_send)
        except _BodyTooLarge:
            if not response_started:
                await self._respond(send, 413, self._too_large_message())

    def _too_large_message(self) -> str:
        return f"Corpo da requisição acima do limite de {self._max_bytes} bytes"

    @staticmethod
    async def _respond(send: Send, status: int, detail: str) -> None:
        body = json.dumps({"detail": detail}, ensure_ascii=False).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": [
                    (b"content-type", b"application/json; charset=utf-8"),
                    (b"content-length", str(len(body)).encode("ascii")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})
