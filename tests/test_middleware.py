"""Limitador de corpo ASGI: o upload precisa ficar abaixo do limite de rollover do Starlette (1 MiB)."""

from __future__ import annotations

import asyncio
from typing import Any

from app.api.middleware import MaxBodySizeMiddleware

PATH = "/api/v1/certificates/batch"


async def _downstream(scope: Any, receive: Any, send: Any) -> None:
    total = 0
    while True:
        message = await receive()
        total += len(message.get("body", b""))
        if not message.get("more_body"):
            break
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": str(total).encode()})


async def _call(path: str, method: str, headers: list[tuple[bytes, bytes]], chunks: list[bytes]) -> tuple[int, bytes]:
    app = MaxBodySizeMiddleware(_downstream, max_bytes=100, path_prefix="/api/v1/certificates")
    sent: list[Any] = []
    iterator = iter(chunks)

    async def receive() -> Any:
        try:
            chunk = next(iterator)
        except StopIteration:
            return {"type": "http.disconnect"}
        return {"type": "http.request", "body": chunk, "more_body": chunk is not chunks[-1]}

    async def send(message: Any) -> None:
        sent.append(message)

    await app({"type": "http", "method": method, "path": path, "headers": headers}, receive, send)
    status = next(m["status"] for m in sent if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return status, body


def run(*args: Any) -> tuple[int, bytes]:
    return asyncio.run(_call(*args))


def test_declared_length_above_limit_is_rejected_without_reading() -> None:
    assert run(PATH, "POST", [(b"content-length", b"500")], [b"x" * 500])[0] == 413


def test_body_within_limit_passes_through() -> None:
    assert run(PATH, "POST", [(b"content-length", b"50")], [b"x" * 50]) == (200, b"50")


def test_chunked_body_exceeding_limit_is_cut() -> None:
    assert run(PATH, "POST", [], [b"x" * 60, b"y" * 60])[0] == 413


def test_exactly_at_limit_is_accepted() -> None:
    assert run(PATH, "POST", [], [b"x" * 60, b"y" * 40]) == (200, b"100")


def test_invalid_content_length_is_400() -> None:
    assert run(PATH, "POST", [(b"content-length", b"abc")], [b"x"])[0] == 400


def test_other_paths_and_methods_are_ignored() -> None:
    assert run("/healthz", "POST", [(b"content-length", b"9999")], [b"x"])[0] == 200
    assert run(PATH, "GET", [(b"content-length", b"9999")], [b"x"])[0] == 200
