"""Puente entre el menú (síncrono) y los clientes de red asíncronos del núcleo."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import TypeVar

from umbra.core.net import Dns, Http

T = TypeVar("T")


def run(job: Callable[[Http, Dns], Awaitable[T]], *, timeout: float = 30.0) -> T:
    """Ejecuta ``job(http, dns)`` con clientes recién creados y devuelve su resultado."""

    async def main() -> T:
        async with Http(timeout=timeout) as http:
            return await job(http, Dns())

    return asyncio.run(main())


async def safe(coro: Awaitable[T], errors: list[str], label: str) -> T | None:
    """Espera ``coro``; si falla, apunta el error en ``errors`` y devuelve ``None``.

    Sirve para consultar varias fuentes a la vez sin que una caída tumbe a las demás.
    """
    try:
        return await coro
    except Exception as exc:  # noqa: BLE001 - se informa al usuario
        errors.append(f"{label}: {exc or exc.__class__.__name__}")
        return None
