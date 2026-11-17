"""Clientes de red compartidos por todos los módulos.

Centralizar aquí HTTP y DNS permite aplicar a todos los módulos, sin que
tengan que preocuparse, lo mismo: límites por servicio, reintentos con
espera, timeouts y un User-Agent honesto.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Collection, Mapping
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx

from umbra import __version__

log = logging.getLogger(__name__)

USER_AGENT = f"umbra-osint/{__version__} (passive OSINT research)"
RETRY_STATUS = frozenset({429, 500, 502, 503, 504})
# Servicios gratuitos que penalizan la concurrencia: una petición cada vez.
HOST_LIMITS = {"crt.sh": 1, "web.archive.org": 1}


class NetError(Exception):
    """Error de red con un mensaje legible."""


class NXDomain(Exception):
    """El nombre DNS consultado no existe."""


class Http:
    def __init__(self, *, timeout: float = 30.0, per_host: int = 4, retries: int = 3) -> None:
        self._client = httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json, */*;q=0.5"},
        )
        self._per_host = per_host
        self._retries = retries
        self._sems: dict[str, asyncio.Semaphore] = {}

    async def __aenter__(self) -> Http:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self._client.aclose()

    def _sem(self, host: str) -> asyncio.Semaphore:
        if host not in self._sems:
            self._sems[host] = asyncio.Semaphore(HOST_LIMITS.get(host, self._per_host))
        return self._sems[host]

    async def get(
        self,
        url: str,
        *,
        params: Mapping[str, str] | None = None,
        timeout: float | None = None,
        retries: int | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> httpx.Response:
        host = httpx.URL(url).host
        retries = self._retries if retries is None else retries
        kwargs: dict[str, Any] = {"params": params, "headers": headers}
        if timeout is not None:
            kwargs["timeout"] = timeout
        last: Exception | None = None
        for attempt in range(retries + 1):
            wait = min(2.0**attempt, 30.0)
            async with self._sem(host):
                try:
                    resp = await self._client.get(url, **kwargs)
                except httpx.TransportError as exc:
                    last = exc
                    log.debug("%s: %r (intento %d)", host, exc, attempt + 1)
                else:
                    if resp.status_code not in RETRY_STATUS or attempt == retries:
                        return resp
                    wait = _retry_after(resp, wait)
                    last = NetError(f"HTTP {resp.status_code}")
                    log.debug("%s: HTTP %d, reintento en %.0fs", host, resp.status_code, wait)
            if attempt < retries:
                await asyncio.sleep(wait)
        reason = "tiempo de espera agotado" if isinstance(last, httpx.TimeoutException) else repr(last)
        raise NetError(f"{host} no responde tras {retries + 1} intento(s): {reason}")

    async def get_json(
        self,
        url: str,
        *,
        params: Mapping[str, str] | None = None,
        timeout: float | None = None,
        retries: int | None = None,
        headers: Mapping[str, str] | None = None,
        missing: Collection[int] = (404,),
    ) -> Any | None:
        """GET que devuelve JSON, o ``None`` si el recurso no existe (códigos en ``missing``)."""
        resp = await self.get(url, params=params, timeout=timeout, retries=retries, headers=headers)
        if resp.status_code in missing:
            return None
        if resp.status_code >= 400:
            raise NetError(f"{resp.url.host} respondió HTTP {resp.status_code}")
        if not resp.content.strip():
            return None
        try:
            return resp.json()
        except ValueError as exc:
            raise NetError(f"{resp.url.host} no devolvió JSON válido") from exc


    async def get_text(
        self,
        url: str,
        *,
        params: Mapping[str, str] | None = None,
        timeout: float | None = None,
        retries: int | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> str:
        resp = await self.get(url, params=params, timeout=timeout, retries=retries, headers=headers)
        if resp.status_code >= 400:
            raise NetError(f"{resp.url.host} respondió HTTP {resp.status_code}")
        return resp.text


def _retry_after(resp: httpx.Response, default: float) -> float:
    try:
        return min(float(resp.headers.get("Retry-After", default)), 30.0)
    except ValueError:
        return default


class Dns:
    def __init__(
        self, nameservers: list[str] | None = None, *, timeout: float = 5.0, concurrency: int = 50
    ) -> None:
        try:
            self._resolver = dns.asyncresolver.Resolver(configure=not nameservers)
        except dns.resolver.NoResolverConfiguration:
            self._resolver = dns.asyncresolver.Resolver(configure=False)
            nameservers = nameservers or ["1.1.1.1", "8.8.8.8"]
        if nameservers:
            self._resolver.nameservers = list(nameservers)
        self._resolver.lifetime = timeout
        self._sem = asyncio.Semaphore(concurrency)

    async def query(self, name: str, rdtype: str) -> list[str]:
        """Registros como texto. Lista vacía si no hay respuesta; ``NXDomain`` si el nombre no existe."""
        async with self._sem:
            try:
                answer = await self._resolver.resolve(name, rdtype, raise_on_no_answer=False)
            except dns.resolver.NXDOMAIN as exc:
                raise NXDomain(name) from exc
            except (dns.resolver.NoNameservers, dns.resolver.NoAnswer, dns.exception.Timeout):
                return []
        if answer.rrset is None:
            return []
        if rdtype == "TXT":
            return [b"".join(r.strings).decode("utf-8", "replace") for r in answer.rrset]
        return [r.to_text() for r in answer.rrset]
