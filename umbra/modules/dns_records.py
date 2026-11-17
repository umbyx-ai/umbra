"""Registros DNS y postura de seguridad del correo (SPF / DMARC)."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Any, NamedTuple

from umbra.core.context import Context
from umbra.core.entities import Entity, Event, Severity
from umbra.core.entities import EntityType as T
from umbra.core.known import (
    MX_PROVIDERS,
    NS_PROVIDERS,
    SPF_SENDERS,
    match_provider,
    match_verifications,
)
from umbra.core.module import Module
from umbra.core.net import NXDomain


class Check(NamedTuple):
    title: str
    severity: Severity
    data: dict[str, Any]


def analyze_spf(txts: list[str]) -> list[Check]:
    spf = [t for t in txts if t.lower().startswith("v=spf1")]
    if not spf:
        return [Check("Sin registro SPF", Severity.LOW, {
            "nota": "Ningún registro dice qué servidores pueden enviar correo en nombre del dominio.",
        })]
    if len(spf) > 1:
        return [Check("Varios registros SPF (configuración inválida, RFC 7208)", Severity.MEDIUM, {
            "registros": spf,
        })]

    record = spf[0]
    includes: list[str] = []
    qualifier: str | None = None
    for term in record.split()[1:]:
        low = term.lower()
        if low.startswith("include:"):
            includes.append(low[8:])
        elif low.startswith("redirect="):
            includes.append(low[9:])
        elif low.lstrip("+-~?") == "all":
            qualifier = low[0] if low[0] in "+-~?" else "+"

    data = {"registro": record, "includes": includes}
    checks: list[Check] = []
    match qualifier:
        case "+":
            checks.append(Check("SPF permite a cualquier servidor enviar correo (+all)", Severity.HIGH, data))
        case "?":
            checks.append(Check("SPF neutral (?all): no protege frente a suplantación", Severity.LOW, data))
        case "~":
            checks.append(Check("SPF en modo softfail (~all)", Severity.INFO, data))
        case "-":
            checks.append(Check("SPF estricto (-all)", Severity.INFO, data))
        case None if not any(t.lower().startswith("redirect=") for t in record.split()):
            checks.append(Check("SPF sin mecanismo 'all' final", Severity.LOW, data))

    senders = sorted({s for inc in includes if (s := match_provider(inc, SPF_SENDERS))})
    if senders:
        checks.append(Check("Servicios autorizados a enviar correo (SPF)", Severity.INFO, {"servicios": senders}))
    return checks


def parse_dmarc(record: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in record.split(";"):
        key, _, value = part.partition("=")
        if key.strip():
            tags[key.strip().lower()] = value.strip()
    return tags


def _dmarc_records(txts: list[str]) -> list[str]:
    return [t for t in txts if t.replace(" ", "").lower().startswith("v=dmarc1")]


def analyze_dmarc(txts: list[str]) -> list[Check]:
    records = _dmarc_records(txts)
    if not records:
        return [Check("Sin registro DMARC", Severity.MEDIUM, {
            "nota": "Sin DMARC, los servidores receptores no tienen política para rechazar "
                    "correos que suplanten al dominio.",
        })]
    tags = parse_dmarc(records[0])
    policy = tags.get("p", "").lower()
    data = {
        "registro": records[0],
        "politica": policy or "(vacía)",
        "subdominios": tags.get("sp", policy),
        "pct": tags.get("pct", "100"),
    }
    if policy == "none":
        return [Check("DMARC en modo monitorización (p=none): no bloquea suplantaciones", Severity.LOW, data)]
    if policy in ("quarantine", "reject"):
        return [Check(f"DMARC activo (p={policy})", Severity.INFO, data)]
    return [Check("DMARC con política inválida", Severity.MEDIUM, data)]


def dmarc_report_emails(txts: list[str]) -> list[str]:
    """Buzones de rua/ruf: delatan quién analiza los informes DMARC (a veces un tercero)."""
    emails: list[str] = []
    for record in _dmarc_records(txts):
        tags = parse_dmarc(record)
        for uri in (tags.get("rua", "") + "," + tags.get("ruf", "")).split(","):
            uri = uri.strip()
            if uri.lower().startswith("mailto:"):
                address = uri[7:].split("!", 1)[0]  # quita sufijos tipo "!10m"
                if address and address not in emails:
                    emails.append(address)
    return emails


class DnsRecords(Module):
    name = "dns"
    description = "Registros A/AAAA/CNAME; en la raíz además MX, NS, TXT, SPF y DMARC"
    consumes = frozenset({T.DOMAIN})
    produces = frozenset({T.IP, T.DOMAIN, T.EMAIL})

    async def run(self, entity: Entity, ctx: Context) -> AsyncIterator[Event]:
        name = entity.value
        is_root = ctx.scope.is_root(entity)
        try:
            cnames = await ctx.dns.query(name, "CNAME")
        except NXDomain:
            if is_root:
                yield self.finding(entity, "El dominio no existe (NXDOMAIN)")
            return

        for value in cnames:
            if target := Entity.try_of(T.DOMAIN, value):
                yield self.link(entity, target, "cname")

        records = await _queries(ctx, name, ["A", "AAAA"])
        if records is None:
            if cnames:
                yield self.finding(
                    entity,
                    "CNAME colgante: el destino no existe (posible subdomain takeover)",
                    Severity.MEDIUM,
                    cname=cnames,
                    nota="Comprueba a mano si el servicio de destino permite reclamar ese nombre.",
                )
            return
        for ip in records["A"] + records["AAAA"]:
            yield self.link(entity, Entity.of(T.IP, ip), "resolves_to")

        if not is_root or cnames:
            return
        async for event in self._root_records(entity, ctx):
            yield event

    async def _root_records(self, entity: Entity, ctx: Context) -> AsyncIterator[Event]:
        name = entity.value
        records = await _queries(ctx, name, ["MX", "NS", "TXT"])
        if records is None:
            return

        mail_providers: set[str] = set()
        for value in records["MX"]:
            host = value.split()[-1]
            if host == ".":
                yield self.finding(entity, "Null MX: el dominio declara que no recibe correo")
                continue
            if mx := Entity.try_of(T.DOMAIN, host):
                yield self.link(entity, mx, "mail_server")
                if provider := match_provider(mx.value, MX_PROVIDERS):
                    mail_providers.add(provider)
        if mail_providers:
            yield self.finding(entity, "Proveedor de correo", proveedores=sorted(mail_providers))

        dns_providers: set[str] = set()
        for value in records["NS"]:
            if ns := Entity.try_of(T.DOMAIN, value):
                yield self.link(entity, ns, "nameserver")
                if provider := match_provider(ns.value, NS_PROVIDERS):
                    dns_providers.add(provider)
        if dns_providers:
            yield self.finding(entity, "Proveedor DNS", proveedores=sorted(dns_providers))

        txts = records["TXT"]
        if txts:
            yield self.finding(entity, "Registros TXT", registros=txts)
        if services := match_verifications(txts):
            yield self.finding(entity, "Servicios de terceros verificados (TXT)", servicios=services)
        for check in analyze_spf(txts):
            yield self.finding(entity, check.title, check.severity, **check.data)

        try:
            dmarc = await ctx.dns.query(f"_dmarc.{name}", "TXT")
        except NXDomain:
            dmarc = []
        for check in analyze_dmarc(dmarc):
            yield self.finding(entity, check.title, check.severity, **check.data)
        for address in dmarc_report_emails(dmarc):
            if email := Entity.try_of(T.EMAIL, address):
                yield self.link(entity, email, "dmarc_reports_to")


async def _queries(ctx: Context, name: str, rdtypes: list[str]) -> dict[str, list[str]] | None:
    """Lanza varias consultas a la vez. ``None`` si el nombre no existe."""
    results = await asyncio.gather(*(ctx.dns.query(name, t) for t in rdtypes), return_exceptions=True)
    if any(isinstance(r, NXDomain) for r in results):
        return None
    for r in results:
        if isinstance(r, BaseException):
            raise r
    return dict(zip(rdtypes, results, strict=True))  # type: ignore[arg-type]
