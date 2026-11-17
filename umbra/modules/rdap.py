"""Datos de registro del dominio vía RDAP (el sucesor estructurado de WHOIS)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Any

from umbra.core.context import Context
from umbra.core.entities import Entity, Event, Severity
from umbra.core.entities import EntityType as T
from umbra.core.module import Module


def _vcard_name(entity: dict[str, Any]) -> str | None:
    vcard = entity.get("vcardArray")
    if isinstance(vcard, list) and len(vcard) == 2:
        for item in vcard[1]:
            if isinstance(item, list) and len(item) >= 4 and item[0] == "fn" and item[3]:
                return str(item[3])
    return None


def parse_rdap_domain(data: dict[str, Any]) -> dict[str, Any]:
    events = {
        e.get("eventAction"): e.get("eventDate")
        for e in data.get("events") or []
        if isinstance(e, dict)
    }
    registrar = None
    for ent in data.get("entities") or []:
        if "registrar" in (ent.get("roles") or []):
            registrar = _vcard_name(ent) or ent.get("handle")
            break
    nameservers = sorted({
        ns["ldhName"].lower().rstrip(".")
        for ns in data.get("nameservers") or []
        if isinstance(ns, dict) and ns.get("ldhName")
    })
    info = {
        "registrador": registrar,
        "creado": events.get("registration"),
        "expira": events.get("expiration"),
        "actualizado": events.get("last changed"),
        "estado": data.get("status") or [],
        "nameservers": nameservers,
        "dnssec": (data.get("secureDNS") or {}).get("delegationSigned"),
    }
    return {k: v for k, v in info.items() if v is not None and v != [] and v != ""}


def parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


class Rdap(Module):
    name = "rdap"
    description = "Registrador, fechas de alta/caducidad y DNSSEC del dominio (RDAP)"
    consumes = frozenset({T.DOMAIN})
    produces = frozenset({T.ORG})
    roots_only = True

    async def run(self, entity: Entity, ctx: Context) -> AsyncIterator[Event]:
        data = await ctx.http.get_json(f"https://rdap.org/domain/{entity.value}", missing=(400, 404))
        if not isinstance(data, dict):
            yield self.finding(
                entity,
                "RDAP sin datos para este dominio",
                nota="Puede ser un subdominio o un TLD sin RDAP público (p. ej. .es).",
            )
            return

        info = parse_rdap_domain(data)
        yield self.finding(entity, "Datos de registro (RDAP)", **info)
        if registrar := info.get("registrador"):
            if org := Entity.try_of(T.ORG, registrar):
                yield self.link(entity, org, "registrar")

        now = datetime.now(UTC)
        if expires := parse_date(info.get("expira")):
            days = (expires - now).days
            if days < 0:
                yield self.finding(entity, "El dominio figura como caducado", Severity.MEDIUM, expira=info["expira"])
            elif days <= 30:
                yield self.finding(entity, "El dominio caduca pronto", Severity.MEDIUM, dias=days, expira=info["expira"])
        if created := parse_date(info.get("creado")):
            age = (now - created).days
            if age <= 90:
                yield self.finding(
                    entity,
                    "Dominio registrado recientemente",
                    Severity.LOW,
                    dias=age,
                    nota="Los dominios recién creados son habituales en campañas de phishing.",
                )
