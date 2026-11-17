"""Subdominios a partir de los logs públicos de Certificate Transparency (crt.sh).

Cada certificado TLS emitido queda registrado en logs públicos. Es una de las
mejores fuentes pasivas de subdominios: no tocamos al objetivo para nada.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterable
from typing import Any

from umbra.core.context import Context
from umbra.core.entities import Entity, Event
from umbra.core.entities import EntityType as T
from umbra.core.module import Module
from umbra.core.net import NetError


def parse_crtsh(records: Iterable[dict[str, Any]], root: str) -> tuple[set[str], set[str]]:
    """Devuelve (subdominios, emails) del dominio ``root`` presentes en la respuesta de crt.sh."""
    subdomains: set[str] = set()
    emails: set[str] = set()
    suffix = "." + root
    for record in records:
        for field in ("name_value", "common_name"):
            for raw in str(record.get(field) or "").splitlines():
                raw = raw.strip()
                if "@" in raw:
                    email = Entity.try_of(T.EMAIL, raw)
                    if email and email.value.endswith(("@" + root, suffix)):
                        emails.add(email.value)
                    continue
                domain = Entity.try_of(T.DOMAIN, raw)
                if domain and domain.value.endswith(suffix):
                    subdomains.add(domain.value)
    return subdomains, emails


class CrtSh(Module):
    name = "crtsh"
    description = "Subdominios y emails en certificados TLS públicos (Certificate Transparency)"
    consumes = frozenset({T.DOMAIN})
    produces = frozenset({T.DOMAIN, T.EMAIL})
    roots_only = True

    async def run(self, entity: Entity, ctx: Context) -> AsyncIterator[Event]:
        data = await ctx.http.get_json(
            "https://crt.sh/", params={"q": f"%.{entity.value}", "output": "json"}, timeout=90
        )
        if data is None:  # crt.sh devuelve a veces un 200 vacío cuando está saturado
            raise NetError("crt.sh devolvió una respuesta vacía (suele estar saturado; vuelve a intentarlo)")
        subdomains, emails = parse_crtsh(data, entity.value)
        for sub in sorted(subdomains):
            yield self.link(entity, Entity(T.DOMAIN, sub), "subdomain")
        for email in sorted(emails):
            yield self.link(entity, Entity(T.EMAIL, email), "cert_contact")
        yield self.finding(
            entity,
            "Subdominios en certificados públicos",
            subdominios=len(subdomains),
            certificados=len(data),
        )
