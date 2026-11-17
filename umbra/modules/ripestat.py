"""ASN, prefijo de red y operador de una IP (RIPEstat, gratuito y sin clave)."""

from __future__ import annotations

from collections.abc import AsyncIterator

from umbra.core.context import Context
from umbra.core.entities import Entity, Event, is_public_ip
from umbra.core.entities import EntityType as T
from umbra.core.known import HOSTING_ORGS, match_provider
from umbra.core.module import Module

BASE = "https://stat.ripe.net/data"
SOURCEAPP = "umbra-osint"  # RIPEstat pide identificar la aplicación


class RipeStat(Module):
    name = "ripestat"
    description = "ASN y prefijo de una IP, y organización que opera el ASN (RIPEstat)"
    consumes = frozenset({T.IP, T.ASN})
    produces = frozenset({T.ASN, T.ORG})

    async def run(self, entity: Entity, ctx: Context) -> AsyncIterator[Event]:
        if entity.type is T.IP:
            if not is_public_ip(entity):
                return
            data = await ctx.http.get_json(
                f"{BASE}/network-info/data.json",
                params={"resource": entity.value, "sourceapp": SOURCEAPP},
            )
            info = (data or {}).get("data") or {}
            for asn in info.get("asns") or []:
                if target := Entity.try_of(T.ASN, str(asn)):
                    yield self.link(entity, target, "announced_by")
            if prefix := info.get("prefix"):
                yield self.finding(entity, "Red anunciada", prefijo=prefix)
            return

        data = await ctx.http.get_json(
            f"{BASE}/as-overview/data.json",
            params={"resource": entity.value, "sourceapp": SOURCEAPP},
        )
        holder = ((data or {}).get("data") or {}).get("holder")
        if not holder:
            return
        if org := Entity.try_of(T.ORG, holder):
            yield self.link(entity, org, "operated_by")
        if provider := match_provider(holder, HOSTING_ORGS):
            yield self.finding(
                entity,
                f"Infraestructura de {provider}",
                titular=holder,
                nota="Las IPs de CDN/cloud son compartidas: no las atribuyas al objetivo sin más.",
            )
