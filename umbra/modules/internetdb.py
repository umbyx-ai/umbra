"""Puertos y vulnerabilidades conocidas de una IP sin escanearla (Shodan InternetDB).

Es la alternativa pasiva al ``nmap -p-``: Shodan ya escaneó Internet y nosotros
solo consultamos su base de datos. El objetivo no recibe ni un paquete.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from umbra.core.context import Context
from umbra.core.entities import Entity, Event, Severity, is_public_ip
from umbra.core.entities import EntityType as T
from umbra.core.known import RISKY_PORTS
from umbra.core.module import Module


class InternetDb(Module):
    name = "internetdb"
    description = "Puertos, software (CPE) y CVEs conocidos de una IP sin escanearla (Shodan InternetDB)"
    consumes = frozenset({T.IP})
    produces = frozenset({T.DOMAIN})

    async def run(self, entity: Entity, ctx: Context) -> AsyncIterator[Event]:
        if not is_public_ip(entity):
            return
        data = await ctx.http.get_json(f"https://internetdb.shodan.io/{entity.value}")
        if not isinstance(data, dict):
            return

        ports = sorted(data.get("ports") or [])
        if ports:
            yield self.finding(
                entity,
                "Puertos expuestos (datos de Shodan)",
                puertos=ports,
                software=data.get("cpes") or [],
                etiquetas=data.get("tags") or [],
            )
            risky = {str(p): RISKY_PORTS[p] for p in ports if p in RISKY_PORTS}
            if risky:
                yield self.finding(entity, "Servicios sensibles expuestos a Internet", Severity.MEDIUM, servicios=risky)

        vulns = sorted(data.get("vulns") or [])
        if vulns:
            yield self.finding(
                entity,
                "CVE potenciales (por versión de software, sin verificar)",
                Severity.MEDIUM,
                total=len(vulns),
                cves=vulns[:100],
            )

        for host in data.get("hostnames") or []:
            if domain := Entity.try_of(T.DOMAIN, host):
                yield self.link(entity, domain, "hostname")
