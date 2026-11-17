"""Pivotes sin red: extrae el dominio (o IP) de emails y URLs para seguir tirando del hilo."""

from __future__ import annotations

from collections.abc import AsyncIterator
from urllib.parse import urlsplit

from umbra.core.context import Context
from umbra.core.entities import Entity, Event
from umbra.core.entities import EntityType as T
from umbra.core.known import FREE_EMAIL_PROVIDERS
from umbra.core.module import Module


class Pivot(Module):
    name = "pivot"
    description = "Saca el dominio de un email y el host de una URL"
    category = "util"
    consumes = frozenset({T.EMAIL, T.URL})
    produces = frozenset({T.DOMAIN, T.IP})

    async def run(self, entity: Entity, ctx: Context) -> AsyncIterator[Event]:
        if entity.type is T.EMAIL:
            domain = entity.value.rpartition("@")[2]
            yield self.link(entity, Entity.of(T.DOMAIN, domain), "email_domain")
            if domain in FREE_EMAIL_PROVIDERS:
                yield self.finding(entity, "Cuenta en un proveedor de correo gratuito", proveedor=domain)
            return

        host = urlsplit(entity.value).hostname or ""
        target = Entity.try_of(T.IP, host) or Entity.try_of(T.DOMAIN, host)
        if target:
            yield self.link(entity, target, "hosted_on")
