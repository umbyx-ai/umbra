"""Alcance de la investigación.

Sin alcance, un pivote ingenuo se descontrola: el MX de example.com apunta a
google.com, y de ahí acabaríamos investigando a Google. El alcance dice qué
dominios son "del objetivo"; el resto se registra pero no se expande.
"""

from __future__ import annotations

from collections.abc import Iterable
from urllib.parse import urlsplit

from umbra.core.entities import Entity, EntityType, normalize
from umbra.core.known import FREE_EMAIL_PROVIDERS


def domain_of(entity: Entity) -> str | None:
    """Dominio asociado a una entidad (el propio dominio, el de un email o el host de una URL)."""
    match entity.type:
        case EntityType.DOMAIN:
            return entity.value
        case EntityType.EMAIL:
            return entity.value.rpartition("@")[2]
        case EntityType.URL:
            host = urlsplit(entity.value).hostname
            domain = Entity.try_of(EntityType.DOMAIN, host) if host else None
            return domain.value if domain else None
    return None


class Scope:
    def __init__(self, roots: Iterable[str] = ()) -> None:
        self.roots: frozenset[str] = frozenset(normalize(EntityType.DOMAIN, r) for r in roots)

    @classmethod
    def from_seed(cls, seed: Entity, extra: Iterable[str] = ()) -> Scope:
        roots = list(extra)
        domain = domain_of(seed)
        # Investigar a alguien@gmail.com no significa investigar gmail.com
        if domain and not (seed.type is EntityType.EMAIL and domain in FREE_EMAIL_PROVIDERS):
            roots.append(domain)
        return cls(roots)

    def is_root(self, entity: Entity) -> bool:
        return entity.type is EntityType.DOMAIN and entity.value in self.roots

    def contains(self, domain: str) -> bool:
        return any(domain == root or domain.endswith("." + root) for root in self.roots)

    def allows_expansion(self, entity: Entity) -> bool:
        if entity.type in (EntityType.DOMAIN, EntityType.EMAIL, EntityType.URL):
            domain = domain_of(entity)
            return bool(domain) and self.contains(domain)
        return True
