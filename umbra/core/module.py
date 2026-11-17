"""Contrato que cumple cada módulo de Umbra."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING, Any, ClassVar

from umbra.core.entities import Entity, EntityType, Event, Finding, Relation, Severity

if TYPE_CHECKING:
    from umbra.core.context import Context
    from umbra.core.scope import Scope


class Module(ABC):
    """Un módulo recibe una entidad y emite relaciones (nuevas entidades) y hallazgos.

    Para crear uno basta con añadir un fichero en ``umbra/modules/`` con una
    subclase de ``Module``: se descubre automáticamente.
    """

    name: ClassVar[str]
    description: ClassVar[str]
    consumes: ClassVar[frozenset[EntityType]]
    produces: ClassVar[frozenset[EntityType]] = frozenset()
    category: ClassVar[str] = "infra"
    passive: ClassVar[bool] = True
    # Solo se ejecuta sobre los dominios raíz del alcance (p. ej. crt.sh ya devuelve todos los subdominios)
    roots_only: ClassVar[bool] = False
    # Variable de entorno con la clave de API que necesita, si necesita alguna
    requires_key: ClassVar[str | None] = None

    def accepts(self, entity: Entity, scope: Scope) -> bool:
        if entity.type not in self.consumes:
            return False
        if self.roots_only and entity.type is EntityType.DOMAIN and not scope.is_root(entity):
            return False
        return True

    @abstractmethod
    def run(self, entity: Entity, ctx: Context) -> AsyncIterator[Event]:
        """Generador asíncrono: hace ``yield self.link(...)`` y ``yield self.finding(...)``."""

    def link(self, source: Entity, target: Entity, label: str) -> Relation:
        return Relation(source, target, label, self.name)

    def finding(
        self, entity: Entity, title: str, severity: Severity = Severity.INFO, **data: Any
    ) -> Finding:
        return Finding(entity, title, Severity(severity), data, self.name)
