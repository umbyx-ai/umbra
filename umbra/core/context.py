"""Lo que recibe cada módulo para trabajar: red, alcance y claves de API."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field

from umbra.core.net import Dns, Http
from umbra.core.scope import Scope


@dataclass
class Context:
    http: Http
    dns: Dns
    scope: Scope
    keys: Mapping[str, str] = field(default_factory=dict)

    def key(self, name: str) -> str | None:
        """Clave de API por nombre (configuración explícita o variable de entorno)."""
        return self.keys.get(name) or os.environ.get(name)
