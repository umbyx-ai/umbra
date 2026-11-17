"""Módulos de Umbra. Cada fichero de esta carpeta (que no empiece por ``_``) se carga solo."""

from __future__ import annotations

import importlib
import inspect
import pkgutil

from umbra.core.module import Module


def discover() -> dict[str, type[Module]]:
    """Importa todos los ficheros del paquete y devuelve sus módulos por nombre."""
    found: dict[str, type[Module]] = {}
    for info in pkgutil.iter_modules(__path__):
        if info.name.startswith("_"):
            continue
        py_module = importlib.import_module(f"{__name__}.{info.name}")
        for obj in vars(py_module).values():
            if (
                inspect.isclass(obj)
                and issubclass(obj, Module)
                and not inspect.isabstract(obj)
                and obj.__module__ == py_module.__name__
            ):
                if obj.name in found:
                    raise RuntimeError(f"nombre de módulo duplicado: {obj.name}")
                found[obj.name] = obj
    return dict(sorted(found.items()))
