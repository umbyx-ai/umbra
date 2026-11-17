"""Motor de investigación: ejecuta módulos y pivota sobre lo que descubren.

Funciona como una búsqueda en anchura asíncrona:

1. La semilla (lo que escribe el usuario) se pasa a todos los módulos que la aceptan.
2. Cada relación que emite un módulo trae una entidad nueva.
3. Si la entidad está dentro del alcance y de la profundidad máxima, se vuelve
   a pasar a los módulos. Y así sucesivamente.

Todo corre en paralelo (con un límite de concurrencia) y cada entidad se expande
una sola vez por ejecución.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from umbra.core.context import Context
from umbra.core.entities import Entity, Event, Finding, Relation
from umbra.core.module import Module
from umbra.core.storage import Store

log = logging.getLogger(__name__)


@dataclass
class RunStats:
    jobs: int = 0
    done: int = 0
    running: int = 0
    discovered: int = 0
    findings: int = 0
    errors: int = 0
    active: Counter[str] = field(default_factory=Counter)  # módulo -> tareas en curso


class Engine:
    COMMIT_EVERY = 50

    def __init__(
        self,
        modules: Iterable[Module],
        ctx: Context,
        store: Store,
        *,
        max_depth: int = 3,
        concurrency: int = 20,
        on_progress: Callable[[RunStats], None] | None = None,
    ) -> None:
        self.modules = list(modules)
        self.ctx = ctx
        self.store = store
        self.max_depth = max_depth
        self.stats = RunStats()
        self._sem = asyncio.Semaphore(concurrency)
        self._on_progress = on_progress or (lambda _stats: None)
        self._discovered: set[Entity] = set()
        self._expanded: set[Entity] = set()

    async def investigate(self, seed: Entity) -> RunStats:
        self.store.add_entity(seed, 0, "seed")
        self._discovered.add(seed)
        self._expanded.add(seed)
        self.stats.discovered = 1
        try:
            async with asyncio.TaskGroup() as tg:
                self._expand(seed, 0, tg)
        finally:
            self.store.commit()
        return self.stats

    def _expand(self, entity: Entity, depth: int, tg: asyncio.TaskGroup) -> None:
        for module in self.modules:
            if module.accepts(entity, self.ctx.scope):
                self.stats.jobs += 1
                tg.create_task(self._run(module, entity, depth, tg))
        self._on_progress(self.stats)

    async def _run(self, module: Module, entity: Entity, depth: int, tg: asyncio.TaskGroup) -> None:
        async with self._sem:
            self.stats.running += 1
            self.stats.active[module.name] += 1
            self._on_progress(self.stats)
            started, events = time.perf_counter(), 0
            try:
                async for event in module.run(entity, self.ctx):
                    events += 1
                    self._handle(event, depth, tg)
            except Exception as exc:  # un módulo que falla no debe tumbar la investigación
                self.stats.errors += 1
                message = str(exc) or exc.__class__.__name__
                self.store.add_error(module.name, entity, message)
                log.warning("[%s] %s: %s", module.name, entity.value, message)
            finally:
                log.info("[%s] %s: %d eventos en %.1fs", module.name, entity.value, events, time.perf_counter() - started)
                self.stats.running -= 1
                self.stats.active[module.name] -= 1
                if not self.stats.active[module.name]:
                    del self.stats.active[module.name]
                self.stats.done += 1
                if self.stats.done % self.COMMIT_EVERY == 0:
                    self.store.commit()
                self._on_progress(self.stats)

    def _handle(self, event: Event, depth: int, tg: asyncio.TaskGroup) -> None:
        if isinstance(event, Finding):
            self.store.add_finding(event)
            self.stats.findings += 1
            return
        if not isinstance(event, Relation):
            raise TypeError(f"evento desconocido: {event!r}")

        target, next_depth = event.target, depth + 1
        self.store.add_entity(target, next_depth, event.module)
        self.store.add_relation(event)
        if target not in self._discovered:
            self._discovered.add(target)
            self.stats.discovered += 1
        if target in self._expanded:
            return
        if next_depth <= self.max_depth and self.ctx.scope.allows_expansion(target):
            self._expanded.add(target)
            self._expand(target, next_depth, tg)
