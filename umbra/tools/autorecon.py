"""Recon pasivo automático: encadena DNS, crt.sh, RDAP, ASN, Shodan y Wayback con el motor de pivotes.

Es la parte "Amass / SpiderFoot" de la presentación: en vez de hacer las
consultas a mano, el motor tira del hilo solo y construye un grafo.
"""

from __future__ import annotations

import asyncio
import json
from collections import Counter
from pathlib import Path

from rich.text import Text

from umbra import __version__, ui
from umbra.case import Case, case_slug
from umbra.core.context import Context
from umbra.core.engine import Engine, RunStats
from umbra.core.entities import Entity, Severity, detect
from umbra.core.module import Module
from umbra.core.net import Dns, Http
from umbra.core.scope import Scope
from umbra.core.storage import Store, now
from umbra.modules import discover
from umbra.report import SEVERITY_LABEL, build_markdown

SEVERITY_STYLE = {Severity.HIGH: "bold red", Severity.MEDIUM: "yellow", Severity.LOW: "cyan", Severity.INFO: "dim"}


async def _investigate(seed: Entity, modules: list[Module], store: Store, scope: Scope, *,
                       depth: int, concurrency: int, timeout: float, resolvers: list[str] | None,
                       progress) -> RunStats:
    async with Http(timeout=timeout) as http:
        ctx = Context(http=http, dns=Dns(resolvers), scope=scope)
        engine = Engine(modules, ctx, store, max_depth=depth, concurrency=concurrency, on_progress=progress)
        return await engine.investigate(seed)


def investigate(case: Case, seed: Entity, modules: list[Module], *, depth: int = 3, extra_scope: list[str] = (),
                concurrency: int = 20, timeout: float = 30.0, resolvers: list[str] | None = None) -> tuple[Store, RunStats, Path]:
    """Lanza la investigación, guarda ``recon_<objetivo>.db/.md`` en el caso y devuelve el resultado."""
    scope = Scope.from_seed(seed, extra=extra_scope)
    stem = f"recon_{case_slug(seed.value)}"
    store = Store(case.dir / f"{stem}.db")
    store.clear_errors()
    store.set_meta(case=case.name, seed=seed.value, seed_type=seed.type, scope=json.dumps(sorted(scope.roots)),
                   depth=depth, modules=",".join(m.name for m in modules), version=__version__, started=now())
    with ui.status("Arrancando…") as st:

        def progress(s: RunStats) -> None:
            waiting = ", ".join(sorted(s.active))
            st.update(f"[bold]Investigando[/] · tareas {s.done}/{s.jobs} · entidades {s.discovered}"
                      f" · hallazgos {s.findings} · errores {s.errors}"
                      + (f" [dim]· en curso: {waiting}[/]" if waiting else ""))

        try:
            stats = asyncio.run(_investigate(seed, modules, store, scope, depth=depth, concurrency=concurrency,
                                             timeout=timeout, resolvers=resolvers, progress=progress))
        finally:
            store.set_meta(finished=now())
            store.commit()
    report = case.dir / f"{stem}.md"
    report.write_text(build_markdown(store), encoding="utf-8")
    return store, stats, report


def print_summary(store: Store, stats: RunStats, report_path: Path) -> None:
    findings = store.findings()
    counts = Counter(e["type"] for e in store.entities())
    ui.table(["Tipo", "Total"], counts.most_common(), title="Entidades")
    relevant = [f for f in findings if f["severity"] != Severity.INFO]
    if relevant:
        ui.table(
            ["Nivel", "Entidad", "Hallazgo"],
            [(Text(SEVERITY_LABEL[Severity(f["severity"])], style=SEVERITY_STYLE[Severity(f["severity"])]),
              f["entity"].partition(":")[2], f["title"]) for f in relevant[:20]],
            title=f"Hallazgos relevantes ({len(relevant)})",
        )
    else:
        ui.ok("Sin hallazgos por encima de nivel informativo.")
    if stats.errors:
        ui.warn(f"{stats.errors} módulo(s) fallaron; detalles en el informe.")
    ui.info(f"Informe completo: {report_path}")


def run(case: Case) -> None:
    ui.title("Recon pasivo automático", "Pivota solo entre DNS, crt.sh, RDAP, RIPEstat, Shodan InternetDB y Wayback.")
    try:
        seed = detect(ui.ask("Objetivo (dominio, IP, email o URL)"))
    except ValueError as exc:
        ui.warn(str(exc))
        return
    depth_raw = ui.ask("Profundidad de pivote (1-4)", default="2")
    depth = min(max(int(depth_raw), 1), 4) if depth_raw.isdigit() else 2
    registry = discover()
    skip = set()
    if ui.confirm("¿Saltar Wayback? (archive.org suele ir lento)", default=True):
        skip.add("wayback")
    modules = [cls() for name, cls in registry.items() if name not in skip]
    store, stats, report = investigate(case, seed, modules, depth=depth)
    try:
        print_summary(store, stats, report)
        counts = store.counts()
    finally:
        store.close()
    if ui.confirm("¿Abrir el informe?", default=False):
        ui.open_path(report)
    case.log("Recon automático", seed.value,
             f"{counts['entities']} entidades, {counts['findings']} hallazgos. Informe: `{report.name}`")
