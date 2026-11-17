"""Punto de entrada: ``umbra`` abre el menú; ``umbra run`` lanza el recon automático sin menú."""

from __future__ import annotations

import argparse
import ipaddress
import logging
import os
import sys
from pathlib import Path

from rich.logging import RichHandler
from rich.markup import escape

from umbra import __version__, ui
from umbra.case import Case
from umbra.core.entities import Entity, EntityType, detect
from umbra.core.module import Module
from umbra.modules import discover

log = logging.getLogger("umbra")


class CliError(Exception):
    pass


def _csv(value: str) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


def select_modules(registry: dict[str, type[Module]], only: list[str], skip: list[str]) -> list[Module]:
    unknown = [n for n in (*only, *skip) if n not in registry]
    if unknown:
        raise CliError(f"módulos desconocidos: {', '.join(unknown)} (mira `umbra modules`)")
    chosen: list[Module] = []
    for name in only or list(registry):
        if name in skip:
            continue
        cls = registry[name]
        if cls.requires_key and not os.environ.get(cls.requires_key):
            log.warning("Módulo %s desactivado: falta la variable de entorno %s", name, cls.requires_key)
            continue
        chosen.append(cls())
    return chosen


def cmd_menu(args: argparse.Namespace) -> int:
    from umbra.menu import main_loop

    return main_loop()


def cmd_run(args: argparse.Namespace) -> int:
    from umbra.tools.autorecon import investigate, print_summary

    try:
        seed = Entity.of(args.type, args.target) if args.type else detect(args.target)
        for resolver in args.resolver or []:
            ipaddress.ip_address(resolver)
    except ValueError as exc:
        raise CliError(str(exc)) from exc
    modules = select_modules(discover(), _csv(args.only), _csv(args.skip))
    if not modules:
        raise CliError("no hay módulos que ejecutar")
    case = Case(args.case or seed.value, Path(args.cases_dir))

    if not args.no_banner:
        ui.banner(f"Recon pasivo automático · v{__version__}\n")
    ui.console.print(f"[bold]Objetivo:[/] {escape(seed.value)} [dim]({seed.type})[/]")
    ui.console.print(f"[bold]Módulos:[/]  {', '.join(m.name for m in modules)} [dim]· profundidad {args.depth}[/]\n")
    try:
        store, stats, report = investigate(
            case, seed, modules, depth=args.depth, extra_scope=_csv(args.scope),
            concurrency=args.concurrency, timeout=args.timeout, resolvers=args.resolver,
        )
    except ValueError as exc:  # p. ej. un dominio extra de --scope no válido
        raise CliError(str(exc)) from exc
    try:
        print_summary(store, stats, report)
        counts = store.counts()
    finally:
        store.close()
    case.log("Recon automático", seed.value, f"{counts['entities']} entidades, {counts['findings']} hallazgos. "
             f"Informe: `{report.name}`")
    return 0


def cmd_modules(args: argparse.Namespace) -> int:
    ui.table(
        ["Módulo", "Consume", "Produce", "Clave", "Descripción"],
        [(name, sorted(cls.consumes), sorted(cls.produces), cls.requires_key, cls.description)
         for name, cls in discover().items()],
    )
    return 0


def cmd_cases(args: argparse.Namespace) -> int:
    names = Case.existing(Path(args.cases_dir))
    if not names:
        ui.console.print("No hay casos todavía. Abre el menú con [bold]umbra[/].")
        return 0
    rows = []
    for name in names:
        case = Case(name, Path(args.cases_dir))
        rows.append((name, case.entries(), len(list(case.dir.iterdir())) - 1, case.dir))
    ui.table(["Caso", "Entradas en la bitácora", "Ficheros", "Carpeta"], rows)
    return 0


def _depth(value: str) -> int:
    n = int(value)
    if not 0 <= n <= 6:
        raise argparse.ArgumentTypeError("la profundidad debe estar entre 0 y 6")
    return n


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-v", "--verbose", action="count", default=0, help="más detalle (-vv para depurar)")
    common.add_argument("--cases-dir", default="cases", help="carpeta de los casos (por defecto ./cases)")

    parser = argparse.ArgumentParser(prog="umbra", parents=[common],
                                     description="Umbra · navaja suiza OSINT. Sin argumentos abre el menú.")
    parser.add_argument("-V", "--version", action="version", version=f"umbra {__version__}")
    parser.set_defaults(func=cmd_menu)
    sub = parser.add_subparsers(dest="command", metavar="comando")

    sub.add_parser("menu", parents=[common], help="abre el menú interactivo (por defecto)").set_defaults(func=cmd_menu)

    run = sub.add_parser("run", parents=[common], help="recon pasivo automático sin menú")
    run.add_argument("target", help="dominio, IP, email, URL o ASN")
    run.add_argument("-t", "--type", choices=[t.value for t in EntityType], help="fuerza el tipo de entidad")
    run.add_argument("-c", "--case", help="nombre del caso (por defecto, el objetivo)")
    run.add_argument("-d", "--depth", type=_depth, default=3, help="saltos de pivote (por defecto 3)")
    run.add_argument("--only", default="", help="solo estos módulos, separados por comas")
    run.add_argument("--skip", default="", help="excluye estos módulos, separados por comas")
    run.add_argument("--scope", default="", help="dominios raíz extra dentro del alcance")
    run.add_argument("--resolver", action="append", help="servidor DNS a usar (se puede repetir)")
    run.add_argument("--concurrency", type=int, default=20, help="tareas en paralelo (por defecto 20)")
    run.add_argument("--timeout", type=float, default=30.0, help="timeout HTTP en segundos")
    run.add_argument("--no-banner", action="store_true", help="no muestra el banner")
    run.set_defaults(func=cmd_run)

    sub.add_parser("modules", parents=[common], help="módulos del recon automático").set_defaults(func=cmd_modules)
    sub.add_parser("cases", parents=[common], help="casos guardados").set_defaults(func=cmd_cases)
    return parser


def _setup_logging(verbosity: int) -> None:
    level = logging.WARNING if verbosity == 0 else logging.INFO if verbosity == 1 else logging.DEBUG
    logging.basicConfig(level=level, format="%(message)s",
                        handlers=[RichHandler(console=ui.console, show_time=False, show_path=False, markup=False)])
    if verbosity < 2:
        for noisy in ("httpx", "httpcore"):
            logging.getLogger(noisy).setLevel(logging.WARNING)


def main(argv: list[str] | None = None) -> int:
    # En Windows, al redirigir la salida, Python usa cp1252 y los acentos se rompen
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    args = build_parser().parse_args(argv)
    _setup_logging(args.verbose)
    if args.cases_dir != "cases":
        import umbra.case

        umbra.case.DEFAULT_CASES_DIR = Path(args.cases_dir)
    try:
        return args.func(args)
    except CliError as exc:
        ui.console.print(f"[bold red]error:[/] {escape(str(exc))}")
        return 2
    except KeyboardInterrupt:
        ui.console.print("\n[yellow]Interrumpido. Lo hecho hasta ahora queda guardado en el caso.[/]")
        return 130
