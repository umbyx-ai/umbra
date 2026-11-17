"""Interfaz de terminal: consola, preguntas, tablas y enlaces.

Todas las herramientas del menú usan estas funciones, así la experiencia es la
misma en todas y no hay que repetir código de Rich por todas partes.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
import webbrowser
from collections.abc import Iterable, Sequence
from pathlib import Path

from rich.console import Console, RenderableType
from rich.markup import escape
from rich.prompt import Confirm, InvalidResponse, Prompt
from rich.table import Table
from rich.text import Text

console = Console(highlight=False)

BANNER = r"""
 _   _ __  __ ____  ____      _
| | | |  \/  | __ )|  _ \    / \
| | | | |\/| |  _ \| |_) |  / _ \
| |_| | |  | | |_) |  _ <  / ___ \
 \___/|_|  |_|____/|_| \_\/_/   \_\
"""


class Back(Exception):
    """El usuario quiere volver al menú."""


# --- mensajes ----------------------------------------------------------------

def banner(subtitle: str = "") -> None:
    console.print(BANNER, style="bold magenta", end="")
    if subtitle:
        console.print(f" {subtitle}", style="magenta")


def title(text: str, subtitle: str = "") -> None:
    console.print()
    console.rule(f"[bold magenta]{escape(text)}[/]", align="left", style="magenta")
    if subtitle:
        console.print(f"[dim]{escape(subtitle)}[/]")
    console.print()


def info(msg: str) -> None:
    console.print(f"[cyan][*][/] {msg}")


def ok(msg: str) -> None:
    console.print(f"[green][+][/] {msg}")


def warn(msg: str) -> None:
    console.print(f"[yellow][!][/] {msg}")


def error(msg: str) -> None:
    console.print(f"[bold red][x][/] {msg}")


def note(msg: str) -> None:
    console.print(f"[dim]{msg}[/]")


def status(msg: str):
    return console.status(f"[magenta]{msg}[/]")


# --- preguntas ---------------------------------------------------------------

class _Confirm(Confirm):
    choices = ["s", "n"]
    validate_error_message = "[prompt.invalid]Responde s o n"

    def process_response(self, value: str) -> bool:
        v = value.strip().lower()
        if v in ("s", "si", "sí", "y", "yes"):
            return True
        if v in ("n", "no"):
            return False
        raise InvalidResponse(self.validate_error_message)


def ask(prompt: str, default: str | None = None, *, required: bool = True) -> str:
    """Pregunta texto. Escribir ``0`` o ``volver`` vuelve al menú."""
    while True:
        kwargs = {"default": default} if default is not None else {}
        value = (Prompt.ask(f"[bold]{prompt}[/]", console=console, **kwargs) or "").strip()
        if value.lower() in ("0", "volver"):
            raise Back
        if value or not required:
            return value
        warn("Este campo es obligatorio (escribe 0 para volver).")


def ask_path(prompt: str, *, must_exist: bool = True) -> Path:
    while True:
        raw = ask(prompt)
        path = Path(raw.strip().strip('"').strip("'")).expanduser()  # rutas arrastradas a la terminal
        if not must_exist or path.exists():
            return path
        warn(f"No existe: {escape(str(path))}")


def confirm(prompt: str, default: bool = True) -> bool:
    return _Confirm.ask(f"[bold]{prompt}[/]", default=default, console=console)


def choose(options: Sequence[tuple[str, str]], prompt: str = "Opción") -> str:
    """Muestra opciones ``(clave, texto)`` y devuelve la clave elegida."""
    for key, label in options:
        console.print(f"  [bold magenta]{key:>2}[/]  {label}")
    console.print()
    keys = {k.lower() for k, _ in options}
    while True:
        value = Prompt.ask(f"[bold]{prompt}[/]", console=console).strip().lower()
        if value in keys:
            return value
        warn("Opción no válida.")


def pause() -> None:
    Prompt.ask("\n[dim]Pulsa Enter para volver[/]", default="", show_default=False, console=console)


# --- tablas y enlaces --------------------------------------------------------

def _cell(value: object) -> RenderableType:
    if isinstance(value, (Text, Table)):
        return value
    if value is None or value == "":
        return Text("-", style="dim")
    if isinstance(value, (list, tuple, set)):
        return Text(", ".join(str(v) for v in value) or "-")
    return Text(str(value))


def table(columns: Sequence[str], rows: Iterable[Sequence[object]], title: str | None = None) -> None:
    t = Table(title=title, title_justify="left", header_style="bold", title_style="bold")
    for col in columns:
        t.add_column(col, overflow="fold")
    for row in rows:
        t.add_row(*(_cell(c) for c in row))
    console.print(t)


def kv(pairs: Iterable[tuple[str, object]], title: str | None = None) -> None:
    t = Table(show_header=False, title=title, title_justify="left", title_style="bold", box=None, padding=(0, 2))
    t.add_column(style="bold cyan", no_wrap=True)
    t.add_column(overflow="fold")
    for key, value in pairs:
        t.add_row(key, _cell(value))
    console.print(t)


def open_url(url: str) -> None:
    webbrowser.open(url, new=2)


def open_path(path: Path) -> None:
    if sys.platform == "win32":
        os.startfile(path)  # type: ignore[attr-defined]
    elif sys.platform == "darwin":
        subprocess.run(["open", str(path)], check=False)
    else:
        subprocess.run(["xdg-open", str(path)], check=False)


def reveal(path: Path) -> None:
    """Abre el explorador de archivos señalando el fichero (útil para arrastrarlo a una web)."""
    if sys.platform == "win32":
        subprocess.run(["explorer", f"/select,{path}"], check=False)
    else:
        open_path(path.parent)


def links(items: Sequence[tuple[str, str]], *, title: str = "Enlaces", offer_open: bool = True) -> None:
    if not items:
        return
    t = Table(title=title, title_justify="left", header_style="bold", title_style="bold")
    t.add_column("#", justify="right", style="magenta")
    t.add_column("Recurso", style="bold")
    t.add_column("URL", overflow="fold", style="blue")
    for i, (label, url) in enumerate(items, 1):
        t.add_row(str(i), Text(label), Text(url))
    console.print(t)
    if not offer_open:
        return
    raw = Prompt.ask(
        "[bold]¿Abrir en el navegador?[/] [dim](números separados por comas, t = todos, Enter = ninguno)[/]",
        default="", show_default=False, console=console,
    ).strip().lower()
    if not raw:
        return
    chosen = range(1, len(items) + 1) if raw in ("t", "todos") else _parse_numbers(raw, len(items))
    for n in chosen:
        open_url(items[n - 1][1])
        time.sleep(0.4)  # algunos navegadores pierden pestañas si se abren de golpe


def _parse_numbers(raw: str, maximum: int) -> list[int]:
    result: list[int] = []
    for part in raw.replace(" ", "").split(","):
        if part.isdigit() and 1 <= int(part) <= maximum and int(part) not in result:
            result.append(int(part))
    return result


# --- markdown para la bitácora -----------------------------------------------

def md_table(columns: Sequence[str], rows: Iterable[Sequence[object]]) -> str:
    def cell(v: object) -> str:
        if isinstance(v, (list, tuple, set)):
            v = ", ".join(str(x) for x in v)
        text = str(v) if v not in (None, "") else "-"
        return text.replace("|", "\\|").replace("\n", " ")

    lines = ["| " + " | ".join(columns) + " |", "|" + "---|" * len(columns)]
    lines += ["| " + " | ".join(cell(c) for c in row) + " |" for row in rows]
    return "\n".join(lines)


def md_links(items: Sequence[tuple[str, str]]) -> str:
    return "\n".join(f"- [{label}]({url})" for label, url in items)
