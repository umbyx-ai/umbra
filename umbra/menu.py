"""Menú principal de Umbra: una opción por práctica de las presentaciones de OSINT."""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass

from rich.markup import escape
from rich.prompt import Prompt
from rich.table import Table
from rich.text import Text

from umbra import __version__, ui
from umbra.case import Case
from umbra.core.net import NetError
from umbra.tools import (
    archive, autorecon, casebook, devices, dnsmail, dorks, egosurf, emails, favicon,
    images, leaks, metadata, probe, subdomains, usernames, whois,
)

log = logging.getLogger("umbra")


@dataclass(frozen=True)
class Option:
    key: str
    title: str
    description: str
    action: Callable[[Case], None]


SECTIONS: list[tuple[str, list[Option]]] = [
    ("BUSCADORES", [
        Option("1", "Google Dorking", "constructor, plantillas contra un dominio y operadores", dorks.run),
        Option("2", "Buscadores de dispositivos", "Shodan, Censys, FOFA… impresoras, cámaras, IPs", devices.run),
    ]),
    ("RECON PASIVO DE INFRAESTRUCTURA", [
        Option("3", "DNS y correo", "MX, SPF, DKIM, DMARC: ¿correo en la nube u on-premise?", dnsmail.run),
        Option("4", "Subdominios", "crt.sh + DNS pasivo + palabras clave (dev, vpn, admin…)", subdomains.run),
        Option("5", "WHOIS, RDAP y ASN", "entidad legal, registrador, ASN y bloques CIDR", whois.run),
        Option("6", "Wayback Machine", "URLs antiguas, documentos y endpoints olvidados", archive.run),
        Option("7", "Favicon hash", "pivote a Shodan/FOFA con el hash del favicon", favicon.run),
        Option("8", "Validación en vivo [ACTIVO]", "códigos 200/401/403 y paneles de acceso", probe.run),
        Option("9", "Recon automático", "encadena todo y genera un grafo e informe", autorecon.run),
    ]),
    ("IMINT · IMÁGENES", [
        Option("10", "Metadatos de archivos", "EXIF, GPS, PDF y Office (+ limpiar una foto)", metadata.run),
        Option("11", "Búsqueda inversa de imágenes", "Google Lens, Bing, Yandex, TinEye + geolocalización", images.reverse),
        Option("12", "¿Imagen manipulada? (ELA)", "Error Level Analysis + detectores de IA", images.ela),
    ]),
    ("SOCMINT · PERSONAS Y CORREO", [
        Option("13", "Emails de una organización", "domain search, email finder y verificación", emails.run),
        Option("14", "Filtraciones de un email", "brechas conocidas (XposedOrNot / HIBP)", leaks.email),
        Option("15", "¿Contraseña filtrada?", "Pwned Passwords con k-anonimato", leaks.password),
        Option("16", "Nombre de usuario en redes", "busca un alias en muchas plataformas", usernames.run),
        Option("17", "Egosurfing", "tu propia huella: dorks sobre ti y Google Alerts", egosurf.run),
    ]),
    ("CASO", [
        Option("18", "Bitácora y GAP analysis", "lo que has hecho, notas y las 4 preguntas", casebook.run),
    ]),
]
OPTIONS = {opt.key: opt for _, options in SECTIONS for opt in options}


def render_menu(case: Case) -> None:
    ui.console.clear()
    ui.banner(f"OSINT · dorks, IMINT, SOCMINT y recon pasivo · v{__version__}")
    ui.console.print(f" [dim]Caso activo:[/] [bold]{case.name}[/] [dim]({case.entries()} entradas en la bitácora)[/]\n")
    grid = Table.grid(padding=(0, 2))
    grid.add_column(justify="right", style="bold magenta", no_wrap=True)
    grid.add_column(style="bold", no_wrap=True)
    grid.add_column(style="dim")
    for section, options in SECTIONS:
        grid.add_row("", Text(section, style="magenta"), "")
        for opt in options:
            grid.add_row(Text(f"[{opt.key}]"), Text(opt.title), Text(opt.description))
        grid.add_row("", "", "")
    grid.add_row(Text("[c]"), Text("Cambiar de caso"), "")
    grid.add_row(Text("[0]"), Text("Salir"), "")
    ui.console.print(grid)
    ui.console.print()


def pick_case(current: str | None = None) -> Case:
    existing = Case.existing()
    if existing:
        ui.note("Casos existentes: " + ", ".join(existing))
    name = ui.ask("Nombre del caso", default=current or "general")
    return Case(name)


def run_option(option: Option, case: Case) -> None:
    ui.console.clear()
    try:
        option.action(case)
    except ui.Back:
        return
    except KeyboardInterrupt:
        ui.warn("Cancelado.")
    except NetError as exc:
        ui.error(escape(f"Error de red: {exc}"))
    except Exception as exc:  # noqa: BLE001 - una herramienta que falla no debe cerrar el menú
        log.debug("Error en %s", option.title, exc_info=True)
        ui.error(escape(f"Algo ha fallado en '{option.title}': {exc.__class__.__name__}: {exc}"))
        ui.note("Lanza umbra con -v para ver el detalle.")
    ui.pause()


def main_loop() -> int:
    ui.console.clear()
    ui.banner(f"OSINT · v{__version__}")
    ui.console.print()
    try:
        case = pick_case()
    except (ui.Back, KeyboardInterrupt, EOFError):
        return 0
    while True:
        render_menu(case)
        try:
            choice = Prompt.ask("[bold magenta]Opción[/]", console=ui.console).strip().lower()
        except (KeyboardInterrupt, EOFError):
            choice = "0"
        if choice == "0":
            ui.console.print("\n[magenta]Desconectando de la sombra… hasta la próxima.[/]\n")
            return 0
        if choice == "c":
            try:
                case = pick_case(case.name)
            except (ui.Back, KeyboardInterrupt):
                pass
            continue
        if option := OPTIONS.get(choice):
            run_option(option, case)
        else:
            ui.warn("Opción no válida.")
            ui.pause()
