"""Validación en vivo [ACTIVO] (práctica "The Live Validation").

Es la única opción que envía peticiones a los servidores del objetivo (como httpx):
una petición HTTP por host para ver si responde y con qué. Un 401/403 o un título
de login no es un callejón sin salida: es un hallazgo de valor.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from html import unescape
from pathlib import Path

import httpx

from umbra import __version__, ui
from umbra.case import Case
from umbra.core.entities import Entity
from umbra.core.entities import EntityType as T

TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
LOGIN_RE = re.compile(
    r"log ?in|sign ?in|iniciar sesi|acceso|acceder|admin|panel|dashboard|portal|webmail|outlook|owa|vpn"
    r"|citrix|jenkins|grafana|kibana|gitlab|phpmyadmin|cpanel|plesk|router|auth",
    re.I,
)
MAX_HOSTS = 500


@dataclass
class ProbeResult:
    host: str
    url: str | None = None
    status: int | None = None
    title: str = ""
    server: str = ""
    error: str = ""
    auth: bool = False

    @property
    def flags(self) -> list[str]:
        out = []
        if self.status in (401, 403):
            out.append(f"restringido ({self.status})")
        if self.auth:
            out.append("pide credenciales")
        if self.title and LOGIN_RE.search(self.title):
            out.append("posible panel de acceso")
        return out


def extract_title(html: str) -> str:
    match = TITLE_RE.search(html[:200_000])
    return re.sub(r"\s+", " ", unescape(match.group(1))).strip()[:120] if match else ""


async def probe_host(client: httpx.AsyncClient, host: str) -> ProbeResult:
    result = ProbeResult(host)
    for scheme in ("https", "http"):
        try:
            resp = await client.get(f"{scheme}://{host}/")
        except httpx.HTTPError as exc:
            result.error = exc.__class__.__name__
            continue
        result.url = str(resp.url)  # URL final tras las redirecciones
        result.status = resp.status_code
        result.server = resp.headers.get("server", "")
        result.auth = "www-authenticate" in resp.headers
        if "html" in resp.headers.get("content-type", ""):
            result.title = extract_title(resp.text)
        result.error = ""
        return result
    return result


async def probe_all(hosts: list[str], on_done) -> list[ProbeResult]:
    sem = asyncio.Semaphore(10)
    # verify=False: solo leemos el código y el título; muchos entornos internos tienen certificados caducados
    async with httpx.AsyncClient(
        timeout=8.0, follow_redirects=True, verify=False,
        headers={"User-Agent": f"umbra-osint/{__version__} (authorized scope validation)"},  # solo ASCII
    ) as client:

        async def one(host: str) -> ProbeResult:
            async with sem:
                res = await probe_host(client, host)
            on_done()
            return res

        return list(await asyncio.gather(*(one(h) for h in hosts)))


def parse_hosts(text: str) -> list[str]:
    hosts: list[str] = []
    for raw in re.split(r"[\s,;]+", text):
        raw = re.sub(r"^https?://", "", raw.strip()).split("/")[0]
        if raw and (e := Entity.try_of(T.DOMAIN, raw) or Entity.try_of(T.IP, raw)) and e.value not in hosts:
            hosts.append(e.value)
    return hosts


def _load_hosts(case: Case) -> list[str]:
    files = case.text_files()
    options = [(str(i), f"Fichero del caso: {p.name}") for i, p in enumerate(files, 1)]
    options += [("f", "Otro fichero (una línea por host)"), ("e", "Escribirlos ahora"), ("0", "Volver")]
    choice = ui.choose(options, "¿De dónde saco los hosts?")
    if choice == "0":
        return []
    if choice == "e":
        return parse_hosts(ui.ask("Hosts separados por comas"))
    path: Path = ui.ask_path("Ruta del fichero") if choice == "f" else files[int(choice) - 1]
    return parse_hosts(path.read_text(encoding="utf-8", errors="replace"))


def run(case: Case) -> None:
    ui.title("Validación en vivo [ACTIVO]", "Comprueba qué hosts responden por HTTP y con qué código y título.")
    ui.warn("Esta opción SÍ contacta con los servidores. Úsala solo dentro de un alcance autorizado "
            "(programa de bug bounty con alcance público, tu propia infraestructura o un laboratorio).")
    if not ui.confirm("¿El objetivo está dentro de un alcance autorizado?", default=False):
        return
    hosts = _load_hosts(case)
    if not hosts:
        return
    if len(hosts) > MAX_HOSTS:
        ui.warn(f"Hay {len(hosts)} hosts; compruebo los {MAX_HOSTS} primeros.")
        hosts = hosts[:MAX_HOSTS]

    done = 0
    with ui.status(f"Comprobando {len(hosts)} hosts…") as st:

        def tick() -> None:
            nonlocal done
            done += 1
            st.update(f"[magenta]Comprobando hosts… {done}/{len(hosts)}[/]")

        results = asyncio.run(probe_all(hosts, tick))

    alive = [r for r in results if r.status is not None]
    alive.sort(key=lambda r: (not r.flags, r.status or 999, r.host))
    ui.table(
        ["Host", "Código", "Título", "Servidor", "Hallazgo"],
        [(r.host, r.status, r.title, r.server, "; ".join(r.flags)) for r in alive],
        title=f"Responden {len(alive)} de {len(hosts)}",
    )
    hot = [r for r in alive if r.flags]
    if hot:
        ui.ok(f"{len(hot)} hosts con acceso restringido o aspecto de panel: revísalos a mano en el navegador.")
        ui.links([(r.host, r.url or f"https://{r.host}/") for r in hot[:20]], title="Abrir candidatos")
    case.log("Validación en vivo", f"{len(hosts)} hosts", ui.md_table(
        ["Host", "Código", "Título", "Servidor", "Hallazgo"],
        [(r.host, r.status, r.title, r.server, "; ".join(r.flags)) for r in alive],
    ))
