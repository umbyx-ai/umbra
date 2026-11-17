"""Favicon pivot (práctica "Shadow IT Hunt").

Shodan indexa el hash Murmur3 del favicon de cada web. Si calculas el del
objetivo y lo buscas (``http.favicon.hash:N``) aparecen otros servidores con el
mismo icono: entornos olvidados, IPs fuera de los rangos conocidos, paneles...

El hash es el mismo que calcula Shodan: Murmur3 (32 bits, con signo) del favicon
codificado en base64 con saltos de línea cada 76 caracteres.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
from html import unescape
from urllib.parse import quote, quote_plus, urljoin

from umbra import ui, web
from umbra.case import Case
from umbra.core.net import Http

ICON_LINK_RE = re.compile(r"<link\b[^>]*>", re.I)
REL_RE = re.compile(r"""rel\s*=\s*["']?([^"'>]+)""", re.I)
HREF_RE = re.compile(r"""href\s*=\s*["']?([^"'\s>]+)""", re.I)


def murmur3_32(data: bytes, seed: int = 0) -> int:
    """MurmurHash3 x86 de 32 bits con signo (igual que ``mmh3.hash``)."""
    c1, c2, mask = 0xCC9E2D51, 0x1B873593, 0xFFFFFFFF
    length = len(data)
    h = seed & mask
    end = length & ~3

    def mix(k: int) -> int:
        k = (k * c1) & mask
        k = ((k << 15) | (k >> 17)) & mask
        return (k * c2) & mask

    for i in range(0, end, 4):
        h ^= mix(int.from_bytes(data[i:i + 4], "little"))
        h = ((h << 13) | (h >> 19)) & mask
        h = (h * 5 + 0xE6546B64) & mask
    tail = data[end:]
    if tail:
        h ^= mix(int.from_bytes(tail, "little"))
    h ^= length
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & mask
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & mask
    h ^= h >> 16
    return h - (1 << 32) if h & 0x80000000 else h


def favicon_hash(content: bytes) -> int:
    return murmur3_32(base64.encodebytes(content))


def icon_urls(html: str, base_url: str) -> list[str]:
    """Iconos candidatos, del más probable al menos: rel="icon", /favicon.ico y apple-touch-icon.

    ``mask-icon`` y ``fluid-icon`` se descartan: no son el favicon que indexa Shodan.
    """
    primary: list[str] = []
    secondary: list[str] = []
    for tag in ICON_LINK_RE.findall(html):
        rel = REL_RE.search(tag)
        href = HREF_RE.search(tag)
        if not (rel and href):
            continue
        rels = rel.group(1).lower().split()
        if "mask-icon" in rels or "fluid-icon" in rels:
            continue
        url = urljoin(base_url, unescape(href.group(1)))
        if "icon" in rels:
            primary.append(url)
        elif any("icon" in r for r in rels):
            secondary.append(url)
    return list(dict.fromkeys(primary + [urljoin(base_url, "/favicon.ico")] + secondary))


def queries(mmh3: int, md5: str) -> list[tuple[str, str, str]]:
    """(motor, consulta, enlace)."""
    shodan = f"http.favicon.hash:{mmh3}"
    fofa = f'icon_hash="{mmh3}"'
    zoomeye = f'iconhash:"{mmh3}"'
    censys = f"services.http.response.favicons.md5_hash:{md5}"
    return [
        ("Shodan", shodan, "https://www.shodan.io/search?query=" + quote_plus(shodan)),
        ("FOFA", fofa, "https://en.fofa.info/result?qbase64=" + quote(base64.b64encode(fofa.encode()).decode())),
        ("ZoomEye", zoomeye, "https://www.zoomeye.ai/searchResult?q=" + quote(base64.b64encode(zoomeye.encode()).decode())),
        ("Censys", censys, "https://search.censys.io/search?resource=hosts&q=" + quote_plus(censys)),
    ]


def _looks_like_image(content: bytes, content_type: str) -> bool:
    return content_type.startswith("image/") or content[:4] in (b"\x00\x00\x01\x00", b"\x89PNG") or content[:3] == b"GIF"


async def fetch_icons(http: Http, target: str) -> list[tuple[str, bytes]]:
    base = target if target.startswith(("http://", "https://")) else f"https://{target}"
    resp = await http.get(base, retries=1, timeout=15)
    candidates = icon_urls(resp.text if resp.status_code < 400 else "", str(resp.url))
    icons: list[tuple[str, bytes]] = []
    for url in candidates[:4]:
        try:
            r = await http.get(url, retries=0, timeout=15)
        except Exception:  # noqa: BLE001 - probamos el siguiente candidato
            continue
        if r.status_code == 200 and r.content and _looks_like_image(r.content, r.headers.get("content-type", "")):
            icons.append((str(r.url), r.content))
    return icons


def _report(case: Case, source: str, content: bytes) -> None:
    mmh3 = favicon_hash(content)
    md5 = hashlib.md5(content).hexdigest()  # noqa: S324 - es el formato que usa Censys
    ui.kv([("Icono", source), ("Tamaño", f"{len(content)} bytes"), ("Murmur3 (Shodan)", mmh3), ("MD5", md5)])
    rows = queries(mmh3, md5)
    ui.table(["Motor", "Consulta"], [(m, q) for m, q, _ in rows])
    ui.links([(m, url) for m, _, url in rows], title="Buscar servidores con el mismo favicon")
    ui.note("Busca IPs que no pertenezcan a los rangos conocidos del objetivo: ahí está el shadow IT.")
    _count(mmh3)
    case.log("Favicon hash", source, ui.md_table(["Motor", "Consulta"], [(m, f"`{q}`") for m, q, _ in rows]))


def _count(mmh3: int) -> None:
    key = os.environ.get("SHODAN_API_KEY")
    if not key:
        return

    async def job(http, _dns):
        return await http.get_json("https://api.shodan.io/shodan/host/count",
                                   params={"key": key, "query": f"http.favicon.hash:{mmh3}"}, missing=())

    try:
        data = web.run(job)
        ui.ok(f"Shodan: {data.get('total', 0)} hosts con ese favicon.")
    except Exception as exc:  # noqa: BLE001
        ui.warn(f"Shodan API: {exc}")


def run(case: Case) -> None:
    ui.title("Favicon hash", "Calcula el hash Murmur3 del favicon y busca servidores con el mismo icono.")
    choice = ui.choose([("1", "Descargarlo de una web"), ("2", "Usar un fichero local (.ico, .png)"), ("0", "Volver")])
    if choice == "2":
        path = ui.ask_path("Ruta del icono")
        _report(case, path.name, path.read_bytes())
        return
    if choice != "1":
        return
    target = ui.ask("Dominio o URL")
    ui.note("Se descarga la web y el icono como lo haría un navegador.")
    with ui.status("Buscando el favicon…"):
        try:
            icons = web.run(lambda http, _dns: fetch_icons(http, target.strip()))
        except Exception as exc:  # noqa: BLE001
            ui.error(f"No se pudo acceder a {target}: {exc}")
            return
    if not icons:
        ui.warn("No he encontrado ningún favicon. Prueba a descargarlo a mano y usar la opción de fichero local.")
        return
    seen: set[bytes] = set()
    for url, content in icons:
        if content not in seen:
            seen.add(content)
            _report(case, url, content)
