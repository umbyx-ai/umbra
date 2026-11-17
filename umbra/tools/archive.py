"""Wayback Machine: lo que el objetivo publicó alguna vez (práctica de archivos web).

Endpoints antiguos, documentos retirados, rutas de API, parámetros, paneles de
login... sin hacer ni una petición a los servidores del objetivo.
"""

from __future__ import annotations

from collections import Counter
from urllib.parse import parse_qsl, quote, urlsplit

from umbra import ui, web
from umbra.case import Case
from umbra.core.entities import Entity
from umbra.core.entities import EntityType as T
from umbra.core.net import Http
from umbra.modules.wayback import classify_urls

CDX = "https://web.archive.org/cdx/search/cdx"
LIMIT = 10000  # archive.org va muy lento con consultas grandes
API_HINTS = ("/api/", "/api.", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/", "/wp-json/", "/swagger", "/openapi")
JUICY_PARAMS = {"redirect", "redirect_uri", "url", "next", "return", "returnurl", "file", "path", "page", "id",
                "debug", "token", "key", "apikey", "api_key", "password", "pass", "email", "user", "cmd", "q"}


def parse_cdx(rows: list[list[str]]) -> list[tuple[str, str, str]]:
    """Filas (timestamp, url, status) sin la cabecera."""
    if not rows:
        return []
    body = rows[1:] if rows[0] and rows[0][0] == "timestamp" else rows
    return [(r[0], r[1], r[2] if len(r) > 2 else "") for r in body if len(r) >= 2]


def api_endpoints(urls: list[str]) -> list[str]:
    seen: dict[str, None] = {}
    for url in urls:
        try:
            parts = urlsplit(url)
        except ValueError:
            continue
        path = parts.path.lower()
        if any(h in path for h in API_HINTS):
            seen[f"{parts.hostname}{parts.path}"] = None
    return list(seen)


def parameters(urls: list[str]) -> Counter[str]:
    counter: Counter[str] = Counter()
    for url in urls:
        try:
            query = urlsplit(url).query
        except ValueError:
            continue
        counter.update({k.lower() for k, _ in parse_qsl(query, keep_blank_values=True)})
    return counter


def _date(ts: str) -> str:
    return f"{ts[6:8]}/{ts[4:6]}/{ts[:4]}" if len(ts) >= 8 else ts


async def fetch(http: Http, domain: str, subdomains: bool, limit: int = LIMIT) -> list[tuple[str, str, str]]:
    rows = await http.get_json(
        CDX,
        params={"url": domain, "matchType": "domain" if subdomains else "host",
                "fl": "timestamp,original,statuscode", "collapse": "urlkey",
                "output": "json", "limit": str(limit)},
        timeout=180, retries=0,
    )
    return parse_cdx(rows or [])


def run(case: Case) -> None:
    ui.title("Wayback Machine", "Histórico de URLs de un dominio en archive.org.")
    domain = Entity.try_of(T.DOMAIN, ui.ask("Dominio"))
    if not domain:
        ui.warn("Dominio no válido.")
        return
    d = domain.value
    subs = ui.confirm("¿Incluir subdominios?", default=True)
    manual = [
        ("Todas las URLs archivadas", f"https://web.archive.org/web/*/{d}/*"),
        ("Calendario de capturas", f"https://web.archive.org/web/2*/{d}"),
    ]
    rows = None
    for limit in (LIMIT, 1000):
        with ui.status(f"Consultando archive.org (hasta {limit} URLs; puede tardar un par de minutos)…"):
            try:
                rows = web.run(lambda http, _dns, n=limit: fetch(http, d, subs, n), timeout=180)
                break
            except Exception as exc:  # noqa: BLE001 - archive.org corta conexiones cuando va saturado
                ui.error(f"archive.org no ha respondido: {exc}")
        if limit == 1000 or not ui.confirm("¿Reintentar con una consulta más pequeña (1000 URLs)?", default=True):
            break
    if rows is None:
        ui.links(manual, title="Consúltalo a mano")
        return
    if not rows:
        ui.info("No hay capturas de ese dominio.")
        return

    urls = [u for _, u, _ in rows]
    stamps = sorted(ts for ts, _, _ in rows)
    result = classify_urls(urls, d)
    endpoints = api_endpoints(urls)
    params = parameters(urls)
    juicy = [f"{p} ({n})" for p, n in params.most_common() if p in JUICY_PARAMS]

    ui.kv([
        ("URLs únicas", f"{len(urls)}" + (" (límite alcanzado)" if len(urls) >= LIMIT else "")),
        ("Primera captura", _date(stamps[0])),
        ("Última captura", _date(stamps[-1])),
        ("Subdominios vistos", len(result.hosts)),
        ("Documentos", len(result.documents)),
        ("Ficheros sensibles", len(result.sensitive)),
        ("Paneles de acceso", len(result.logins)),
        ("Endpoints de API", len(endpoints)),
        ("Parámetros interesantes", juicy[:15]),
    ], title=d)
    for label, items in (("Ficheros potencialmente sensibles", list(result.sensitive)),
                         ("Documentos", list(result.documents)),
                         ("Paneles de acceso", list(result.logins)),
                         ("Endpoints de API", endpoints)):
        if items:
            ui.table([label], [(u,) for u in items[:15]])
            if len(items) > 15:
                ui.note(f"… y {len(items) - 15} más en el fichero.")

    path = case.save(f"wayback_{d}.txt", "\n".join(urls) + "\n")
    ui.ok(f"Todas las URLs en {path}")
    ui.note("Abre una URL antigua en archive.org con: https://web.archive.org/web/2020/<url>")
    sample = list(result.sensitive)[:3] + list(result.documents)[:3]
    ui.links(manual + [(f"Captura de {u[:60]}", f"https://web.archive.org/web/2*/{quote(u, safe=':/')}") for u in sample],
             title="Ver en archive.org")

    case.log("Wayback Machine", d, "\n\n".join([
        f"{len(urls)} URLs únicas entre {_date(stamps[0])} y {_date(stamps[-1])}.",
        ui.md_table(["Tipo", "Total", "Muestra"], [
            ("Ficheros sensibles", len(result.sensitive), list(result.sensitive)[:5]),
            ("Documentos", len(result.documents), list(result.documents)[:5]),
            ("Paneles de acceso", len(result.logins), list(result.logins)[:5]),
            ("Endpoints de API", len(endpoints), endpoints[:5]),
        ]),
        f"Parámetros interesantes: {', '.join(juicy[:15]) or '-'}",
        f"Lista completa: `{path.name}`",
    ]))
