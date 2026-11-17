"""Histórico de URLs en la Wayback Machine (archive.org).

Lo que una web publicó alguna vez suele seguir archivado: subdominios olvidados,
documentos (con metadatos jugosos) o ficheros que nunca debieron ser públicos.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterable
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from urllib.parse import urlsplit

from umbra.core.context import Context
from umbra.core.entities import Entity, Event, Severity
from umbra.core.entities import EntityType as T
from umbra.core.module import Module

CDX = "https://web.archive.org/cdx/search/cdx"
LIMIT = 20000
SAMPLE = 50

DOCUMENT_EXT = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods", ".odp", ".rtf"}
SENSITIVE_EXT = {
    ".sql", ".bak", ".backup", ".old", ".env", ".log", ".conf", ".cfg", ".ini", ".key", ".pem",
    ".zip", ".tar", ".gz", ".tgz", ".7z", ".rar", ".swp", ".db", ".sqlite",
}
LOGIN_HINTS = (
    "/admin", "/administrator", "/login", "/signin", "/wp-admin", "/wp-login",
    "/phpmyadmin", "/cpanel", "/webmail", "/owa", "/dashboard",
)


@dataclass
class Classified:
    hosts: set[str] = field(default_factory=set)
    documents: dict[str, None] = field(default_factory=dict)  # dict = conjunto ordenado
    sensitive: dict[str, None] = field(default_factory=dict)
    logins: dict[str, None] = field(default_factory=dict)


def classify_urls(urls: Iterable[str], root: str) -> Classified:
    result = Classified()
    suffix = "." + root
    for url in urls:
        try:
            parts = urlsplit(url)
            host = parts.hostname
        except ValueError:
            continue
        if host and host.endswith(suffix):
            if domain := Entity.try_of(T.DOMAIN, host):
                result.hosts.add(domain.value)
        path = parts.path.lower()
        ext = PurePosixPath(path).suffix
        if ext in DOCUMENT_EXT:
            result.documents[url] = None
        elif ext in SENSITIVE_EXT:
            result.sensitive[url] = None
        elif any(path == hint or path.startswith(hint + "/") or path.startswith(hint + ".") for hint in LOGIN_HINTS):
            result.logins[url] = None
    return result


class Wayback(Module):
    name = "wayback"
    description = "URLs archivadas en archive.org: subdominios, documentos y ficheros sensibles"
    consumes = frozenset({T.DOMAIN})
    produces = frozenset({T.DOMAIN})
    roots_only = True

    async def run(self, entity: Entity, ctx: Context) -> AsyncIterator[Event]:
        rows = await ctx.http.get_json(
            CDX,
            params={
                "url": entity.value,
                "matchType": "domain",
                "fl": "original",
                "collapse": "urlkey",
                "output": "json",
                "limit": str(LIMIT),
            },
            timeout=60,
            retries=0,  # archive.org suele ir lento: mejor fallar rápido que bloquear la investigación
        )
        if not rows:
            return
        if rows and rows[0] == ["original"]:
            rows = rows[1:]  # la primera fila es la cabecera
        urls = [r[0] for r in rows if r]
        result = classify_urls(urls, entity.value)

        for host in sorted(result.hosts):
            yield self.link(entity, Entity(T.DOMAIN, host), "archived_host")
        yield self.finding(
            entity,
            "URLs archivadas en la Wayback Machine",
            total=len(urls),
            truncado=len(urls) >= LIMIT,
            hosts=len(result.hosts),
        )
        if result.documents:
            yield self.finding(
                entity,
                "Documentos públicos archivados",
                total=len(result.documents),
                muestra=list(result.documents)[:SAMPLE],
                nota="Candidatos para extraer metadatos (autores, software, rutas internas).",
            )
        if result.sensitive:
            yield self.finding(
                entity,
                "Ficheros potencialmente sensibles en el histórico",
                Severity.MEDIUM,
                total=len(result.sensitive),
                muestra=list(result.sensitive)[:SAMPLE],
            )
        if result.logins:
            yield self.finding(
                entity,
                "Paneles de acceso en el histórico",
                total=len(result.logins),
                muestra=list(result.logins)[:SAMPLE],
            )
