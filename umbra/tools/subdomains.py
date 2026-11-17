"""Subdomain harvesting pasivo: Certificate Transparency, DNS pasivo y archivo web.

Práctica de clase: buscar en crt.sh con el comodín % y localizar al menos 3
subdominios de staging, herramientas internas o acceso remoto. Umbra junta varias
fuentes, marca los subdominios con palabras clave interesantes y separa los que
siguen vivos de los registros muertos.
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import quote

from umbra import lookups, ui, web
from umbra.case import Case
from umbra.core.entities import Entity
from umbra.core.entities import EntityType as T
from umbra.core.net import Dns, Http, NXDomain
from umbra.modules.wayback import classify_urls

KEYWORDS: dict[str, set[str]] = {
    "desarrollo/pruebas": {"dev", "develop", "development", "test", "testing", "qa", "uat", "stage", "staging",
                           "stg", "pre", "preprod", "sandbox", "demo", "beta", "lab", "poc"},
    "acceso remoto": {"vpn", "sslvpn", "remote", "rdp", "citrix", "ssh", "gateway", "gw", "access", "owa",
                      "webmail", "exchange", "autodiscover", "mail", "smtp", "imap"},
    "administración": {"admin", "administrator", "panel", "manage", "manager", "cpanel", "plesk", "dashboard",
                       "portal", "intranet", "internal", "corp", "sso", "auth", "login", "idp", "adfs"},
    "APIs": {"api", "apis", "graphql", "ws", "rest", "backend", "services"},
    "DevOps": {"git", "gitlab", "github", "jenkins", "ci", "cd", "jira", "confluence", "grafana", "kibana",
               "prometheus", "sonar", "sonarqube", "nexus", "harbor", "argocd", "k8s", "registry", "vault"},
    "legado/copias": {"old", "legacy", "backup", "bak", "archive", "temp", "tmp", "v1", "v2"},
}


def interesting(subdomain: str, root: str) -> list[str]:
    """Categorías de palabras clave presentes en las etiquetas del subdominio."""
    label = subdomain[: -len(root) - 1] if subdomain.endswith("." + root) else subdomain
    tokens = {re.sub(r"\d+$", "", tok) for tok in re.split(r"[.\-_]", label) if tok}
    return [f"{cat} ({', '.join(sorted(tokens & words))})" for cat, words in KEYWORDS.items() if tokens & words]


async def harvest(domain: str, http: Http, use_wayback: bool) -> tuple[dict[str, set[str]], list[str]]:
    errors: list[str] = []
    sources: dict[str, set[str]] = {}
    crt, ht, thc, wb = await asyncio.gather(
        web.safe(lookups.crtsh(http, domain), errors, "crt.sh"),
        web.safe(lookups.hackertarget(http, domain), errors, "HackerTarget"),
        web.safe(lookups.thc(http, domain), errors, "ip.thc.org"),
        web.safe(_wayback_hosts(http, domain), errors, "Wayback") if use_wayback else asyncio.sleep(0),
    )
    if crt:
        sources["crt.sh"] = crt[0]
    if ht:
        sources["HackerTarget"] = set(ht)
    if thc:
        sources["ip.thc.org"] = thc
    if wb:
        sources["Wayback"] = wb
    found: dict[str, set[str]] = {}
    for source, subs in sources.items():
        for sub in subs:
            if (e := Entity.try_of(T.DOMAIN, sub)) and e.value.endswith("." + domain):
                found.setdefault(e.value, set()).add(source)
    return found, errors


async def _wayback_hosts(http: Http, domain: str) -> set[str]:
    rows = await http.get_json(
        "https://web.archive.org/cdx/search/cdx",
        params={"url": domain, "matchType": "domain", "fl": "original", "collapse": "urlkey",
                "output": "json", "limit": "20000"},
        timeout=60, retries=0,
    )
    urls = [r[0] for r in (rows or [])[1:] if r]
    return classify_urls(urls, domain).hosts


async def resolve_all(names: list[str], dns: Dns) -> dict[str, list[str]]:
    async def one(name: str) -> tuple[str, list[str]]:
        try:
            return name, await dns.query(name, "A")
        except NXDomain:
            return name, []

    return dict(await asyncio.gather(*(one(n) for n in names)))


def run(case: Case) -> None:
    ui.title("Subdominios", "Certificate Transparency (crt.sh), DNS pasivo (HackerTarget, ip.thc.org) y Wayback.")
    domain = Entity.try_of(T.DOMAIN, ui.ask("Dominio raíz"))
    if not domain:
        ui.warn("Dominio no válido.")
        return
    d = domain.value
    use_wayback = ui.confirm("¿Incluir también la Wayback Machine? (más lento)", default=False)

    with ui.status("Recolectando subdominios de varias fuentes (crt.sh puede tardar un minuto)…"):
        found, errors = web.run(lambda http, _dns: harvest(d, http, use_wayback), timeout=90)
    for err in errors:
        ui.warn(err)
    if not found:
        ui.info("Ninguna fuente ha devuelto subdominios.")
        return
    per_source = {s: sum(s in v for v in found.values()) for s in sorted({x for v in found.values() for x in v})}
    ui.ok(f"{len(found)} subdominios únicos · " + " · ".join(f"{s}: {n}" for s, n in per_source.items()))

    resolved: dict[str, list[str]] = {}
    if ui.confirm(f"¿Resolverlos por DNS para separar vivos de muertos? ({len(found)} consultas)", default=True):
        with ui.status("Resolviendo…"):
            resolved = web.run(lambda _http, dns: resolve_all(sorted(found), dns))

    rows = []
    for sub in sorted(found, key=lambda s: (not interesting(s, d), s)):
        tags = interesting(sub, d)
        ips = resolved.get(sub)
        state = "-" if not resolved else (", ".join(ips[:3]) if ips else "no resuelve")
        rows.append((sub, sorted(found[sub]), state, "; ".join(tags)))
    shown = rows[:150]
    ui.table(["Subdominio", "Fuentes", "IP", "Palabras clave"], shown, title="Subdominios (interesantes primero)")
    if len(rows) > len(shown):
        ui.note(f"… y {len(rows) - len(shown)} más en el fichero.")

    hot = [r for r in rows if r[3]]
    alive = [s for s, ips in resolved.items() if ips]
    all_path = case.save(f"subdominios_{d}.txt", "\n".join(sorted(found)) + "\n")
    ui.ok(f"{len(hot)} con palabras clave interesantes · lista completa en {all_path}")
    if alive:
        alive_path = case.save(f"vivos_{d}.txt", "\n".join(sorted(alive)) + "\n")
        ui.ok(f"{len(alive)} resuelven · lista para la validación en vivo: {alive_path}")
    ui.links([("crt.sh (consulta manual de la práctica)", f"https://crt.sh/?q={quote('%.' + d)}")], title="Manual")

    body = (
        f"{len(found)} subdominios únicos. Fuentes: "
        + ", ".join(f"{s} ({n})" for s, n in per_source.items())
        + (f". Resuelven: {len(alive)}." if resolved else ".")
        + "\n\n**Con palabras clave interesantes:**\n\n"
        + (ui.md_table(["Subdominio", "IP", "Palabras clave"], [(r[0], r[2], r[3]) for r in hot]) if hot else "_Ninguno._")
        + f"\n\nLista completa: `{all_path.name}`"
    )
    case.log("Subdominios", d, body)
