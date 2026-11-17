"""Emails de una organización (práctica "get mail addresses from company name").

Las tres partes de la práctica:

- domain search: direcciones publicadas del dominio (certificados, DNS, WHOIS, su web, Hunter.io).
- email finder: posibles direcciones de una persona a partir de su nombre.
- single email: comprobar si un email tiene pinta de ser real.
"""

from __future__ import annotations

import asyncio
import os
import re
import unicodedata

from umbra import lookups, ui, web
from umbra.case import Case
from umbra.core.entities import Entity
from umbra.core.entities import EntityType as T
from umbra.core.known import FREE_EMAIL_PROVIDERS, MX_PROVIDERS, match_provider
from umbra.core.net import Dns, Http, NXDomain
from umbra.modules.dns_records import dmarc_report_emails
from umbra.tools.dnsmail import parse_soa

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
OBFUSCATED_RE = re.compile(
    r"([a-zA-Z0-9._%+-]+)\s*[\[({]\s*(?:at|arroba)\s*[\])}]\s*([a-zA-Z0-9.-]+?)\s*[\[({]\s*(?:dot|punto)\s*[\])}]\s*([a-zA-Z]{2,})",
    re.I,
)
NOT_TLDS = {"png", "jpg", "jpeg", "gif", "svg", "webp", "css", "js", "ico"}
WEB_PATHS = ["", "contacto", "contact", "contacta", "aviso-legal", "legal", "privacidad",
             "politica-de-privacidad", "privacy", "quienes-somos", "about", "equipo", "team"]
ROLE_ACCOUNTS = {
    "info", "contacto", "contact", "admin", "hostmaster", "postmaster", "webmaster", "abuse", "noc", "rgpd",
    "dpo", "privacy", "privacidad", "soporte", "support", "ventas", "sales", "rrhh", "hr", "prensa", "press",
    "marketing", "hola", "hello", "comercial", "administracion", "facturacion", "empleo", "jobs", "careers",
    "security", "seguridad", "legal", "dmarc", "noreply", "no-reply", "office", "oficina", "recepcion",
}
DISPOSABLE = {
    "mailinator.com", "10minutemail.com", "guerrillamail.com", "yopmail.com", "tempmail.com", "temp-mail.org",
    "trashmail.com", "getnada.com", "sharklasers.com", "maildrop.cc", "dispostable.com", "fakeinbox.com",
    "throwawaymail.com", "emailondeck.com", "mohmal.com",
}


def extract_emails(text: str) -> set[str]:
    found: set[str] = set()
    candidates = EMAIL_RE.findall(text) + [f"{u}@{d}.{t}" for u, d, t in OBFUSCATED_RE.findall(text)]
    for raw in candidates:
        if raw.rsplit(".", 1)[-1].lower() in NOT_TLDS:  # logo@2x.png no es un email
            continue
        if email := Entity.try_of(T.EMAIL, raw.strip(".")):
            found.add(email.value)
    return found


def is_role(email: str) -> bool:
    """Cuenta genérica (info@, dmarc-ruf@, noreply@...) o con el nombre de la propia organización (iana@iana.org)."""
    local, _, domain = email.partition("@")
    first = re.split(r"[._+-]", local, maxsplit=1)[0]
    org = domain.split(".")[-2] if domain.count(".") >= 1 else domain
    return local in ROLE_ACCOUNTS or first in ROLE_ACCOUNTS or local == org


def infer_pattern(emails: list[str]) -> str | None:
    """Adivina el formato de las direcciones personales (nombre.apellido, inicial+apellido...)."""
    personal = [e.split("@", 1)[0] for e in emails if not is_role(e)]
    if len(personal) < 2:
        return None
    for sep, pattern in ((".", "{nombre}.{apellido}"), ("_", "{nombre}_{apellido}"), ("-", "{nombre}-{apellido}")):
        hits = sum(bool(re.fullmatch(rf"[a-z]+\{sep}[a-z]+", p)) for p in personal)
        if hits >= 2 and hits >= len(personal) / 2:
            return pattern
    return None


def _tokens(text: str) -> list[str]:
    ascii_text = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode().lower()
    return [t for t in re.split(r"[^a-z0-9]+", ascii_text) if t]


def permutations(first: str, last1: str, last2: str, domain: str) -> list[str]:
    """Formatos habituales de email corporativo (incluye el segundo apellido, típico en España)."""
    names, a_tokens, b_tokens = _tokens(first), _tokens(last1), _tokens(last2)
    if not names or not a_tokens:
        return []
    n1, n = names[0], "".join(names)
    a, b = "".join(a_tokens), "".join(b_tokens)
    i, j = n1[0], a[0]
    locals_ = [n1, f"{n1}.{a}", f"{n1}{a}", f"{n1}_{a}", f"{n1}-{a}", f"{i}{a}", f"{i}.{a}", f"{n1}{j}",
               f"{n1}.{j}", f"{a}.{n1}", f"{a}{n1}", f"{a}{i}", f"{a}.{i}", a]
    if n != n1:
        locals_ += [n, f"{n}.{a}", f"{n}{a}"]
    if b:
        locals_ += [f"{n1}.{a}.{b}", f"{n1}{a}{b}", f"{i}{a}{b}", f"{i}{a}{b[0]}", f"{n1}.{a}{b[0]}",
                    f"{n1}{j}{b[0]}", f"{i}.{a}.{b}"]
    return [f"{local}@{domain}" for local in dict.fromkeys(locals_)]


# --- fuentes -----------------------------------------------------------------

async def _website(http: Http, domain: str) -> dict[str, set[str]]:
    async def one(path: str) -> tuple[str, str] | None:
        try:
            resp = await http.get(f"https://{domain}/{path}", retries=0, timeout=12)
        except Exception:  # noqa: BLE001 - página que no existe o no responde
            return None
        if resp.status_code == 200 and "html" in resp.headers.get("content-type", ""):
            return str(resp.url), resp.text
        return None

    found: dict[str, set[str]] = {}
    for page in await asyncio.gather(*(one(p) for p in WEB_PATHS)):
        if page:
            for email in extract_emails(page[1]):
                found.setdefault(email, set()).add(page[0])
    return found


async def _hunter(http: Http, domain: str, key: str) -> tuple[list[dict], str | None]:
    data = await http.get_json("https://api.hunter.io/v2/domain-search",
                               params={"domain": domain, "api_key": key, "limit": "100"}, missing=())
    body = (data or {}).get("data") or {}
    return body.get("emails") or [], body.get("pattern")


async def domain_search(domain: str, http: Http, dns: Dns, use_web: bool) -> dict:
    errors: list[str] = []
    found: dict[str, set[str]] = {}

    def add(emails, source: str) -> None:
        for e in emails:
            found.setdefault(e, set()).add(source)

    async def txt(name: str) -> list[str]:
        try:
            return await dns.query(name, "TXT")
        except NXDomain:
            return []

    key = os.environ.get("HUNTER_API_KEY")
    crt, soa, dmarc, whois, site, hunter = await asyncio.gather(
        web.safe(lookups.crtsh(http, domain), errors, "crt.sh"),
        web.safe(dns.query(domain, "SOA"), errors, "SOA"),
        web.safe(txt(f"_dmarc.{domain}"), errors, "DMARC"),
        web.safe(lookups.whois_domain(domain), errors, "WHOIS"),
        web.safe(_website(http, domain), errors, "web") if use_web else asyncio.sleep(0),
        web.safe(_hunter(http, domain, key), errors, "Hunter.io") if key else asyncio.sleep(0),
    )
    if crt:
        add(crt[1], "certificados (crt.sh)")
    if soa:
        contact = parse_soa(soa[0]).get("contacto")
        if contact and (e := Entity.try_of(T.EMAIL, contact)):
            add([e.value], "DNS SOA")
    if dmarc:
        add([e for e in dmarc_report_emails(dmarc) if Entity.try_of(T.EMAIL, e)], "DNS DMARC")
    for _, text in whois or []:
        add(extract_emails(text), "WHOIS")
    for email, pages in (site or {}).items():
        add([email], "web: " + ", ".join(sorted(p.split("//", 1)[-1] for p in pages))[:80])
    pattern = None
    if hunter:
        add([h["value"] for h in hunter[0] if h.get("value")], "Hunter.io")
        pattern = hunter[1]
    return {"found": found, "errors": errors, "hunter_pattern": pattern}


async def verify(email: str, http: Http, dns: Dns) -> dict:
    domain = email.rpartition("@")[2]
    errors: list[str] = []
    mx, profile = await asyncio.gather(
        web.safe(lookups.mx_hosts(dns, domain), errors, "MX"),
        web.safe(lookups.gravatar_profile(http, email), errors, "Gravatar"),
    )
    result = {"mx": mx or [], "gravatar": profile, "errors": errors, "hunter": None}
    if key := os.environ.get("HUNTER_API_KEY"):
        data = await web.safe(http.get_json("https://api.hunter.io/v2/email-verifier",
                                            params={"email": email, "api_key": key}, missing=()), errors, "Hunter.io")
        result["hunter"] = (data or {}).get("data")
    return result


# --- interacción -------------------------------------------------------------

def _domain_search(case: Case) -> None:
    ui.title("Domain search", "Direcciones del dominio publicadas en fuentes abiertas.")
    domain = Entity.try_of(T.DOMAIN, ui.ask("Dominio de la organización"))
    if not domain:
        ui.warn("Dominio no válido.")
        return
    d = domain.value
    use_web = ui.confirm("¿Buscar también en su web (contacto, aviso legal, privacidad...)? Visita la web", default=True)
    if not os.environ.get("HUNTER_API_KEY"):
        ui.note("Consejo: con una clave gratuita de Hunter.io (variable HUNTER_API_KEY) salen muchos más.")
    with ui.status("Buscando emails en certificados, DNS, WHOIS y la web…"):
        res = web.run(lambda http, dns: domain_search(d, http, dns, use_web), timeout=60)
    for err in res["errors"]:
        ui.warn(err)
    found = res["found"]
    own = sorted(e for e in found if e.endswith("@" + d) or e.endswith("." + d))
    other = sorted(e for e in found if e not in own)
    ui.table(["Email", "Tipo", "Fuente"], [(e, "genérico" if is_role(e) else "personal", sorted(found[e])) for e in own],
             title=f"Emails de {d} ({len(own)})")
    if other:
        ui.table(["Email", "Fuente"], [(e, sorted(found[e])) for e in other], title="Otros dominios (registrador, proveedores...)")
    pattern = res["hunter_pattern"] or infer_pattern(own)
    if pattern:
        ui.ok(f"Formato probable de las direcciones personales: {pattern}@{d}")
    dorks = [
        ("Google: emails fuera de su web", "https://www.google.com/search?q=" + f'%22%40{d}%22+-site%3A{d}'),
        ("Google: emails en documentos", "https://www.google.com/search?q=" + f'%22%40{d}%22+filetype%3Apdf'),
        ("Hunter.io (domain search)", f"https://hunter.io/search/{d}"),
        ("Phonebook.cz", "https://phonebook.cz/"),
    ]
    ui.links(dorks, title="Seguir buscando")
    case.log("Emails de una organización", d, "\n\n".join([
        ui.md_table(["Email", "Fuente"], [(e, sorted(found[e])) for e in own + other]) if found else "_Ninguno._",
        f"Formato probable: `{pattern}@{d}`" if pattern else "",
    ]))


def _finder(case: Case) -> None:
    ui.title("Email finder", "Genera las direcciones probables de una persona y busca señales de que existen.")
    first = ui.ask("Nombre")
    last1 = ui.ask("Primer apellido")
    last2 = ui.ask("Segundo apellido", required=False)
    domain = Entity.try_of(T.DOMAIN, ui.ask("Dominio de la empresa"))
    if not domain:
        ui.warn("Dominio no válido.")
        return
    candidates = permutations(first, last1, last2, domain.value)
    if not candidates:
        ui.warn("No he podido generar direcciones con esos datos.")
        return

    async def job(http: Http, dns: Dns):
        mx = await lookups.mx_hosts(dns, domain.value)
        checks = await asyncio.gather(*(web.safe(lookups.gravatar_exists(http, c), [], c) for c in candidates))
        return mx, checks

    with ui.status(f"Comprobando {len(candidates)} candidatos en Gravatar…"):
        mx, gravatar = web.run(job)
    if not mx:
        ui.warn(f"{domain.value} no tiene MX: no recibe correo, ninguna dirección será válida.")
    hits = [c for c, g in zip(candidates, gravatar, strict=True) if g]
    ui.table(["Candidato", "Gravatar"], [(c, "SÍ: existe" if g else "") for c, g in zip(candidates, gravatar, strict=True)],
             title=f"{len(candidates)} candidatos")
    if hits:
        ui.ok(f"Con perfil en Gravatar (casi seguro reales): {', '.join(hits)}")
    ui.note("Comprobar el buzón por SMTP (RCPT TO) es una técnica activa, poco fiable y los ISP bloquean el puerto 25: "
            "Umbra no la usa. Con HUNTER_API_KEY puedes verificar cada candidato en la opción 3.")
    case.log("Email finder", f"{first} {last1} {last2} @ {domain.value}".replace("  ", " "),
             ui.md_table(["Candidato", "Gravatar"], [(c, "sí" if g else "") for c, g in zip(candidates, gravatar, strict=True)]))


def _verify(case: Case) -> None:
    ui.title("Verificar un email", "Sintaxis, MX, proveedor, Gravatar y (con clave) Hunter.io.")
    email = Entity.try_of(T.EMAIL, ui.ask("Email"))
    if not email:
        ui.warn("Sintaxis no válida.")
        return
    e = email.value
    domain = e.rpartition("@")[2]
    with ui.status("Comprobando…"):
        res = web.run(lambda http, dns: verify(e, http, dns))
    mx = res["mx"]
    providers = sorted({p for _, h in mx if (p := match_provider(h, MX_PROVIDERS))})
    profile = res["gravatar"] or {}
    rows = [
        ("Sintaxis", "válida"),
        ("Servidores MX", [h for _, h in mx] or "ninguno: el dominio no recibe correo"),
        ("Proveedor de correo", providers),
        ("Tipo", "gratuito" if domain in FREE_EMAIL_PROVIDERS else "desechable" if domain in DISPOSABLE else "corporativo / propio"),
        ("Cuenta genérica", "sí" if is_role(e) else "no"),
        ("Gravatar", profile.get("profileUrl") or "sin perfil"),
        ("Nombre (Gravatar)", profile.get("displayName")),
        ("Cuentas enlazadas", [a.get("url") for a in profile.get("accounts") or [] if a.get("url")]),
    ]
    if hunter := res["hunter"]:
        rows += [("Hunter.io", f"{hunter.get('result')} (puntuación {hunter.get('score')})")]
    ui.kv(rows, title=e)
    for err in res["errors"]:
        ui.warn(err)
    ui.note("Para ver si ha aparecido en filtraciones usa la opción 'Filtraciones de un email'.")
    case.log("Verificar email", e, ui.md_table(["Campo", "Valor"], rows))


def run(case: Case) -> None:
    ui.title("Emails de una organización", "Domain search, email finder y verificación de un email.")
    choice = ui.choose([
        ("1", "Buscar emails de un dominio (domain search)"),
        ("2", "Generar los emails de una persona (email finder)"),
        ("3", "Verificar un email (single email)"),
        ("0", "Volver"),
    ])
    match choice:
        case "1":
            _domain_search(case)
        case "2":
            _finder(case)
        case "3":
            _verify(case)
