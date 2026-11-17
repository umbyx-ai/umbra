"""Huella DNS y de correo de un dominio (práctica "DNS footprinting").

Responde a la pregunta de clase: ¿su correo está en la nube (Google, Microsoft 365)
o en un servidor propio? Y de paso saca SPF, DKIM, DMARC, SOA y los rangos IP
que el SPF revela.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from datetime import datetime

from umbra import lookups, ui, web
from umbra.case import Case
from umbra.core.entities import Entity
from umbra.core.entities import EntityType as T
from umbra.core.known import MX_PROVIDERS, NS_PROVIDERS, SPF_SENDERS, match_provider, match_verifications
from umbra.core.net import Dns, Http, NXDomain
from umbra.modules.dns_records import analyze_dmarc, analyze_spf

# Selector DKIM -> proveedor que suele usarlo
DKIM_SELECTORS: dict[str, str | None] = {
    "google": "Google Workspace", "selector1": "Microsoft 365", "selector2": "Microsoft 365",
    "k1": "Mailchimp", "k2": "Mailchimp", "s1": "SendGrid", "s2": "SendGrid", "mandrill": "Mandrill",
    "zoho": "Zoho Mail", "protonmail": "Proton Mail", "protonmail2": "Proton Mail", "fm1": "Fastmail",
    "default": None, "dkim": None, "mail": None, "smtp": None, "mx": None, "key1": None,
    "sig1": None, "everlytickey1": "Everlytic", "mxvault": None,
}
RECORD_TYPES = ["A", "AAAA", "MX", "NS", "SOA", "TXT", "CAA"]


def parse_soa(record: str) -> dict[str, str]:
    parts = record.split()
    if len(parts) < 3:
        return {}
    primary, rname, serial = parts[0].rstrip("."), parts[1].rstrip("."), parts[2]
    # El primer punto no escapado del RNAME es la @ del email del responsable
    match = re.match(r"^((?:[^.\\]|\\.)*)\.(.+)$", rname)
    contact = f"{match.group(1).replace(chr(92), '')}@{match.group(2)}" if match else rname
    info = {"servidor_primario": primary, "contacto": contact, "serial": serial}
    if re.fullmatch(r"(19|20)\d{8}", serial):
        try:
            info["ultima_modificacion"] = datetime.strptime(serial[:8], "%Y%m%d").strftime("%d/%m/%Y")
        except ValueError:
            pass
    return info


def spf_ranges(txts: list[str]) -> list[str]:
    ranges = []
    for txt in txts:
        if txt.lower().startswith("v=spf1"):
            ranges += [t.split(":", 1)[1] for t in txt.split() if t.lower().startswith(("ip4:", "ip6:"))]
    return ranges


def mail_verdict(domain: str, mx: list[tuple[int, str]], dkim_providers: set[str], mx_holders: list[str]) -> str:
    if not mx:
        return "No tiene MX: el dominio no recibe correo."
    providers = {p for _, host in mx if (p := match_provider(host, MX_PROVIDERS))}
    if providers:
        return f"En la nube: {', '.join(sorted(providers))} (lo dicen sus registros MX)."
    own = [host for _, host in mx if host == domain or host.endswith("." + domain)]
    clouds = {h for h in mx_holders if h}
    if own:
        hint = f" Su IP es de {', '.join(sorted(clouds))}." if clouds else ""
        extra = f" Firma DKIM de {', '.join(sorted(dkim_providers))}." if dkim_providers else ""
        return f"Probablemente on-premise o servidor propio: el MX ({own[0]}) está en su dominio.{hint}{extra}"
    return f"Proveedor externo no identificado: {mx[0][1]}."


@dataclass
class MailReport:
    domain: str
    records: dict[str, list[str]] = field(default_factory=dict)
    dmarc: list[str] = field(default_factory=list)
    dkim: dict[str, str] = field(default_factory=dict)
    mx: list[tuple[int, str]] = field(default_factory=list)
    mx_info: list[dict[str, str | None]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


async def _txt_or_empty(dns: Dns, name: str) -> list[str]:
    try:
        return await dns.query(name, "TXT")
    except NXDomain:
        return []


async def collect(domain: str, http: Http, dns: Dns) -> MailReport:
    report = MailReport(domain)
    results = await asyncio.gather(*(dns.query(domain, t) for t in RECORD_TYPES), return_exceptions=True)
    if any(isinstance(r, NXDomain) for r in results):
        raise NXDomain(domain)
    for rtype, result in zip(RECORD_TYPES, results, strict=True):
        report.records[rtype] = [] if isinstance(result, BaseException) else result
    report.dmarc = await _txt_or_empty(dns, f"_dmarc.{domain}")

    selectors = list(DKIM_SELECTORS)
    dkim = await asyncio.gather(*(_txt_or_empty(dns, f"{s}._domainkey.{domain}") for s in selectors))
    for selector, txts in zip(selectors, dkim, strict=True):
        record = next((t for t in txts if "p=" in t or t.lower().startswith("v=dkim1")), None)
        if record:
            report.dkim[selector] = record

    report.mx = await lookups.mx_hosts(dns, domain)

    async def mx_detail(host: str) -> dict[str, str | None]:
        detail: dict[str, str | None] = {"host": host, "ip": None, "asn": None, "titular": None}
        try:
            ips = await dns.query(host, "A")
        except NXDomain:
            return detail
        if ips:
            detail["ip"] = ips[0]
            owner = await web.safe(lookups.ip_owner(http, ips[0]), report.errors, f"RIPEstat {ips[0]}")
            if owner:
                detail.update(asn=owner["asn"], titular=owner["titular"])
        return detail

    report.mx_info = list(await asyncio.gather(*(mx_detail(h) for _, h in report.mx[:5])))
    return report


def _commands(domain: str) -> list[tuple[str, str]]:
    return [
        ("MX", f"dig MX {domain} +short    |  nslookup -type=mx {domain}"),
        ("SPF", f"dig TXT {domain} +short | grep v=spf1    |  nslookup -type=txt {domain}"),
        ("DMARC", f"dig TXT _dmarc.{domain} +short"),
        ("DKIM", f"dig TXT selector1._domainkey.{domain} +short"),
        ("SOA", f"dig SOA {domain} +short"),
    ]


def run(case: Case) -> None:
    ui.title("DNS y correo", "MX, SPF, DKIM, DMARC, NS y SOA. ¿Correo en la nube u on-premise?")
    domain = Entity.try_of(T.DOMAIN, ui.ask("Dominio"))
    if not domain:
        ui.warn("Dominio no válido.")
        return
    d = domain.value
    with ui.status(f"Consultando el DNS de {d} (incluye {len(DKIM_SELECTORS)} selectores DKIM)…"):
        try:
            rep = web.run(lambda http, dns: collect(d, http, dns))
        except NXDomain:
            ui.error(f"{d} no existe (NXDOMAIN).")
            return

    r = rep.records
    txts = r.get("TXT", [])
    ui.table(["Tipo", "Registros"], [(t, "\n".join(r.get(t, [])) or "-") for t in RECORD_TYPES], title="Registros DNS")

    mx_rows = [
        (pref, info["host"], info["ip"], info["asn"], info["titular"], match_provider(info["host"], MX_PROVIDERS))
        for (pref, _), info in zip(rep.mx, rep.mx_info, strict=False)
    ]
    if mx_rows:
        ui.table(["Prioridad", "MX", "IP", "ASN", "Titular de la IP", "Proveedor"], mx_rows, title="Servidores de correo")

    spf_checks = analyze_spf(txts)
    dmarc_checks = analyze_dmarc(rep.dmarc)
    includes = next((c.data.get("includes") for c in spf_checks if "includes" in c.data), []) or []
    senders = sorted({s for inc in includes if (s := match_provider(inc, SPF_SENDERS))})
    ranges = spf_ranges(txts)
    dkim_providers = {p for s in rep.dkim if (p := DKIM_SELECTORS.get(s))}
    soa = parse_soa(r["SOA"][0]) if r.get("SOA") else {}
    ns_providers = sorted({p for ns in r.get("NS", []) if (p := match_provider(ns.rstrip("."), NS_PROVIDERS))})
    verdict = mail_verdict(d, rep.mx, dkim_providers, [i["titular"] or "" for i in rep.mx_info])

    analysis = [
        ("Veredicto correo", verdict),
        ("SPF", "; ".join(f"{c.title}" for c in spf_checks if not c.title.startswith("Servicios")) or "-"),
        ("Autorizados en SPF", senders),
        ("Rangos IP en SPF", ranges),
        ("DMARC", "; ".join(c.title for c in dmarc_checks)),
        ("DKIM encontrado", [f"{s} ({DKIM_SELECTORS[s] or 'genérico'})" for s in rep.dkim]),
        ("Proveedor DNS", ns_providers),
        ("Servicios por TXT", match_verifications(txts)),
        ("SOA", "; ".join(f"{k}: {v}" for k, v in soa.items())),
    ]
    ui.kv(analysis, title="Análisis")
    if ranges:
        ui.note("Los rangos ip4:/ip6: del SPF suelen revelar infraestructura propia de la organización.")
    for err in rep.errors:
        ui.warn(err)
    ui.table(["Registro", "Comando equivalente"], _commands(d), title="Para comprobarlo tú con dig / nslookup")

    body = "\n\n".join([
        f"**Veredicto:** {verdict}",
        ui.md_table(["Tipo", "Registros"], [(t, "<br>".join(r.get(t, []))) for t in RECORD_TYPES]),
        ui.md_table(["Prioridad", "MX", "IP", "ASN", "Titular", "Proveedor"], mx_rows) if mx_rows else "",
        ui.md_table(["Campo", "Valor"], analysis),
    ])
    case.log("DNS y correo", d, body)
