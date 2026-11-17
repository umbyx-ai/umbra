"""WHOIS, RDAP y ASN (práctica "The Origin").

A partir de un dominio, una IP, un ASN o el nombre de una empresa saca:
registrador, fechas, entidad legal (si el RGPD no la oculta), ASN, titular y los
bloques CIDR que anuncia la organización.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re

from umbra import lookups, ui, web
from umbra.case import Case
from umbra.core.entities import Entity
from umbra.core.entities import EntityType as T
from umbra.core.net import Dns, Http, NXDomain
from umbra.modules.rdap import parse_rdap_domain

GDPR_NOTE = (
    "Por el RGPD casi todos los registros ocultan los datos personales del titular, "
    "pero la infraestructura (registrador, NS, ASN, CIDR) sigue siendo pública."
)


def asn_links(asn: str) -> list[tuple[str, str]]:
    n = asn.upper().removeprefix("AS")
    return [
        ("bgp.he.net", f"https://bgp.he.net/AS{n}"),
        ("bgp.tools", f"https://bgp.tools/as/{n}"),
        ("RIPEstat", f"https://stat.ripe.net/AS{n}"),
    ]


def summarize_prefixes(prefixes: list[str]) -> tuple[list[str], list[str]]:
    v4 = [p for p in prefixes if ":" not in p]
    v6 = [p for p in prefixes if ":" in p]
    key = lambda p: ipaddress.ip_network(p, strict=False)  # noqa: E731
    return sorted(v4, key=key), sorted(v6, key=key)


async def _domain(domain: str, http: Http, dns: Dns) -> dict:
    errors: list[str] = []
    rdap, whois, ips = await asyncio.gather(
        web.safe(http.get_json(f"https://rdap.org/domain/{domain}", missing=(400, 404)), errors, "RDAP"),
        web.safe(lookups.whois_domain(domain), errors, "WHOIS (puerto 43)"),
        web.safe(dns.query(domain, "A"), errors, "DNS"),
    )
    owner = await web.safe(lookups.ip_owner(http, ips[0]), errors, "RIPEstat") if ips else None
    ip_rdap = await web.safe(lookups.rdap_ip(http, ips[0]), errors, "RDAP IP") if ips else None
    return {"rdap": rdap, "whois": whois or [], "ips": ips or [], "owner": owner, "ip_rdap": ip_rdap, "errors": errors}


async def _ip(ip: str, http: Http) -> dict:
    errors: list[str] = []
    owner, ip_rdap = await asyncio.gather(
        web.safe(lookups.ip_owner(http, ip), errors, "RIPEstat"),
        web.safe(lookups.rdap_ip(http, ip), errors, "RDAP"),
    )
    return {"owner": owner, "ip_rdap": ip_rdap, "errors": errors}


async def _asn(asn: str, http: Http) -> dict:
    errors: list[str] = []
    holder, prefixes = await asyncio.gather(
        web.safe(lookups.asn_holder(http, asn), errors, "RIPEstat"),
        web.safe(lookups.asn_prefixes(http, asn), errors, "RIPEstat prefijos"),
    )
    return {"holder": holder, "prefixes": prefixes or [], "errors": errors}


def _show_asn(case: Case, asn: str) -> None:
    with ui.status(f"Consultando {asn} y sus prefijos anunciados (BGP)…"):
        data = web.run(lambda http, _dns: _asn(asn, http))
    for err in data["errors"]:
        ui.warn(err)
    v4, v6 = summarize_prefixes(data["prefixes"])
    ui.kv([("ASN", asn), ("Titular", data["holder"]), ("Prefijos IPv4", len(v4)), ("Prefijos IPv6", len(v6))])
    if v4 or v6:
        ui.table(["IPv4", "IPv6"], [(a, b) for a, b in _pairs(v4[:60], v6[:60])], title="Bloques CIDR anunciados")
        path = case.save(f"cidr_{asn}.txt", "\n".join(v4 + v6) + "\n")
        ui.ok(f"Lista completa en {path}")
    ui.links(asn_links(asn), title="Ver el ASN")
    case.log("WHOIS / ASN", asn, ui.md_table(["Campo", "Valor"], [
        ("Titular", data["holder"]), ("IPv4", len(v4)), ("IPv6", len(v6)), ("Muestra", (v4 + v6)[:20]),
    ]))


def _pairs(a: list[str], b: list[str]):
    for i in range(max(len(a), len(b))):
        yield (a[i] if i < len(a) else "", b[i] if i < len(b) else "")


def _ip_rows(owner: dict | None, ip_rdap: dict | None) -> list[tuple[str, object]]:
    owner, ip_rdap = owner or {}, ip_rdap or {}
    return [
        ("ASN", owner.get("asn")),
        ("Titular del ASN", owner.get("titular")),
        ("Prefijo BGP", owner.get("prefijo")),
        ("Red (RDAP)", ip_rdap.get("red")),
        ("Organización (RDAP)", ip_rdap.get("organizacion")),
        ("Rango asignado", ip_rdap.get("rango")),
        ("País", ip_rdap.get("pais")),
        ("Contacto de abuso", ip_rdap.get("abuse")),
    ]


def run(case: Case) -> None:
    ui.title("WHOIS, RDAP y ASN", "Dominio, IP, ASN (AS13335) o nombre de una empresa.")
    raw = ui.ask("Objetivo")
    target = (
        Entity.try_of(T.IP, raw)
        or (Entity.try_of(T.ASN, raw) if re.fullmatch(r"(?i)as\d+", raw.strip()) else None)
        or Entity.try_of(T.DOMAIN, raw)
    )

    if target is None:
        with ui.status("Buscando ASNs por nombre…"):
            matches = web.run(lambda http, _dns: lookups.asn_search(http, raw))
        if not matches:
            ui.info("No hay ASNs con ese nombre.")
            return
        ui.table(["#", "ASN", "Titular"], [(i, a, d) for i, (a, d) in enumerate(matches, 1)])
        pick = ui.ask("Número del ASN a consultar (Enter = ninguno)", required=False)
        if pick.isdigit() and 1 <= int(pick) <= len(matches):
            _show_asn(case, matches[int(pick) - 1][0])
        return

    if target.type is T.ASN:
        _show_asn(case, target.value)
        return

    if target.type is T.IP:
        with ui.status("Consultando RDAP y RIPEstat…"):
            data = web.run(lambda http, _dns: _ip(target.value, http))
        rows = _ip_rows(data["owner"], data["ip_rdap"])
        ui.kv(rows, title=f"IP {target.value}")
        for err in data["errors"]:
            ui.warn(err)
        if asn := (data["owner"] or {}).get("asn"):
            ui.links(asn_links(asn), title="Ver el ASN")
            if ui.confirm("¿Ver todos los bloques CIDR de ese ASN?", default=False):
                _show_asn(case, asn)
        case.log("WHOIS / ASN", target.value, ui.md_table(["Campo", "Valor"], rows))
        return

    d = target.value
    with ui.status(f"Consultando RDAP, WHOIS y ASN de {d}…"):
        try:
            data = web.run(lambda http, dns: _domain(d, http, dns))
        except NXDomain:
            data = {"rdap": None, "whois": [], "ips": [], "owner": None, "ip_rdap": None, "errors": []}
    rdap = parse_rdap_domain(data["rdap"]) if isinstance(data["rdap"], dict) else {}
    highlights = [hl for _, text in data["whois"] for hl in lookups.whois_highlights(text)]
    registrant = list(dict.fromkeys(
        v for k, v in highlights
        if re.search(r"registrant.*(org|name)|holder|owner|^org(anisation|anization)?$", k, re.I)
        and "redacted" not in v.lower()
    ))

    rows: list[tuple[str, object]] = [
        ("Registrador", rdap.get("registrador")),
        ("Titular (WHOIS)", registrant or "oculto / no publicado"),
        ("Alta", rdap.get("creado")),
        ("Caducidad", rdap.get("expira")),
        ("Nameservers", rdap.get("nameservers")),
        ("DNSSEC", {True: "sí", False: "no"}.get(rdap.get("dnssec"), "-")),
        ("IP principal", data["ips"][:3]),
    ] + _ip_rows(data["owner"], data["ip_rdap"])
    ui.kv(rows, title=d)
    if highlights:
        servers = ", ".join(s for s, _ in data["whois"])
        ui.table(["Campo", "Valor"], highlights[:25], title=f"WHOIS en bruto ({servers})")
    if not rdap and not highlights:
        ui.warn("Ni RDAP ni WHOIS han devuelto datos (algunos ccTLD como .es restringen el acceso).")
    for err in data["errors"]:
        ui.warn(err)
    ui.note(GDPR_NOTE)
    asn = (data["owner"] or {}).get("asn")
    extra = asn_links(asn) if asn else []
    ui.links(extra + [("RDAP (rdap.org)", f"https://rdap.org/domain/{d}")], title="Ver más")
    if asn and ui.confirm(f"¿Ver todos los bloques CIDR de {asn}?", default=False):
        _show_asn(case, asn)
    case.log("WHOIS / ASN", d, ui.md_table(["Campo", "Valor"], rows))
