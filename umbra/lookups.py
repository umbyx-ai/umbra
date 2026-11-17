"""Consultas a fuentes públicas reutilizadas por varias herramientas del menú.

Cada función hace una cosa (preguntar a una fuente) y devuelve datos ya limpios.
Las funciones ``parse_*`` son puras: no tocan la red y tienen tests.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
from typing import Any

from umbra.core.net import Dns, Http, NetError, NXDomain
from umbra.modules.crtsh import parse_crtsh

RIPE = "https://stat.ripe.net/data"
SOURCEAPP = "umbra-osint"
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


# --- RIPEstat: ASN, prefijos y operadores -----------------------------------

async def ripe(http: Http, call: str, resource: str) -> dict[str, Any]:
    data = await http.get_json(f"{RIPE}/{call}/data.json", params={"resource": resource, "sourceapp": SOURCEAPP})
    return (data or {}).get("data") or {}


async def ip_owner(http: Http, ip: str) -> dict[str, Any]:
    """ASN, prefijo y titular de una IP."""
    info = await ripe(http, "network-info", ip)
    asns = [f"AS{a}" for a in info.get("asns") or []]
    holder = await asn_holder(http, asns[0]) if asns else None
    return {"asn": asns[0] if asns else None, "prefijo": info.get("prefix"), "titular": holder}


async def asn_holder(http: Http, asn: str) -> str | None:
    return (await ripe(http, "as-overview", asn)).get("holder")


async def asn_prefixes(http: Http, asn: str) -> list[str]:
    data = await ripe(http, "announced-prefixes", asn)
    return [p["prefix"] for p in data.get("prefixes") or [] if p.get("prefix")]


async def asn_search(http: Http, text: str) -> list[tuple[str, str]]:
    data = await ripe(http, "searchcomplete", text)
    for category in data.get("categories") or []:
        if category.get("category") == "ASNs":
            return [(s["value"], s.get("description", "")) for s in category.get("suggestions") or []]
    return []


# --- RDAP de IPs -------------------------------------------------------------

def _vcard(entity: dict[str, Any], field: str) -> str | None:
    vcard = entity.get("vcardArray")
    if isinstance(vcard, list) and len(vcard) == 2:
        for item in vcard[1]:
            if isinstance(item, list) and len(item) >= 4 and item[0] == field and item[3]:
                value = item[3]
                return " ".join(value) if isinstance(value, list) else str(value)
    return None


def _walk_entities(entities: list[dict[str, Any]]):
    for ent in entities or []:
        yield ent
        yield from _walk_entities(ent.get("entities") or [])


def parse_rdap_ip(data: dict[str, Any]) -> dict[str, Any]:
    cidrs = [
        f"{c.get('v4prefix') or c.get('v6prefix')}/{c.get('length')}"
        for c in data.get("cidr0_cidrs") or []
        if c.get("length") is not None
    ]
    organization, abuse = None, []
    for ent in _walk_entities(data.get("entities") or []):
        roles = ent.get("roles") or []
        if "registrant" in roles and not organization:
            organization = _vcard(ent, "fn")
        if "abuse" in roles and (email := _vcard(ent, "email")):
            abuse.append(email)
    info = {
        "red": data.get("name"),
        "handle": data.get("handle"),
        "organizacion": organization,
        "rango": f"{data.get('startAddress')} - {data.get('endAddress')}" if data.get("startAddress") else None,
        "cidr": cidrs,
        "pais": data.get("country"),
        "abuse": sorted(set(abuse)),
    }
    return {k: v for k, v in info.items() if v not in (None, [], "")}


async def rdap_ip(http: Http, ip: str) -> dict[str, Any] | None:
    data = await http.get_json(f"https://rdap.org/ip/{ip}", missing=(400, 404))
    return parse_rdap_ip(data) if isinstance(data, dict) else None


# --- WHOIS clásico (puerto 43) -----------------------------------------------

async def whois_query(server: str, query: str, timeout: float = 10.0) -> str:
    reader, writer = await asyncio.wait_for(asyncio.open_connection(server, 43), timeout)
    try:
        writer.write(f"{query}\r\n".encode())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(), timeout)
    finally:
        writer.close()
    return data.decode("utf-8", "replace")


async def whois_domain(domain: str) -> list[tuple[str, str]]:
    """Sigue las referencias IANA -> registro -> registrador. Devuelve [(servidor, texto)]."""
    tld = domain.rsplit(".", 1)[-1]
    iana = await whois_query("whois.iana.org", tld)
    refer = re.search(r"^(?:refer|whois):\s*(\S+)", iana, re.M | re.I)
    if not refer:
        return [("whois.iana.org", iana)]
    server = refer.group(1)
    results = [(server, await whois_query(server, domain))]
    registrar = re.search(r"Registrar WHOIS Server:\s*(\S+)", results[0][1], re.I)
    if registrar and registrar.group(1).lower() not in (server.lower(), ""):
        try:
            results.append((registrar.group(1), await whois_query(registrar.group(1), domain)))
        except (OSError, TimeoutError):
            pass
    return results


WHOIS_KEYS = re.compile(
    r"registrant|registrar$|registrar:|sponsoring|creation|created|expir|updated|name server|nserver"
    r"|org|country|e-?mail|abuse|dnssec|status|holder|owner|descr|netname|admin-c",
    re.I,
)


def whois_highlights(text: str, limit: int = 30) -> list[tuple[str, str]]:
    """Líneas ``Clave: valor`` interesantes de una respuesta WHOIS (sin duplicados)."""
    seen: set[tuple[str, str]] = set()
    out: list[tuple[str, str]] = []
    for line in text.splitlines():
        if line.startswith(("%", "#", ">>>")) or ":" not in line:
            continue
        key, _, value = line.partition(":")
        key, value = key.strip(), value.strip()
        if not value or len(key) > 40 or not WHOIS_KEYS.search(key):
            continue
        if (key.lower(), value.lower()) in seen:
            continue
        seen.add((key.lower(), value.lower()))
        out.append((key, value))
        if len(out) >= limit:
            break
    return out


# --- subdominios -------------------------------------------------------------

async def crtsh(http: Http, domain: str) -> tuple[set[str], set[str]]:
    data = await http.get_json("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"}, timeout=90)
    if data is None:
        raise NetError("crt.sh devolvió una respuesta vacía (suele estar saturado; reinténtalo)")
    return parse_crtsh(data, domain)


def parse_hackertarget(text: str, domain: str) -> dict[str, str]:
    hosts: dict[str, str] = {}
    for line in text.splitlines():
        host, _, ip = line.strip().partition(",")
        host = host.lower().rstrip(".")
        if host == domain or host.endswith("." + domain):
            hosts[host] = ip.strip()
    return hosts


async def hackertarget(http: Http, domain: str) -> dict[str, str]:
    text = await http.get_text("https://api.hackertarget.com/hostsearch/", params={"q": domain}, retries=1)
    if text.lower().startswith("error") or "api count exceeded" in text.lower():
        raise NetError(f"HackerTarget: {text.strip()[:120]}")
    return parse_hackertarget(text, domain)


def parse_thc(text: str, domain: str) -> set[str]:
    subs: set[str] = set()
    for line in ANSI_RE.sub("", text).splitlines():
        line = line.strip().lower().rstrip(".")
        if line and not line.startswith(";") and (line == domain or line.endswith("." + domain)):
            subs.add(line)
    return subs


async def thc(http: Http, domain: str, limit: int = 1000) -> set[str]:
    text = await http.get_text(f"https://ip.thc.org/sb/{domain}", params={"l": str(limit)}, retries=1)
    return parse_thc(text, domain)


# --- correo y Gravatar -------------------------------------------------------

def gravatar_md5(email: str) -> str:
    return hashlib.md5(email.strip().lower().encode()).hexdigest()  # noqa: S324 - lo exige Gravatar


async def gravatar_profile(http: Http, email: str) -> dict[str, Any] | None:
    data = await http.get_json(f"https://en.gravatar.com/{gravatar_md5(email)}.json", retries=1)
    entries = (data or {}).get("entry") if isinstance(data, dict) else None
    return entries[0] if entries else None


async def gravatar_exists(http: Http, email: str) -> bool:
    resp = await http.get(f"https://gravatar.com/avatar/{gravatar_md5(email)}", params={"d": "404"}, retries=1)
    return resp.status_code == 200


async def mx_hosts(dns: Dns, domain: str) -> list[tuple[int, str]]:
    try:
        records = await dns.query(domain, "MX")
    except NXDomain:
        return []
    out = []
    for rec in records:
        pref, _, host = rec.partition(" ")
        host = host.strip().rstrip(".").lower()
        if host:
            out.append((int(pref) if pref.isdigit() else 0, host))
    return sorted(out)
