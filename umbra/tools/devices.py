"""Buscadores de dispositivos conectados: Shodan, Censys, FOFA, ZoomEye, Netlas, LeakIX...

- Plantillas de la práctica de impresoras y otros dorks de Shodan clásicos.
- Constructor de consultas con filtros.
- Consulta de una IP sin escanearla (Shodan InternetDB, gratis y sin cuenta).
- Si defines ``SHODAN_API_KEY``, también busca por API.
"""

from __future__ import annotations

import base64
import os
from urllib.parse import quote, quote_plus

from umbra import ui, web
from umbra.case import Case
from umbra.core.entities import Entity
from umbra.core.entities import EntityType as T
from umbra.core.known import RISKY_PORTS

TEMPLATES: list[tuple[str, list[tuple[str, str]]]] = [
    ("Impresoras (práctica de clase)", [
        ("Epson", "Server: EPSON"),
        ("HP: página de estado", '"/general/status.html"'),
        ("HP OfficeJet", 'product:"officejet"'),
        ("HP LaserJet", "hp laserjet"),
        ("Canon", 'product:"Canon printer web interface"'),
        ("Ricoh", 'title:"ricoh myprint"'),
        ("Brother", "title:brother"),
    ]),
    ("Cámaras y vídeo", [
        ("Cámaras Hikvision", 'product:"Hikvision IP Camera"'),
        ("Webcams con captura", "webcam has_screenshot:true"),
    ]),
    ("Servicios expuestos", [
        ("Escritorio remoto (RDP) en España", "port:3389 country:ES"),
        ("MongoDB sin autenticación", '"MongoDB Server Information" port:27017 -authentication'),
        ("Elasticsearch abierto", "port:9200 product:Elastic"),
        ("FTP anónimo", '"230 Login successful" port:21'),
        ("Listados de directorios", 'http.title:"Index of /"'),
        ("VNC sin autenticación", '"authentication disabled" "RFB 003.008"'),
    ]),
    ("Industrial / IoT", [
        ("Modbus (SCADA)", "port:502"),
        ("Siemens S7", "port:102 product:Siemens"),
    ]),
]

FILTERS = [
    ("product", "Producto (p. ej. Apache, nginx, OpenSSH)"),
    ("port", "Puerto"),
    ("country", "País (código: ES, FR...)"),
    ("city", "Ciudad"),
    ("org", "Organización / ISP"),
    ("net", "Rango de red (CIDR)"),
    ("hostname", "Nombre de host o dominio"),
    ("http.title", "Título de la web"),
    ("ssl.cert.subject.cn", "CN del certificado TLS"),
]


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def shodan_link(query: str) -> str:
    return "https://www.shodan.io/search?query=" + quote_plus(query)


def engine_links(query: str) -> list[tuple[str, str]]:
    """Mismo texto en varios motores (los filtros tienen sintaxis distinta en cada uno)."""
    return [
        ("Shodan", shodan_link(query)),
        ("Censys", "https://search.censys.io/search?resource=hosts&q=" + quote_plus(query)),
        ("FOFA", "https://en.fofa.info/result?qbase64=" + quote(_b64(query))),
        ("ZoomEye", "https://www.zoomeye.ai/searchResult?q=" + quote(_b64(query))),
        ("Netlas", "https://app.netlas.io/responses/?q=" + quote_plus(query)),
        ("LeakIX", "https://leakix.net/search?scope=service&q=" + quote_plus(query)),
    ]


def ip_links(ip: str) -> list[tuple[str, str]]:
    return [
        ("Shodan", f"https://www.shodan.io/host/{ip}"),
        ("Censys", f"https://search.censys.io/hosts/{ip}"),
        ("GreyNoise", f"https://viz.greynoise.io/ip/{ip}"),
        ("Netlas", f"https://app.netlas.io/host/{ip}/"),
        ("LeakIX", f"https://leakix.net/host/{ip}"),
    ]


def build_query(text: str, filters: dict[str, str]) -> str:
    parts = [text.strip()] if text.strip() else []
    for key, value in filters.items():
        value = value.strip()
        if value:
            parts.append(f'{key}:"{value}"' if " " in value else f"{key}:{value}")
    return " ".join(parts)


def _api_search(query: str) -> None:
    key = os.environ.get("SHODAN_API_KEY")
    if not key or not ui.confirm("Tienes SHODAN_API_KEY: ¿buscar también por API?", default=False):
        return

    async def job(http, _dns):
        return await http.get_json(
            "https://api.shodan.io/shodan/host/search",
            params={"key": key, "query": query, "minify": "true"},
            missing=(),
        )

    with ui.status("Consultando la API de Shodan…"):
        try:
            data = web.run(job)
        except Exception as exc:  # noqa: BLE001
            ui.error(f"Shodan: {exc}. Las cuentas gratuitas no permiten buscar con filtros por API.")
            return
    matches = (data or {}).get("matches") or []
    ui.ok(f"{(data or {}).get('total', 0)} resultados en total (muestro {min(len(matches), 25)}).")
    ui.table(
        ["IP", "Puerto", "Organización", "País", "Producto", "Hostnames"],
        [
            (m.get("ip_str"), m.get("port"), m.get("org"), (m.get("location") or {}).get("country_code"),
             m.get("product"), m.get("hostnames"))
            for m in matches[:25]
        ],
    )


def _templates(case: Case) -> None:
    ui.title("Plantillas de Shodan")
    flat: list[tuple[str, str, str]] = [(group, label, q) for group, items in TEMPLATES for label, q in items]
    ui.table(["#", "Grupo", "Qué busca", "Consulta"], [(i, g, l, q) for i, (g, l, q) in enumerate(flat, 1)])
    ui.note("Para usar filtros en shodan.io tienes que iniciar sesión (la cuenta gratuita basta).")
    items = [(f"{l} (Shodan)", shodan_link(q)) for _, l, q in flat]
    ui.links(items, title="Abrir en Shodan")
    ui.warn("Mirar no es entrar: no accedas a interfaces ajenas ni pruebes contraseñas por defecto.")
    case.log("Buscadores de dispositivos", "plantillas", ui.md_table(["Qué busca", "Consulta"], [(l, f"`{q}`") for _, l, q in flat]))


def _builder(case: Case) -> None:
    ui.title("Constructor de consultas", "Deja en blanco los filtros que no quieras usar.")
    text = ui.ask("Texto libre", required=False)
    filters = {key: ui.ask(f"{key}: {desc}", required=False) for key, desc in FILTERS}
    query = build_query(text, filters)
    if not query:
        ui.warn("No has puesto nada.")
        return
    ui.kv([("Consulta", query)])
    ui.note("Shodan entiende los filtros tal cual; en los demás motores la sintaxis cambia un poco.")
    items = engine_links(query)
    ui.links(items, title="Buscar en")
    _api_search(query)
    case.log("Buscadores de dispositivos", query, ui.md_links(items))


def _ip_lookup(case: Case) -> None:
    ui.title("Consultar una IP", "Datos de Shodan InternetDB: no se envía ni un paquete a la IP.")
    ip = Entity.try_of(T.IP, ui.ask("IP"))
    if not ip:
        ui.warn("IP no válida.")
        return

    async def job(http, _dns):
        return await http.get_json(f"https://internetdb.shodan.io/{ip.value}")

    with ui.status("Consultando InternetDB…"):
        data = web.run(job)
    if not data:
        ui.info("Shodan no tiene datos de esa IP.")
        data = {}
    ports = sorted(data.get("ports") or [])
    risky = [f"{p} ({RISKY_PORTS[p]})" for p in ports if p in RISKY_PORTS]
    pairs = [
        ("Puertos", ports),
        ("Servicios sensibles", risky),
        ("Hostnames", data.get("hostnames")),
        ("Software (CPE)", data.get("cpes")),
        ("Etiquetas", data.get("tags")),
        ("CVE potenciales", (data.get("vulns") or [])[:30]),
    ]
    ui.kv(pairs)
    if risky:
        ui.warn("Hay servicios que no deberían estar expuestos a Internet.")
    items = ip_links(ip.value)
    ui.links(items, title="Ver en otros motores")
    body = ui.md_table(["Campo", "Valor"], pairs) + "\n\n" + ui.md_links(items)
    case.log("Buscadores de dispositivos", ip.value, body)


def run(case: Case) -> None:
    ui.title("Buscadores de dispositivos", "Shodan, Censys, FOFA, ZoomEye, Netlas, LeakIX, GreyNoise.")
    choice = ui.choose([
        ("1", "Plantillas (impresoras, cámaras, servicios expuestos...)"),
        ("2", "Constructor de consultas con filtros"),
        ("3", "Consultar una IP (puertos y CVE sin escanear)"),
        ("0", "Volver"),
    ])
    match choice:
        case "1":
            _templates(case)
        case "2":
            _builder(case)
        case "3":
            _ip_lookup(case)
