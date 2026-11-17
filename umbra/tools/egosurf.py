"""Egosurfing: busca tu propia huella digital y configura alertas (práctica de Google Alerts).

Sirve para auditar qué se sabe de ti (o de tu empresa, con su permiso): tu
nombre en documentos, tu email o teléfono publicados, tu DNI en boletines o
currículums... Es la versión responsable de la práctica del DNI en CVs.
"""

from __future__ import annotations

import re
from urllib.parse import quote_plus

from umbra import ui
from umbra.case import Case

GOOGLE = "https://www.google.com/search?q="


def phone_variants(phone: str) -> list[str]:
    digits = re.sub(r"\D", "", phone)
    if digits.startswith("34") and len(digits) == 11:
        digits = digits[2:]
    if len(digits) != 9:
        return [phone.strip()] if phone.strip() else []
    return [digits, f"{digits[:3]} {digits[3:5]} {digits[5:7]} {digits[7:]}", f"{digits[:3]} {digits[3:6]} {digits[6:]}",
            f"+34 {digits}"]


def ego_dorks(name: str = "", alias: str = "", email: str = "", phone: str = "", dni: str = "",
              city: str = "") -> list[tuple[str, str]]:
    """(qué buscas, dork)."""
    dorks: list[tuple[str, str]] = []
    if name:
        q = f'"{name}"'
        dorks += [
            ("Tu nombre", q),
            ("Tu nombre en documentos", f"{q} (filetype:pdf | filetype:docx | filetype:xlsx)"),
            ("Tu currículum publicado", f'{q} "curriculum vitae" filetype:pdf'),
            ("Tu nombre en redes", f"{q} (site:linkedin.com | site:instagram.com | site:facebook.com | site:x.com | site:tiktok.com)"),
            ("Boletines oficiales (BOE, DOGC, BOP)", f"{q} (site:boe.es | site:dogc.gencat.cat | inurl:bop)"),
        ]
        if city:
            dorks.append(("Tu nombre y tu ciudad", f'{q} "{city}"'))
    if alias:
        dorks += [("Tu alias", f'"{alias}"'), ("Tu alias en URLs de perfiles", f"inurl:{alias}")]
    if email:
        dorks += [("Tu email", f'"{email}"'), ("Tu email en pastes y código", f'"{email}" (site:pastebin.com | site:github.com)')]
    for variant in phone_variants(phone):
        dorks.append((f"Tu teléfono ({variant})", f'"{variant}"'))
    if dni:
        number = re.sub(r"[^0-9]", "", dni)
        dorks += [("Tu DNI", f'"{dni}" | "{number}"'), ("Tu DNI en PDFs", f'("{dni}" | "{number}") filetype:pdf')]
    return dorks


def run(case: Case) -> None:
    ui.title("Egosurfing", "Qué hay publicado sobre ti. Rellena solo lo que quieras buscar.")
    ui.note("Pensado para auditar TU huella (o la de quien te lo pida). Buscar datos de otros sin permiso es doxing.")
    data = {
        "name": ui.ask("Nombre y apellidos", required=False),
        "alias": ui.ask("Alias / nombre de usuario", required=False),
        "email": ui.ask("Email", required=False),
        "phone": ui.ask("Teléfono", required=False),
        "dni": ui.ask("DNI / NIE", required=False),
        "city": ui.ask("Ciudad", required=False),
    }
    dorks = ego_dorks(**data)
    if not dorks:
        ui.warn("No has rellenado nada.")
        return
    ui.table(["#", "Qué buscas", "Dork"], [(i, label, q) for i, (label, q) in enumerate(dorks, 1)])
    ui.links([(label, GOOGLE + quote_plus(q)) for label, q in dorks], title="Buscar en Google")
    alerts = [label for label, _ in dorks if not label.startswith("Tu DNI")][:4]
    ui.info("Crea alertas para enterarte cuando aparezca algo nuevo. Sugerencias: " + "; ".join(alerts))
    ui.links([
        ("Google Alerts", "https://www.google.es/alerts"),
        ("Resultados sobre ti (Google)", "https://myactivity.google.com/results-about-you"),
        ("INCIBE: egosurfing en la empresa", "https://www.incibe.es/empresas/blog/el-egosurfing-y-practicarlo-mi-empresa"),
        ("AEPD: derecho de supresión", "https://www.aepd.es/derechos-y-deberes/conoce-tus-derechos/derecho-de-supresion-al-olvido"),
    ], title="Alertas y qué hacer si encuentras algo")
    dni = data["dni"]
    masked = [(label, q.replace(dni, "********").replace(re.sub(r"[^0-9]", "", dni) or "\0", "********") if dni else q)
              for label, q in dorks]
    case.log("Egosurfing", data["name"] or data["alias"] or "huella propia",
             ui.md_table(["Qué buscas", "Dork"], [(label, f"`{q}`") for label, q in masked]))
