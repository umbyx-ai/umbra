"""Filtraciones: brechas en las que aparece un email y contraseñas expuestas.

- Email: XposedOrNot (gratis, sin clave) y Have I Been Pwned si defines ``HIBP_API_KEY``.
- Contraseña: Pwned Passwords con k-anonimato. Solo se envían los 5 primeros
  caracteres del hash SHA-1: la contraseña nunca sale de tu ordenador.
"""

from __future__ import annotations

import getpass
import hashlib
import os
from urllib.parse import quote

from umbra import ui, web
from umbra.case import Case
from umbra.core.entities import Entity
from umbra.core.entities import EntityType as T
from umbra.core.net import Http


def parse_xon(data: dict | None) -> tuple[list[dict], int]:
    """(brechas, nº de pastes) de la respuesta de breach-analytics de XposedOrNot."""
    if not isinstance(data, dict):
        return [], 0
    breaches = ((data.get("ExposedBreaches") or {}).get("breaches_details")) or []
    pastes = data.get("ExposedPastes") or []
    return breaches, len(pastes) if isinstance(pastes, list) else 0


def pwned_count(range_body: str, suffix: str) -> int:
    for line in range_body.splitlines():
        candidate, _, count = line.strip().partition(":")
        if candidate.upper() == suffix.upper():
            return int(count or 0)
    return 0


async def email_breaches(http: Http, email: str) -> dict:
    errors: list[str] = []
    data = await web.safe(http.get_json("https://api.xposedornot.com/v1/breach-analytics",
                                        params={"email": email}, retries=1), errors, "XposedOrNot")
    breaches, pastes = parse_xon(data)
    hibp = None
    if key := os.environ.get("HIBP_API_KEY"):
        before = len(errors)
        hibp = await web.safe(http.get_json(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email)}",
            params={"truncateResponse": "false"}, headers={"hibp-api-key": key}), errors, "HIBP")
        if hibp is None and len(errors) == before:  # 404 = no aparece en ninguna brecha
            hibp = []
    return {"breaches": breaches, "pastes": pastes, "hibp": hibp, "errors": errors}


def email(case: Case) -> None:
    ui.title("Filtraciones de un email", "¿En qué brechas de datos conocidas aparece? (XposedOrNot / HIBP)")
    entity = Entity.try_of(T.EMAIL, ui.ask("Email"))
    if not entity:
        ui.warn("Email no válido.")
        return
    e = entity.value
    with ui.status("Consultando bases de datos de brechas…"):
        res = web.run(lambda http, _dns: email_breaches(http, e))
    for err in res["errors"]:
        ui.warn(err)
    breaches = sorted(res["breaches"], key=lambda b: str(b.get("xposed_date", "")), reverse=True)
    if breaches:
        ui.table(
            ["Brecha", "Año", "Datos expuestos", "Contraseñas"],
            [(b.get("breach"), b.get("xposed_date"), (b.get("xposed_data") or "").replace(";", ", "),
              b.get("password_risk")) for b in breaches],
            title=f"Aparece en {len(breaches)} brechas",
        )
        ui.warn("Cambia la contraseña de esos servicios y de cualquier otro donde la hayas reutilizado; activa 2FA.")
        ui.note("Si auditas una empresa y aparece un email corporativo, avisa a su propietario.")
    elif not res["errors"]:
        ui.ok("No aparece en las brechas que conoce XposedOrNot.")
    if res["pastes"]:
        ui.warn(f"También aparece en {res['pastes']} pastes públicos.")
    if res["hibp"] is not None:
        ui.table(["Brecha (HIBP)", "Fecha", "Datos"],
                 [(b.get("Title"), b.get("BreachDate"), b.get("DataClasses")) for b in res["hibp"]],
                 title=f"Have I Been Pwned: {len(res['hibp'])}")
    ui.links([
        ("Have I Been Pwned", "https://haveibeenpwned.com/"),
        ("XposedOrNot", f"https://xposedornot.com/xposed#{quote(e)}"),
        ("Intelligence X", "https://intelx.io/"),
    ], title="Comprobar a mano")
    case.log("Filtraciones de un email", e, ui.md_table(
        ["Brecha", "Año", "Datos expuestos"],
        [(b.get("breach"), b.get("xposed_date"), b.get("xposed_data")) for b in breaches],
    ) if breaches else "No aparece en brechas conocidas (XposedOrNot).")


def password(case: Case) -> None:
    ui.title("¿Contraseña filtrada?", "Pwned Passwords con k-anonimato: la contraseña no sale de tu equipo.")
    secret = getpass.getpass("Contraseña (no se muestra al escribir): ")
    if not secret:
        return
    digest = hashlib.sha1(secret.encode("utf-8")).hexdigest().upper()  # noqa: S324 - lo exige la API
    del secret
    prefix, suffix = digest[:5], digest[5:]
    ui.note(f"Se envía solo el prefijo del hash SHA-1: {prefix} (compartido por cientos de contraseñas).")

    async def job(http: Http, _dns):
        return await http.get_text(f"https://api.pwnedpasswords.com/range/{prefix}", headers={"Add-Padding": "true"})

    with ui.status("Consultando Pwned Passwords…"):
        body = web.run(job)
    count = pwned_count(body, suffix)
    if count:
        ui.error(f"Esta contraseña aparece {count:,} veces en filtraciones. No la uses en ningún sitio.".replace(",", "."))
    else:
        ui.ok("No aparece en ninguna filtración conocida (eso no la hace segura si es corta o previsible).")
    case.log("Contraseña filtrada", "(no se guarda)", f"Comprobada una contraseña: aparece {count} veces.")
