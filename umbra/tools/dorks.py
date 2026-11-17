"""Google Dorking: constructor guiado, plantillas contra un dominio y chuleta de operadores.

Umbra no automatiza las búsquedas en Google (va contra sus condiciones y acaba en
CAPTCHA): construye el dork y lo abre en tu navegador, que es como se hace en clase.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import quote_plus

from umbra import ui
from umbra.case import Case
from umbra.core.entities import Entity
from umbra.core.entities import EntityType as T

ENGINES = {
    "Google": "https://www.google.com/search?q=",
    "Bing": "https://www.bing.com/search?q=",
    "DuckDuckGo": "https://duckduckgo.com/?q=",
}

OPERATORS = [
    ("site:", "Solo resultados de un dominio", "site:example.com"),
    ("filetype: / ext:", "Tipo de fichero", "filetype:pdf"),
    ("inurl:", "Palabra en la URL", "inurl:admin"),
    ("intitle:", "Palabra en el título de la página", 'intitle:"index of"'),
    ("intext:", "Palabra en el texto", 'intext:"contraseña"'),
    ('"..."', "Frase exacta", '"curriculum vitae"'),
    ("OR  |", "Una cosa u otra", "pdf | docx"),
    ("AND", "Todas (Google lo hace por defecto)", "dni AND granollers"),
    ("-", "Excluye un término u operador", "-site:www.example.com"),
    ("*", "Comodín: cualquier palabra", '"técnico * sistemas"'),
    ("( )", "Agrupa para dar prioridad", "(ext:sql | ext:bak)"),
    ("before: / after:", "Filtra por fecha", "after:2024-01-01"),
]


def search_links(query: str) -> list[tuple[str, str]]:
    return [(name, base + quote_plus(query)) for name, base in ENGINES.items()]


def _quote(value: str) -> str:
    value = value.strip()
    return f'"{value}"' if " " in value and not value.startswith('"') else value


@dataclass
class DorkParts:
    terms: str = ""
    phrase: str = ""
    site: str = ""
    filetypes: list[str] = field(default_factory=list)
    inurl: str = ""
    intitle: str = ""
    intext: str = ""
    exclude: list[str] = field(default_factory=list)
    after: str = ""
    before: str = ""


def build_dork(p: DorkParts) -> str:
    tokens: list[str] = []
    if p.site:
        tokens.append(f"site:{p.site.strip()}")
    types = [t.strip().lstrip(".") for t in p.filetypes if t.strip()]
    if len(types) == 1:
        tokens.append(f"filetype:{types[0]}")
    elif types:
        tokens.append("(" + " | ".join(f"filetype:{t}" for t in types) + ")")
    for op, value in (("inurl", p.inurl), ("intitle", p.intitle), ("intext", p.intext)):
        if value.strip():
            tokens.append(f"{op}:{_quote(value)}")
    if p.phrase.strip():
        tokens.append(f'"{p.phrase.strip().strip(chr(34))}"')
    if p.terms.strip():
        tokens.append(p.terms.strip())
    tokens += [f"-{_quote(x)}" for x in p.exclude if x.strip()]
    if p.after.strip():
        tokens.append(f"after:{p.after.strip()}")
    if p.before.strip():
        tokens.append(f"before:{p.before.strip()}")
    return " ".join(tokens)


def domain_templates(domain: str, company: str = "") -> list[tuple[str, str, str]]:
    """(categoría, para qué sirve, dork) contra un dominio objetivo."""
    d = domain
    org = company or d.split(".")[0]
    return [
        ("Documentos", "Documentos ofimáticos publicados (metadatos)",
         f"site:{d} (filetype:pdf | filetype:docx | filetype:doc | filetype:xlsx | filetype:pptx)"),
        ("Ficheros sensibles", "Configuración, copias, bases de datos y logs",
         f"site:{d} (ext:env | ext:sql | ext:bak | ext:log | ext:conf | ext:ini | ext:old)"),
        ("Listado de directorios", "Servidores con el índice abierto", f'site:{d} intitle:"index of"'),
        ("Paneles de acceso", "Logins y administración",
         f"site:{d} (inurl:login | inurl:admin | inurl:signin | intitle:login | intitle:acceso)"),
        ("Errores", "Mensajes de error que revelan tecnología o rutas",
         f'site:{d} (intext:"sql syntax" | intext:"Warning: mysql" | intext:"stack trace" | intext:"Fatal error")'),
        ("Subdominios", "Subdominios indexados (sin www)", f"site:*.{d} -site:www.{d}"),
        ("Correos", "Direcciones del dominio publicadas fuera de su web", f'"@{d}" -site:{d}'),
        ("Código y pastes", "Menciones en repositorios y pastes",
         f'"{d}" (site:github.com | site:gitlab.com | site:pastebin.com)'),
        ("Nube", "Documentos y tableros compartidos en abierto",
         f'"{d}" (site:docs.google.com | site:drive.google.com | site:trello.com | site:s3.amazonaws.com)'),
        ("Personas", "Empleados con perfil en LinkedIn", f'site:linkedin.com/in "{org}"'),
    ]


# --- interacción -------------------------------------------------------------

def _show_and_log(case: Case, query: str, label: str = "Dork") -> None:
    ui.console.print()
    ui.kv([("Dork", query)])
    console_links = search_links(query)
    ui.links(console_links, title="Buscar en")
    case.log("Google Dorking", label, f"```\n{query}\n```\n\n{ui.md_links(console_links)}")


def _builder(case: Case) -> None:
    ui.title("Constructor guiado", "Deja en blanco lo que no quieras usar.")
    parts = DorkParts(
        site=ui.ask("site: (dominio)", required=False),
        filetypes=[x for x in ui.ask("filetype: (p. ej. pdf,docx)", required=False).split(",") if x],
        inurl=ui.ask("inurl:", required=False),
        intitle=ui.ask("intitle:", required=False),
        intext=ui.ask("intext:", required=False),
        phrase=ui.ask("Frase exacta", required=False),
        terms=ui.ask("Otros términos (OR, *, paréntesis...)", required=False),
        exclude=[x for x in ui.ask("Excluir (separado por comas)", required=False).split(",") if x],
        after=ui.ask("after: (AAAA-MM-DD)", required=False),
        before=ui.ask("before: (AAAA-MM-DD)", required=False),
    )
    query = build_dork(parts)
    if not query:
        ui.warn("No has puesto nada.")
        return
    _show_and_log(case, query, "constructor")


def _templates(case: Case) -> None:
    ui.title("Plantillas contra un dominio", "Reconocimiento de lo que un buscador ya ha indexado del objetivo.")
    domain = Entity.try_of(T.DOMAIN, ui.ask("Dominio objetivo"))
    if not domain:
        ui.warn("Dominio no válido.")
        return
    company = ui.ask("Nombre de la organización (para LinkedIn)", default=domain.value.split(".")[0])
    templates = domain_templates(domain.value, company)
    ui.table(["#", "Categoría", "Para qué", "Dork"], [(i, c, d, q) for i, (c, d, q) in enumerate(templates, 1)])
    items = [(f"{c} (Google)", ENGINES["Google"] + quote_plus(q)) for c, _, q in templates]
    ui.links(items, title="Abrir en Google")
    body = ui.md_table(["Categoría", "Dork"], [(c, f"`{q}`") for c, _, q in templates])
    case.log("Google Dorking", domain.value, body)


def _free(case: Case) -> None:
    ui.title("Dork libre", 'Ejemplo de clase: filetype:pdf "curriculum vitae" dni granollers')
    _show_and_log(case, ui.ask("Dork"), "dork libre")


def _cheatsheet() -> None:
    ui.title("Operadores de búsqueda")
    ui.table(["Operador", "Qué hace", "Ejemplo"], OPERATORS)
    ui.links([
        ("Google Hacking Database (Exploit-DB)", "https://www.exploit-db.com/google-hacking-database"),
        ("Metodología avanzada de dorks (lostsec)", "https://lostsec.xyz/"),
        ("INCIBE: Google Dorks para encontrar información sobre ti",
         "https://www.incibe.es/ciudadania/blog/google-dorks-te-ayuda-encontrar-informacion-sobre-ti-en-la-red"),
    ], title="Recursos")


def run(case: Case) -> None:
    ui.title("Google Dorking", "Operadores avanzados para encontrar lo que ya está indexado.")
    choice = ui.choose([
        ("1", "Constructor guiado"),
        ("2", "Plantillas contra un dominio (documentos, logins, ficheros sensibles...)"),
        ("3", "Dork libre"),
        ("4", "Chuleta de operadores y recursos (GHDB)"),
        ("0", "Volver"),
    ])
    match choice:
        case "1":
            _builder(case)
        case "2":
            _templates(case)
        case "3":
            _free(case)
        case "4":
            _cheatsheet()
