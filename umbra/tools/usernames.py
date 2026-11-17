"""Nombre de usuario en redes y plataformas (práctica "find social media from mail or username").

Comprueba si existe un perfil público con ese alias en varias plataformas que se
pueden consultar sin cuenta. Las grandes redes (Instagram, TikTok, X, LinkedIn...)
bloquean estas comprobaciones: para ellas se generan los enlaces y se mira a mano.
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass

from umbra import ui, web
from umbra.case import Case
from umbra.core.net import Http


@dataclass(frozen=True)
class Site:
    name: str
    category: str
    profile: str                     # URL pública del perfil
    probe: str = ""                  # URL que se comprueba (si no, la del perfil)
    method: str = "status"           # status | missing_text | present_text | json_list | json_null
    text: str = ""                   # texto para missing_text / present_text
    missing: tuple[int, ...] = (404, 410)  # códigos que significan "no existe"

    def url(self, user: str) -> str:
        return self.profile.format(u=user)

    def probe_url(self, user: str) -> str:
        return (self.probe or self.profile).format(u=user)


SITES: list[Site] = [
    Site("GitHub", "código", "https://github.com/{u}", "https://api.github.com/users/{u}"),
    Site("GitLab", "código", "https://gitlab.com/{u}", "https://gitlab.com/api/v4/users?username={u}", "json_list"),
    Site("Codeberg", "código", "https://codeberg.org/{u}", "https://codeberg.org/api/v1/users/{u}"),
    Site("Docker Hub", "código", "https://hub.docker.com/u/{u}", "https://hub.docker.com/v2/users/{u}/"),
    Site("Dev.to", "código", "https://dev.to/{u}", "https://dev.to/api/users/by_username?url={u}"),
    Site("Hacker News", "foros", "https://news.ycombinator.com/user?id={u}",
         "https://hacker-news.firebaseio.com/v0/user/{u}.json", "json_null"),
    Site("Keybase", "identidad", "https://keybase.io/{u}",
         "https://keybase.io/_/api/1.0/user/lookup.json?usernames={u}", "present_text", '"basics"'),
    Site("Gravatar", "identidad", "https://gravatar.com/{u}", "https://en.gravatar.com/{u}.json"),
    Site("Mastodon (mastodon.social)", "redes", "https://mastodon.social/@{u}",
         "https://mastodon.social/api/v1/accounts/lookup?acct={u}"),
    Site("Bluesky", "redes", "https://bsky.app/profile/{u}.bsky.social",
         "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={u}.bsky.social", missing=(400, 404)),
    Site("Telegram", "redes", "https://t.me/{u}", method="present_text", text="tgme_page_title"),
    Site("Steam", "juegos", "https://steamcommunity.com/id/{u}", method="missing_text",
         text="The specified profile could not be found"),
    Site("Chess.com", "juegos", "https://www.chess.com/member/{u}", "https://api.chess.com/pub/player/{u}"),
    Site("Lichess", "juegos", "https://lichess.org/@/{u}", "https://lichess.org/api/user/{u}"),
    Site("Duolingo", "otros", "https://www.duolingo.com/profile/{u}",
         "https://www.duolingo.com/2017-06-30/users?username={u}&fields=users", "present_text", '"users":[{'),
    Site("SoundCloud", "música", "https://soundcloud.com/{u}"),
    Site("Vimeo", "vídeo", "https://vimeo.com/{u}"),
]

MANUAL: list[tuple[str, str]] = [
    ("Instagram", "https://www.instagram.com/{u}/"),
    ("TikTok", "https://www.tiktok.com/@{u}"),
    ("X / Twitter", "https://x.com/{u}"),
    ("Facebook", "https://www.facebook.com/{u}"),
    ("Threads", "https://www.threads.net/@{u}"),
    ("YouTube", "https://www.youtube.com/@{u}"),
    ("Twitch", "https://www.twitch.tv/{u}"),
    ("Pinterest", "https://www.pinterest.com/{u}/"),
    ("Snapchat", "https://www.snapchat.com/add/{u}"),
    ("Reddit", "https://www.reddit.com/user/{u}"),
    ("Linktree", "https://linktr.ee/{u}"),
    ("LinkedIn (búsqueda)", 'https://www.google.com/search?q=site%3Alinkedin.com%2Fin+%22{u}%22'),
]
OTHER_TOOLS = [
    ("user-scanner (Python)", "https://github.com/kaifcodec/user-scanner"),
    ("Sherlock", "https://github.com/sherlock-project/sherlock"),
    ("WhatsMyName", "https://whatsmyname.app/"),
]

USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{2,40}$")


def evaluate(site: Site, status: int, body: str) -> bool | None:
    """True = existe, False = no existe, None = no se puede saber (bloqueo, error...)."""
    if status in (403, 429, 503) or status >= 500:
        return None
    if status in site.missing:
        return False
    match site.method:
        case "status":
            return True if status == 200 else None
        case "missing_text":
            return None if status != 200 else site.text not in body
        case "present_text":
            return site.text in body if status == 200 else None
        case "json_list":
            try:
                return bool(json.loads(body)) if status == 200 else None
            except ValueError:
                return None
        case "json_null":
            return None if status != 200 else body.strip() not in ("null", "")
    return None


async def check_all(http: Http, user: str) -> list[tuple[Site, bool | None, str]]:
    async def one(site: Site) -> tuple[Site, bool | None, str]:
        try:
            resp = await http.get(site.probe_url(user), retries=0, timeout=15)
        except Exception as exc:  # noqa: BLE001
            return site, None, exc.__class__.__name__
        return site, evaluate(site, resp.status_code, resp.text), f"HTTP {resp.status_code}"

    return list(await asyncio.gather(*(one(s) for s in SITES)))


def run(case: Case) -> None:
    ui.title("Nombre de usuario en redes", f"Comprueba un alias en {len(SITES)} plataformas y prepara enlaces para el resto.")
    raw = ui.ask("Nombre de usuario (o un email: uso la parte antes de la @)")
    user = raw.split("@", 1)[0].lstrip("@").strip() if "@" in raw.lstrip("@") else raw.lstrip("@").strip()
    if not USERNAME_RE.match(user):
        ui.warn("Ese alias tiene caracteres raros; las plataformas solo admiten letras, números, punto, guion y guion bajo.")
        return
    with ui.status(f"Buscando '{user}' en {len(SITES)} plataformas…"):
        results = web.run(lambda http, _dns: check_all(http, user), timeout=15)

    found = [(s, d) for s, ok, d in results if ok]
    unknown = [(s, d) for s, ok, d in results if ok is None]
    ui.table(
        ["Plataforma", "Categoría", "Perfil"],
        [(s.name, s.category, s.url(user)) for s, _ in found],
        title=f"Encontrado en {len(found)} de {len(SITES)}",
    )
    if unknown:
        ui.note("No se ha podido comprobar: " + ", ".join(f"{s.name} ({d})" for s, d in unknown))
    ui.note("Que exista el alias no significa que sea la misma persona: contrasta foto, bio y enlaces entre perfiles.")
    if found:
        ui.links([(s.name, s.url(user)) for s, _ in found], title="Abrir perfiles encontrados")
    manual = [(name, url.format(u=user)) for name, url in MANUAL]
    ui.links(manual, title="Compruébalo a mano (bloquean las consultas automáticas)")
    ui.links(OTHER_TOOLS, title="Otras herramientas de la presentación", offer_open=False)
    case.log("Nombre de usuario", user, "\n\n".join([
        ui.md_table(["Plataforma", "Perfil"], [(s.name, s.url(user)) for s, _ in found]) if found else "_Sin resultados._",
        "No comprobables: " + (", ".join(s.name for s, _ in unknown) or "-"),
        "**A mano:**\n\n" + ui.md_links(manual),
    ]))
