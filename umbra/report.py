"""Generación de informes (Markdown y JSON) a partir de un caso."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from typing import Any

from umbra.core.entities import Severity
from umbra.core.scope import Scope
from umbra.core.storage import Store

SEVERITY_LABEL = {
    Severity.HIGH: "ALTO",
    Severity.MEDIUM: "MEDIO",
    Severity.LOW: "BAJO",
    Severity.INFO: "INFO",
}


def build_json(store: Store) -> dict[str, Any]:
    return {
        "meta": store.meta(),
        "entities": store.entities(),
        "relations": store.relations(),
        "findings": store.findings(),
        "errors": store.errors(),
    }


def _value(key: str) -> str:
    return key.partition(":")[2]


def _fmt(value: Any, limit: int = 25) -> str:
    if isinstance(value, bool):
        return "sí" if value else "no"
    if isinstance(value, list):
        items = [str(v) for v in value]
        text = ", ".join(items[:limit])
        if len(items) > limit:
            text += f" … (+{len(items) - limit})"
        return text or "-"
    if isinstance(value, dict):
        return "; ".join(f"{k}: {v}" for k, v in value.items()) or "-"
    return str(value)


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ") or "-"


def build_markdown(store: Store) -> str:
    meta = store.meta()
    scope = Scope(json.loads(meta.get("scope", "[]")))
    entities = store.entities()
    relations = store.relations()
    findings = store.findings()
    errors = store.errors()

    out: list[str] = []
    w = out.append

    w(f"# Informe OSINT · {meta.get('seed', '?')}")
    w("")
    w(f"- **Caso:** `{meta.get('case', '?')}` · Umbra {meta.get('version', '')}")
    w(f"- **Ejecución:** {meta.get('started', '?')} → {meta.get('finished', '(sin terminar)')}")
    w(f"- **Alcance:** {', '.join(sorted(scope.roots)) or '(sin dominios raíz)'} · profundidad {meta.get('depth', '?')}")
    w(f"- **Módulos:** {meta.get('modules', '?')}")
    w("")

    # --- resumen -------------------------------------------------------------
    w("## Resumen")
    w("")
    by_type = Counter(e["type"] for e in entities)
    by_severity = Counter(f["severity"] for f in findings)
    w("| Entidades | Total |  | Hallazgos | Total |")
    w("|---|---:|---|---|---:|")
    types = by_type.most_common()
    severities = [(SEVERITY_LABEL[s], by_severity.get(s.value, 0)) for s in reversed(Severity)]
    for i in range(max(len(types), len(severities))):
        t = types[i] if i < len(types) else ("", "")
        s = severities[i] if i < len(severities) else ("", "")
        w(f"| {t[0]} | {t[1]} |  | {s[0]} | {s[1]} |")
    w("")

    # --- hallazgos relevantes ------------------------------------------------
    relevant = [f for f in findings if f["severity"] != Severity.INFO]
    w(f"## Hallazgos relevantes ({len(relevant)})")
    w("")
    if not relevant:
        w("_Nada por encima de nivel informativo._")
        w("")
    for f in relevant:
        w(f"### [{SEVERITY_LABEL[Severity(f['severity'])]}] {f['title']}")
        w("")
        w(f"`{_value(f['entity'])}` · módulo `{f['module']}`")
        w("")
        for key, value in f["data"].items():
            w(f"- **{key}:** {_fmt(value)}")
        w("")

    # --- dominios del objetivo -----------------------------------------------
    targets: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    for r in relations:
        targets[r["source"]][r["label"]].append(_value(r["target"]))

    domains = [e for e in entities if e["type"] == "domain"]
    own = [e for e in domains if scope.contains(e["value"])]
    third = [e for e in domains if not scope.contains(e["value"])]

    w(f"## Dominios del objetivo ({len(own)})")
    w("")
    if own:
        w("| Dominio | IPs | CNAME |")
        w("|---|---|---|")
        for e in own:
            rel = targets.get(e["key"], {})
            w(f"| {_cell(e['value'])} | {_cell(_fmt(rel.get('resolves_to', []), 6))} | {_cell(_fmt(rel.get('cname', [])))} |")
        w("")

    # --- IPs -----------------------------------------------------------------
    ports = {
        f["entity"]: f["data"].get("puertos", [])
        for f in findings
        if f["module"] == "internetdb" and "puertos" in f["data"]
    }
    ips = [e for e in entities if e["type"] == "ip"]
    w(f"## Direcciones IP ({len(ips)})")
    w("")
    if ips:
        w("| IP | ASN | Organización | Puertos (Shodan) |")
        w("|---|---|---|---|")
        for e in ips:
            asns = targets.get(e["key"], {}).get("announced_by", [])
            orgs = [o for a in asns for o in targets.get(f"asn:{a}", {}).get("operated_by", [])]
            w(f"| {_cell(e['value'])} | {_cell(_fmt(asns))} | {_cell(_fmt(orgs))} | {_cell(_fmt(ports.get(e['key'], [])))} |")
        w("")

    # --- terceros ------------------------------------------------------------
    incoming: dict[str, set[str]] = defaultdict(set)
    for r in relations:
        incoming[r["target"]].add(r["label"])
    w(f"## Infraestructura de terceros ({len(third)})")
    w("")
    w("_Dominios fuera del alcance: se registran pero no se investigan._")
    w("")
    for e in third:
        w(f"- `{e['value']}` ({', '.join(sorted(incoming.get(e['key'], set()))) or '-'})")
    w("")

    others = [e for e in entities if e["type"] not in ("domain", "ip")]
    if others:
        w("## Otras entidades")
        w("")
        for e in others:
            w(f"- **{e['type']}** · {e['value']}")
        w("")

    # --- información ---------------------------------------------------------
    info = [f for f in findings if f["severity"] == Severity.INFO]
    w(f"## Información ({len(info)})")
    w("")
    for f in info:
        details = "; ".join(f"{k}: {_fmt(v, 10)}" for k, v in f["data"].items())
        w(f"- `{_value(f['entity'])}` · **{f['title']}**" + (f" · {details}" if details else ""))
    w("")

    if errors:
        w(f"## Errores de módulos ({len(errors)})")
        w("")
        for e in errors:
            w(f"- `{e['module']}` sobre `{_value(e['entity'])}`: {e['message']}")
        w("")

    return "\n".join(out)
