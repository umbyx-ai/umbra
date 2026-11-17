"""Bitácora del caso y GAP analysis.

GAP analysis (de la presentación): cuatro preguntas para no perderse en
tangentes durante una investigación.
"""

from __future__ import annotations

from rich.markdown import Markdown

from umbra import ui
from umbra.case import Case

GAP_QUESTIONS = [
    ("¿Qué sé?", "What do I know?"),
    ("¿Qué significa?", "What does this mean?"),
    ("¿Qué necesito saber?", "So, what do I need to know?"),
    ("¿Cómo lo averiguo?", "How do I find out?"),
]


def gap_analysis(case: Case) -> None:
    ui.title("GAP analysis", "Responde a las cuatro preguntas para decidir el siguiente paso.")
    answers = [(es, en, ui.ask(f"{es} [dim]({en})[/]", required=False)) for es, en in GAP_QUESTIONS]
    if not any(a for _, _, a in answers):
        return
    body = "\n".join(f"**{es}** _({en})_\n\n{a or '-'}\n" for es, en, a in answers)
    case.log("GAP analysis", "nota", body)
    ui.ok("Guardado en la bitácora.")


def note(case: Case) -> None:
    text = ui.ask("Nota")
    case.log("Nota", "manual", text)
    ui.ok("Guardada.")


def run(case: Case) -> None:
    ui.title("Bitácora del caso", f"Caso '{case.name}' · {case.entries()} entradas · {case.dir}")
    choice = ui.choose([
        ("1", "Ver la bitácora"),
        ("2", "GAP analysis (las 4 preguntas)"),
        ("3", "Añadir una nota"),
        ("4", "Abrir la carpeta del caso"),
        ("0", "Volver"),
    ])
    match choice:
        case "1":
            ui.console.print(Markdown(case.log_path.read_text(encoding="utf-8")))
        case "2":
            gap_analysis(case)
        case "3":
            note(case)
        case "4":
            ui.open_path(case.dir)
