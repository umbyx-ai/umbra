"""Casos de investigación.

Un caso es una carpeta en ``cases/<nombre>/`` con:

- ``bitacora.md``: todo lo que haces desde el menú, con fecha y hora (tu informe).
- los ficheros que generan las herramientas (listas de subdominios, ELA, recon...).
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

DEFAULT_CASES_DIR = Path("cases")


def case_slug(name: str) -> str:
    """Nombre seguro para ficheros y carpetas (sin rutas ni caracteres raros)."""
    slug = re.sub(r"[^a-z0-9._-]+", "_", name.lower()).strip("._-")
    return slug[:80] or "caso"


class Case:
    def __init__(self, name: str, base: Path | None = None) -> None:
        self.name = case_slug(name)
        self.dir = Path(base or DEFAULT_CASES_DIR) / self.name
        self.dir.mkdir(parents=True, exist_ok=True)
        self.log_path = self.dir / "bitacora.md"
        if not self.log_path.exists():
            self.log_path.write_text(
                f"# Bitácora del caso `{self.name}`\n\n"
                f"_Creado el {datetime.now():%d/%m/%Y a las %H:%M}._\n\n",
                encoding="utf-8",
            )

    def log(self, tool: str, target: str, body: str) -> None:
        """Añade una entrada a la bitácora."""
        entry = f"## {datetime.now():%d/%m/%Y %H:%M} · {tool} · `{target}`\n\n{body.strip()}\n\n"
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(entry)

    def file(self, name: str) -> Path:
        """Ruta segura dentro de la carpeta del caso."""
        stem, dot, ext = name.rpartition(".")
        safe = f"{case_slug(stem)}.{case_slug(ext)}" if dot else case_slug(name)
        return self.dir / safe

    def save(self, name: str, content: str) -> Path:
        path = self.file(name)
        path.write_text(content, encoding="utf-8")
        return path

    def text_files(self) -> list[Path]:
        return sorted(p for p in self.dir.glob("*.txt"))

    def entries(self) -> int:
        return self.log_path.read_text(encoding="utf-8").count("\n## ")

    @staticmethod
    def existing(base: Path | None = None) -> list[str]:
        base = Path(base or DEFAULT_CASES_DIR)
        if not base.is_dir():
            return []
        return sorted(p.name for p in base.iterdir() if (p / "bitacora.md").exists())
