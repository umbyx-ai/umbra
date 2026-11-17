"""Persistencia de un caso en SQLite (un fichero .db por investigación).

Volver a ejecutar un caso no borra nada: actualiza lo que ya había y añade lo nuevo.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from umbra.core.entities import Entity, Finding, Relation, Severity

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS entities (
    key        TEXT PRIMARY KEY,
    type       TEXT NOT NULL,
    value      TEXT NOT NULL,
    depth      INTEGER NOT NULL,
    module     TEXT NOT NULL,
    first_seen TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS relations (
    source     TEXT NOT NULL,
    target     TEXT NOT NULL,
    label      TEXT NOT NULL,
    module     TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    PRIMARY KEY (source, target, label)
);
CREATE TABLE IF NOT EXISTS findings (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    entity   TEXT NOT NULL,
    module   TEXT NOT NULL,
    title    TEXT NOT NULL,
    severity TEXT NOT NULL,
    data     TEXT NOT NULL,
    updated  TEXT NOT NULL,
    UNIQUE (entity, module, title)
);
CREATE TABLE IF NOT EXISTS errors (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    module  TEXT NOT NULL,
    entity  TEXT NOT NULL,
    message TEXT NOT NULL,
    created TEXT NOT NULL
);
"""


def now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


class Store:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(self.path)
        self._db.row_factory = sqlite3.Row
        self._db.executescript(SCHEMA)

    def __enter__(self) -> Store:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def commit(self) -> None:
        self._db.commit()

    def close(self) -> None:
        self._db.commit()
        self._db.close()

    # --- escritura -------------------------------------------------------

    def set_meta(self, **values: Any) -> None:
        self._db.executemany(
            "INSERT INTO meta(key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            [(k, str(v)) for k, v in values.items()],
        )

    def add_entity(self, entity: Entity, depth: int, module: str) -> None:
        self._db.execute(
            "INSERT INTO entities(key, type, value, depth, module, first_seen) VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET depth = MIN(depth, excluded.depth)",
            (entity.key, str(entity.type), entity.value, depth, module, now()),
        )

    def add_relation(self, rel: Relation) -> None:
        self._db.execute(
            "INSERT OR IGNORE INTO relations(source, target, label, module, first_seen) "
            "VALUES (?, ?, ?, ?, ?)",
            (rel.source.key, rel.target.key, rel.label, rel.module, now()),
        )

    def add_finding(self, f: Finding) -> None:
        self._db.execute(
            "INSERT INTO findings(entity, module, title, severity, data, updated) VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(entity, module, title) DO UPDATE SET "
            "severity = excluded.severity, data = excluded.data, updated = excluded.updated",
            (
                f.entity.key,
                f.module,
                f.title,
                str(f.severity),
                json.dumps(f.data, ensure_ascii=False, default=str),
                now(),
            ),
        )

    def add_error(self, module: str, entity: Entity, message: str) -> None:
        self._db.execute(
            "INSERT INTO errors(module, entity, message, created) VALUES (?, ?, ?, ?)",
            (module, entity.key, message, now()),
        )

    def clear_errors(self) -> None:
        self._db.execute("DELETE FROM errors")

    # --- lectura ---------------------------------------------------------

    def meta(self) -> dict[str, str]:
        return {r["key"]: r["value"] for r in self._db.execute("SELECT key, value FROM meta")}

    def entities(self) -> list[dict[str, Any]]:
        rows = self._db.execute("SELECT * FROM entities ORDER BY type, value")
        return [dict(r) for r in rows]

    def relations(self) -> list[dict[str, Any]]:
        rows = self._db.execute("SELECT * FROM relations ORDER BY source, label, target")
        return [dict(r) for r in rows]

    def findings(self) -> list[dict[str, Any]]:
        rows = [dict(r) for r in self._db.execute("SELECT * FROM findings")]
        for r in rows:
            r["data"] = json.loads(r["data"])
        rows.sort(key=lambda r: (-Severity(r["severity"]).rank, r["entity"], r["title"]))
        return rows

    def errors(self) -> list[dict[str, Any]]:
        return [dict(r) for r in self._db.execute("SELECT * FROM errors ORDER BY id")]

    def counts(self) -> dict[str, int]:
        return {
            table: self._db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("entities", "relations", "findings", "errors")
        }
