"""Tests del instalador y de cómo la CLI elige la carpeta de casos."""

import importlib.util
import os
from pathlib import Path, PurePosixPath

from umbra.cli import build_parser, resolve_cases_dir

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("install", ROOT / "install.py")
install = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(install)

SEP = os.pathsep


def test_path_with_appends_once():
    assert install.path_with("", "/x/bin") == "/x/bin"
    assert install.path_with(f"/a{SEP}/b{SEP}", "/x/bin") == f"/a{SEP}/b{SEP}/x/bin"
    assert install.path_with(f"/a{SEP}/x/bin/", "/x/bin") is None  # ya estaba (con barra final)


def test_path_without_only_removes_ours():
    assert install.path_without(f"/a{SEP}/x/bin{SEP}/b", "/x/bin") == f"/a{SEP}/b"
    assert install.path_without(f"/a{SEP}/b", "/x/bin") is None


def test_unix_launcher_quotes_paths_with_spaces():
    root = PurePosixPath("/home/ana/mis proyectos/umbra")  # el lanzador solo se genera en Linux/macOS
    script = install.unix_launcher(root, root / ".venv/bin/python")
    assert script.startswith("#!/bin/sh\n")
    assert "ROOT='/home/ana/mis proyectos/umbra'" in script
    assert 'UMBRA_CASES_DIR:=$ROOT/cases' in script
    assert script.rstrip().endswith('-m umbra "$@"')


def test_cases_dir_before_subcommand_is_kept():
    args = build_parser().parse_args(["--cases-dir", "X", "run", "example.com"])
    assert resolve_cases_dir(args) == Path("X")
    args = build_parser().parse_args(["run", "example.com", "--cases-dir", "Y"])
    assert resolve_cases_dir(args) == Path("Y")


def test_cases_dir_from_environment(monkeypatch):
    monkeypatch.setenv("UMBRA_CASES_DIR", "/desde/el/lanzador")
    assert resolve_cases_dir(build_parser().parse_args([])) == Path("/desde/el/lanzador")
    monkeypatch.delenv("UMBRA_CASES_DIR")
    assert resolve_cases_dir(build_parser().parse_args(["cases"])) == Path("cases")


def test_launchers_exist_with_correct_line_endings():
    assert b"-m umbra" in (ROOT / "bin" / "umbra.cmd").read_bytes()
    assert b"\r\n" not in (ROOT / "bin" / "umbra").read_bytes()
    assert b"\r\n" not in (ROOT / "install.sh").read_bytes()
