#!/usr/bin/env python3
"""Instalador de Umbra (solo librería estándar).

Crea el entorno virtual ``.venv``, instala Umbra dentro y deja el comando
``umbra`` disponible en cualquier terminal nueva:

- Windows: añade la carpeta ``bin`` del proyecto al PATH de tu usuario. Ahí está
  ``umbra.cmd``, que llama a ``python.exe -m umbra``. Así no le afectan la política
  de scripts de PowerShell ni el Control inteligente de aplicaciones de Windows 11
  (que bloquea los ``.exe`` sin firmar que genera pip).
- Linux y macOS: crea el lanzador ``~/.local/bin/umbra``.

Uso:
    python install.py              instala o actualiza
    python install.py --dev        también instala pytest (para desarrollar)
    python install.py --no-path    no toca el PATH ni crea el lanzador
    python install.py --uninstall  quita el comando umbra (no borra la carpeta)
"""

from __future__ import annotations

import argparse
import os
import shlex
import subprocess
import sys
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENV = ROOT / ".venv"
WINDOWS = os.name == "nt"
VENV_PYTHON = VENV / ("Scripts/python.exe" if WINDOWS else "bin/python")
WINDOWS_BIN = ROOT / "bin"
UNIX_BIN = Path(os.environ.get("XDG_BIN_HOME") or Path.home() / ".local" / "bin")
MIN_PYTHON = (3, 11)


def info(msg: str) -> None:
    print(f"[*] {msg}", flush=True)


def ok(msg: str) -> None:
    print(f"[+] {msg}", flush=True)


def warn(msg: str) -> None:
    print(f"[!] {msg}", flush=True)


def fail(msg: str) -> None:
    print(f"[x] {msg}", file=sys.stderr, flush=True)
    sys.exit(1)


# --- lógica pura (con tests) ---------------------------------------------------

def _same_dir(a: str, b: str) -> bool:
    norm = os.path.normcase if WINDOWS else (lambda s: s)
    return norm(os.path.expandvars(a).rstrip("\\/")) == norm(b.rstrip("\\/"))


def path_with(value: str, directory: str) -> str | None:
    """PATH con ``directory`` añadido al final, o ``None`` si ya estaba."""
    parts = [p for p in value.split(os.pathsep) if p]
    if any(_same_dir(p, directory) for p in parts):
        return None
    return f"{value.rstrip(os.pathsep)}{os.pathsep}{directory}" if value.strip(os.pathsep) else directory


def path_without(value: str, directory: str) -> str | None:
    """PATH sin ``directory``, o ``None`` si no estaba."""
    parts = value.split(os.pathsep)
    kept = [p for p in parts if not (p and _same_dir(p, directory))]
    return os.pathsep.join(kept) if len(kept) != len(parts) else None


def unix_launcher(root: Path, python: Path) -> str:
    return (
        "#!/bin/sh\n"
        "# Lanzador de Umbra generado por install.py\n"
        f"ROOT={shlex.quote(str(root))}\n"
        ': "${UMBRA_CASES_DIR:=$ROOT/cases}"\n'
        "export UMBRA_CASES_DIR\n"
        f"exec {shlex.quote(str(python))} -m umbra \"$@\"\n"
    )


# --- pasos ---------------------------------------------------------------------

def check_python() -> None:
    if sys.version_info < MIN_PYTHON:
        fail(f"Umbra necesita Python {'.'.join(map(str, MIN_PYTHON))} o superior y tienes {sys.version.split()[0]}.")
    ok(f"Python {sys.version.split()[0]} ({sys.executable})")


def create_venv() -> None:
    if VENV_PYTHON.exists():
        ok("El entorno virtual .venv ya existe: lo reutilizo.")
        return
    info("Creando el entorno virtual .venv…")
    try:
        venv.EnvBuilder(with_pip=True).create(VENV)
    except Exception as exc:  # noqa: BLE001
        hint = "" if WINDOWS else " En Debian, Ubuntu o Kali instala antes: sudo apt install python3-venv"
        fail(f"No se pudo crear el entorno virtual: {exc}.{hint}")
    ok("Entorno virtual creado.")


def install_package(dev: bool) -> None:
    info("Instalando Umbra y sus dependencias (puede tardar un minuto)…")
    subprocess.run([str(VENV_PYTHON), "-m", "pip", "install", "--quiet", "--upgrade", "pip"], check=False)
    target = ".[dev]" if dev else "."
    quiet_env = {**os.environ, "PYTHONWARNINGS": "ignore"}  # oculta avisos técnicos de setuptools; los errores siguen saliendo
    result = subprocess.run([str(VENV_PYTHON), "-m", "pip", "install", "--quiet", "-e", target],
                            cwd=ROOT, env=quiet_env, check=False)
    if result.returncode:
        fail("pip no ha podido instalar Umbra. Revisa los mensajes de arriba (¿tienes conexión a Internet?).")
    out = subprocess.run([str(VENV_PYTHON), "-m", "umbra", "--version"], capture_output=True, text=True, check=False)
    if out.returncode:
        fail(f"Umbra se ha instalado pero no arranca:\n{out.stderr}")
    ok(f"Instalado: {out.stdout.strip()}")


def _broadcast_environment_change() -> None:
    """Avisa a Windows de que el PATH ha cambiado (las terminales nuevas lo verán)."""
    try:
        import ctypes

        result = ctypes.c_size_t()
        ctypes.windll.user32.SendMessageTimeoutW(0xFFFF, 0x1A, 0, "Environment", 0x2, 5000, ctypes.byref(result))
    except Exception:  # noqa: BLE001 - no es grave: basta con abrir una terminal nueva
        pass


def windows_path(add: bool) -> bool:
    import winreg

    directory = str(WINDOWS_BIN)
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_READ | winreg.KEY_WRITE) as key:
        try:
            value, kind = winreg.QueryValueEx(key, "Path")
        except FileNotFoundError:
            value, kind = "", winreg.REG_EXPAND_SZ
        new = path_with(value, directory) if add else path_without(value, directory)
        if new is None:
            return False
        if kind not in (winreg.REG_SZ, winreg.REG_EXPAND_SZ):
            kind = winreg.REG_EXPAND_SZ
        winreg.SetValueEx(key, "Path", 0, kind, new)
    _broadcast_environment_change()
    return True


def _shell_rc() -> Path:
    shell = os.path.basename(os.environ.get("SHELL", ""))
    return Path.home() / {"zsh": ".zshrc", "bash": ".bashrc"}.get(shell, ".profile")


def unix_install_launcher() -> None:
    UNIX_BIN.mkdir(parents=True, exist_ok=True)
    launcher = UNIX_BIN / "umbra"
    launcher.write_text(unix_launcher(ROOT, VENV_PYTHON), encoding="utf-8")
    launcher.chmod(0o755)
    ok(f"Comando creado: {launcher}")
    if any(_same_dir(p, str(UNIX_BIN)) for p in os.environ.get("PATH", "").split(os.pathsep) if p):
        return
    rc = _shell_rc()
    line = f'export PATH="{UNIX_BIN}:$PATH"  # añadido por el instalador de Umbra'
    if line not in (rc.read_text(encoding="utf-8") if rc.exists() else ""):
        with rc.open("a", encoding="utf-8") as fh:
            fh.write(f"\n{line}\n")
        ok(f"Añadido {UNIX_BIN} al PATH en {rc}.")


def uninstall() -> None:
    if WINDOWS:
        removed = windows_path(add=False)
        print("[+] Quitada la carpeta bin del PATH." if removed else "[*] La carpeta bin no estaba en el PATH.")
    else:
        launcher = UNIX_BIN / "umbra"
        if launcher.exists() and "install.py" in launcher.read_text(encoding="utf-8", errors="ignore"):
            launcher.unlink()
            ok(f"Borrado {launcher}.")
        else:
            info("No había lanzador que borrar.")
    info(f"Para borrar Umbra del todo, elimina la carpeta {ROOT} (tus casos están en {ROOT / 'cases'}).")


def main() -> None:
    parser = argparse.ArgumentParser(description="Instalador de Umbra")
    parser.add_argument("--dev", action="store_true", help="instala también las dependencias de desarrollo (pytest)")
    parser.add_argument("--no-path", action="store_true", help="no toca el PATH ni crea el lanzador")
    parser.add_argument("--uninstall", action="store_true", help="quita el comando umbra")
    args = parser.parse_args()

    print("\n== Instalador de Umbra ==\n", flush=True)
    if args.uninstall:
        uninstall()
        return
    check_python()
    create_venv()
    install_package(args.dev)

    if args.no_path:
        info("--no-path: no he tocado el PATH.")
        run_cmd = r"bin\umbra.cmd" if WINDOWS else f"{VENV_PYTHON} -m umbra"
        print(f"\nListo. Arráncalo con:  {run_cmd}\n")
        return
    if WINDOWS:
        added = windows_path(add=True)
        ok(f"Añadido {WINDOWS_BIN} al PATH de tu usuario." if added else f"{WINDOWS_BIN} ya estaba en tu PATH.")
    else:
        unix_install_launcher()
    print("\nListo. Abre una terminal NUEVA (las que ya tenías abiertas no ven el cambio) y escribe:\n\n    umbra\n")


if __name__ == "__main__":
    main()
