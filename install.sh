#!/bin/sh
# Instalador de Umbra para Linux y macOS: busca Python 3.11+ y ejecuta install.py.
set -eu
cd "$(dirname -- "$0")"

for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1 \
        && "$candidate" -c 'import sys; sys.exit(sys.version_info < (3, 11))' 2>/dev/null; then
        exec "$candidate" install.py "$@"
    fi
done

echo "[x] No encuentro Python 3.11 o superior." >&2
echo "    Debian, Ubuntu o Kali:  sudo apt install python3 python3-venv" >&2
echo "    macOS:                  brew install python" >&2
exit 1
