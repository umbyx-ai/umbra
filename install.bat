@echo off
rem Instalador de Umbra para Windows: busca Python 3.11+ y ejecuta install.py.
rem Es un .bat (no un .ps1) para que funcione aunque PowerShell tenga los scripts deshabilitados.
setlocal
cd /d "%~dp0"

set "UMBRA_PYCMD="
py -3 -c "import sys; sys.exit(sys.version_info < (3, 11))" >nul 2>&1 && set "UMBRA_PYCMD=py -3"
if not defined UMBRA_PYCMD python -c "import sys; sys.exit(sys.version_info < (3, 11))" >nul 2>&1 && set "UMBRA_PYCMD=python"

if not defined UMBRA_PYCMD (
    echo [x] No encuentro Python 3.11 o superior.
    echo     Instalalo con:  winget install Python.Python.3.13
    echo     o desde https://www.python.org/downloads/ y vuelve a ejecutar install.bat
    exit /b 1
)

%UMBRA_PYCMD% "%~dp0install.py" %*
exit /b %errorlevel%
