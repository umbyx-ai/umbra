@echo off
rem Lanzador de Umbra para Windows (cmd y PowerShell).
rem Llama al python.exe del entorno virtual, que esta firmado: asi no le afectan la politica
rem de scripts de PowerShell ni el Control inteligente de aplicaciones de Windows 11.
setlocal
for %%I in ("%~dp0..") do set "UMBRA_ROOT=%%~fI"
set "UMBRA_PY=%UMBRA_ROOT%\.venv\Scripts\python.exe"
if not exist "%UMBRA_PY%" (
    echo [x] Umbra no esta instalado todavia. Ejecuta install.bat en "%UMBRA_ROOT%".
    exit /b 1
)
if not defined UMBRA_CASES_DIR set "UMBRA_CASES_DIR=%UMBRA_ROOT%\cases"
"%UMBRA_PY%" -m umbra %*
exit /b %errorlevel%
