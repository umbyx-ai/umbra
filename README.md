# Umbra 👻

[![tests](https://github.com/umbyx-ai/umbra/actions/workflows/tests.yml/badge.svg)](https://github.com/umbyx-ai/umbra/actions/workflows/tests.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
[![Licencia: MIT](https://img.shields.io/badge/licencia-MIT-green)](LICENSE)

**Umbra** es una navaja suiza de **OSINT** para terminal. Tiene un menú con una opción por cada práctica del tema de OSINT y reconocimiento pasivo: Google Dorking, Shodan, IMINT (metadatos, búsqueda inversa, ELA), SOCMINT (emails, filtraciones, usuarios, egosurfing) y recon pasivo de infraestructura (DNS, crt.sh, WHOIS/ASN, Wayback, favicon hash).

```text
 _   _ __  __ ____  ____      _
| | | |  \/  | __ )|  _ \    / \
| | | | |\/| |  _ \| |_) |  / _ \
| |_| | |  | | |_) |  _ <  / ___ \
 \___/|_|  |_|____/|_| \_\/_/   \_\
 OSINT · dorks, IMINT, SOCMINT y recon pasivo

      BUSCADORES
 [1]  Google Dorking                   constructor, plantillas contra un dominio y operadores
 [2]  Buscadores de dispositivos       Shodan, Censys, FOFA… impresoras, cámaras, IPs
      RECON PASIVO DE INFRAESTRUCTURA
 [3]  DNS y correo                     MX, SPF, DKIM, DMARC: ¿correo en la nube u on-premise?
 [4]  Subdominios                      crt.sh + DNS pasivo + palabras clave (dev, vpn, admin…)
 [5]  WHOIS, RDAP y ASN                entidad legal, registrador, ASN y bloques CIDR
 [6]  Wayback Machine                  URLs antiguas, documentos y endpoints olvidados
 [7]  Favicon hash                     pivote a Shodan/FOFA con el hash del favicon
 [8]  Validación en vivo [ACTIVO]      códigos 200/401/403 y paneles de acceso
 [9]  Recon automático                 encadena todo y genera un grafo e informe
      IMINT · IMÁGENES
[10]  Metadatos de archivos            EXIF, GPS, PDF y Office (+ limpiar una foto)
[11]  Búsqueda inversa de imágenes     Google Lens, Bing, Yandex, TinEye + geolocalización
[12]  ¿Imagen manipulada? (ELA)        Error Level Analysis + detectores de IA
      SOCMINT · PERSONAS Y CORREO
[13]  Emails de una organización       domain search, email finder y verificación
[14]  Filtraciones de un email         brechas conocidas (XposedOrNot / HIBP)
[15]  ¿Contraseña filtrada?            Pwned Passwords con k-anonimato
[16]  Nombre de usuario en redes       busca un alias en muchas plataformas
[17]  Egosurfing                       tu propia huella: dorks sobre ti y Google Alerts
      CASO
[18]  Bitácora y GAP analysis          lo que has hecho, notas y las 4 preguntas
```

## Instalación

### 1. Requisitos

| Necesitas | Cómo comprobarlo | Si no lo tienes |
|---|---|---|
| **Python 3.11 o superior** | `python --version` (en Windows también `py --version`) | Windows: `winget install Python.Python.3.13` o [python.org](https://www.python.org/downloads/) · Debian/Ubuntu/Kali: `sudo apt install python3 python3-venv` · macOS: `brew install python` |
| **Git** (opcional) | `git --version` | Windows: `winget install Git.Git` · Linux: `sudo apt install git`. También puedes bajar el ZIP desde el botón verde **Code** de GitHub. |

No hace falta nada más: ni Go, ni Git Bash, ni binarios externos.

### 2. Descargar e instalar

Elige una carpeta donde guardar Umbra (por ejemplo `Documentos`) y abre una terminal en ella.

**Windows** (PowerShell, cmd o Windows Terminal):

```bash
git clone https://github.com/umbyx-ai/umbra.git
cd umbra
.\install.bat
```

**Linux y macOS:**

```bash
git clone https://github.com/umbyx-ai/umbra.git
cd umbra
sh install.sh
```

El instalador hace todo solo:

1. Comprueba que tienes Python 3.11 o superior.
2. Crea un entorno virtual en `umbra/.venv`, aislado del resto de tu Python.
3. Instala Umbra y sus dependencias dentro de él.
4. Deja disponible el comando `umbra` en cualquier terminal:
   - **Windows:** añade la carpeta `umbra\bin` al PATH de tu usuario (no hacen falta permisos de administrador).
   - **Linux/macOS:** crea el comando `~/.local/bin/umbra` y, si esa carpeta no está en tu PATH, la añade en tu `.bashrc` o `.zshrc`.

### 3. Abrir Umbra

**Cierra la terminal y abre una nueva** (las que ya estaban abiertas no ven el cambio del PATH). Desde cualquier carpeta, escribe:

```bash
umbra
```

Si quieres comprobar que todo está bien antes de abrir el menú, `umbra --version` debe responder `umbra 0.2.0`.

### Instalación manual (opcional)

Si prefieres no tocar el PATH, puedes instalarlo a mano y arrancarlo siempre desde la carpeta del proyecto:

```bash
python -m venv .venv
```

| Paso | Windows | Linux / macOS |
|---|---|---|
| Instalar | `.venv\Scripts\python -m pip install -e .` | `.venv/bin/python -m pip install -e .` |
| Arrancar | `.venv\Scripts\python -m umbra` | `.venv/bin/python -m umbra` |

Con este método no hace falta "activar" el entorno virtual. Si lo activas (`.venv\Scripts\activate` o `source .venv/bin/activate`), el comando `umbra` solo existe en esa terminal y mientras siga activado. También puedes ejecutar `.\install.bat --no-path` o `sh install.sh --no-path`: instala todo sin tocar el PATH.

### Actualizar

```bash
cd umbra
git pull
```

Como la instalación apunta a la carpeta del proyecto, `git pull` basta. Si alguna versión nueva añade dependencias, vuelve a ejecutar `.\install.bat` o `sh install.sh`: reutiliza el entorno y solo instala lo que falte.

### Desinstalar

1. Quita el comando: `.\install.bat --uninstall` (Windows) o `sh install.sh --uninstall` (Linux/macOS).
2. Borra la carpeta `umbra`. **Antes guarda `umbra/cases` si quieres conservar tus investigaciones.**

## Uso

### El menú, paso a paso

1. Escribe `umbra`. Aparece el banner y te pide el **nombre del caso**: por ejemplo `practica-dns` o `examen-osint`. Pulsa Enter para usar `general`. Si el caso ya existe, continúas donde lo dejaste.
2. Elige una opción del menú escribiendo su **número** y pulsando Enter.
3. Responde a lo que te pregunta. Entre corchetes ves el valor por defecto: `(s)` significa que con Enter respondes "sí".
4. Al terminar, pulsa Enter para volver al menú. `c` cambia de caso y `0` sale.

Ejemplo con la opción 3 (DNS y correo):

```text
Opción: 3
Dominio: example.com
[*] Consultando el DNS de example.com…
   (tablas con registros MX, SPF, DMARC, DKIM y el veredicto: ¿correo en la nube u on-premise?)
¿Abrir en el navegador? (números separados por comas, t = todos, Enter = ninguno):
Pulsa Enter para volver
```

### Trucos

- Escribe **`0`** en cualquier pregunta para volver al menú sin terminar.
- **Ctrl+C** cancela la opción en curso, por ejemplo una consulta que tarda demasiado.
- Cuando te pida la ruta de un fichero (opciones 10, 11 y 12), puedes **arrastrar el fichero a la terminal** en lugar de escribirla.
- Las tablas de enlaces te preguntan cuáles abrir: `1,3` abre el 1 y el 3, `t` los abre todos y Enter ninguno.
- Lanza `umbra -v` para ver más detalle cuando algo falla.

### Dónde se guardan los resultados

Cada caso es una carpeta `umbra/cases/<caso>/` con:

- `bitacora.md`: todo lo que has hecho, con fecha y hora, en Markdown. Es la base de tu informe. Puedes verla desde la opción 18.
- Los ficheros que generan las opciones: listas de subdominios (`subdominios_*.txt`, `vivos_*.txt`), URLs de Wayback, imágenes ELA, informes del recon automático...

Para guardarlos en otra carpeta usa `umbra --cases-dir D:\investigaciones` o define la variable `UMBRA_CASES_DIR`.

### Sin menú (para scripts)

```bash
umbra run example.com                          # recon pasivo automático (profundidad 3)
umbra run example.com -d 1 --skip wayback      # más rápido
umbra run example.com -c mi-caso               # guardarlo en un caso concreto
umbra cases                                    # lista los casos guardados
umbra modules                                  # módulos del recon automático
umbra --help                                   # todas las opciones
```

### Claves de API opcionales

Todo funciona sin cuentas. Si defines estas variables de entorno, algunas opciones dan más resultados:

| Variable | Para qué |
|---|---|
| `SHODAN_API_KEY` | Búsquedas por API en la opción 2 y recuento de hosts por favicon en la 7 |
| `HUNTER_API_KEY` | Más emails en el *domain search* y verificación de emails (Hunter.io, plan gratuito) |
| `HIBP_API_KEY` | Have I Been Pwned además de XposedOrNot en la opción 14 |

Para definirlas de forma permanente:

- **Windows:** `setx HUNTER_API_KEY "tu_clave"`.
- **Linux/macOS:** añade `export HUNTER_API_KEY="tu_clave"` a tu `~/.bashrc` o `~/.zshrc`.

Después abre una terminal nueva. Las claves son personales: no las subas nunca al repositorio.

## Problemas frecuentes

**`umbra : El término 'umbra' no se reconoce como nombre de un cmdlet…`** (o `command not found`)

- ¿Has abierto una terminal **nueva** después de instalar? Las que ya estaban abiertas no ven el PATH actualizado. En editores como VS Code, ciérralo y vuelve a abrirlo entero.
- ¿Has ejecutado el instalador? Desde la carpeta `umbra`: `.\install.bat` o `sh install.sh`.
- Mientras tanto, puedes arrancarlo desde la carpeta del proyecto con `bin\umbra.cmd` (Windows) o `.venv/bin/python -m umbra` (Linux/macOS).

**`No se puede cargar el archivo …\Activate.ps1 porque la ejecución de scripts está deshabilitada en este sistema`**

Es la política por defecto de PowerShell. Con el instalador no necesitas activar nada: usa `.\install.bat`. Si aun así quieres activar entornos virtuales en PowerShell, puedes permitir scripts locales para tu usuario con `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`; es decisión tuya.

**`Una directiva de Control de aplicaciones bloqueó este archivo`**

El Control inteligente de aplicaciones de Windows 11 bloquea `.venv\Scripts\umbra.exe` porque no está firmado. El comando `umbra` que instala `install.bat` no usa ese `.exe`: llama a `python.exe`, que sí está firmado, así que no le afecta.

**`python` no se reconoce o abre la Microsoft Store**

Python no está instalado o no está en el PATH. Instálalo con `winget install Python.Python.3.13` (o desde python.org marcando *Add python.exe to PATH*) y abre una terminal nueva. En Windows también puedes probar con `py --version`.

**`The virtual environment was not created successfully because ensurepip is not available`** (Debian, Ubuntu, Kali)

Falta el paquete de entornos virtuales: `sudo apt install python3-venv` y vuelve a ejecutar `sh install.sh`.

**En Git Bash (Windows) no encuentra `umbra`**

Ejecuta `install.bat` una vez desde PowerShell o cmd y abre Git Bash de nuevo: la carpeta `bin` del proyecto también tiene un lanzador para Git Bash.

## De la presentación al menú

| Práctica de clase | Opción |
|---|---|
| Google dorks (`filetype:pdf "curriculum vitae" dni granollers`) | 1 → dork libre o constructor |
| Impresoras en Shodan (EPSON, `/general/status.html`, OfficeJet, Ricoh, Brother...) y Shodan dorks | 2 → plantillas |
| Reverse image search (Google, Bing, Yandex, TinEye) y geolocalizar una foto | 11 |
| Metadatos EXIF y GPS (ExifTool) | 10 (usa exiftool si lo tienes instalado) |
| Verificar si una foto está retocada (ELA) | 12 |
| Egosurfing con Google Alerts | 17 |
| Data leak: probar tus emails en fuentes de filtraciones | 14 y 15 |
| Get mail addresses from company name (domain search, email finder, single email) | 13 |
| Find social media from mail or username | 16 (y 13.3 con Gravatar) |
| DNS footprinting: MX y SPF, ¿on-premise o cloud? (`dig` / `nslookup`) | 3 (muestra también los comandos equivalentes) |
| Subdomain harvesting en crt.sh con `%` | 4 |
| The Origin: entidad legal y ASN | 5 |
| Web archives (Wayback Machine) | 6 |
| The Favicon Pivot (Murmur3 + `http.favicon.hash`) | 7 |
| The Live Validation (httpx, 401/403) | 8 |
| Frameworks automáticos (Amass, SpiderFoot...) | 9 |
| GAP analysis (las 4 preguntas) | 18 |

## Qué es pasivo y qué no

- **Pasivo** (no toca al objetivo): 2, 3, 4, 5, 6, 9, 14, 15, 16. Todo sale de fuentes de terceros (DNS público, crt.sh, RIPEstat, RDAP, Shodan InternetDB, archive.org, XposedOrNot...).
- **Como un navegador**: la 7 descarga el favicon de la web y la 13 puede leer sus páginas de contacto y aviso legal. Te lo pregunta antes.
- **Activo**: la 8 envía una petición HTTP a cada host. Pide confirmación de que estás dentro de un alcance autorizado.
- **Local**: 10, 11 y 12 trabajan con tus ficheros, sin subirlos a ningún sitio.
- Las búsquedas en Google y en los buscadores de dispositivos se abren en tu navegador: automatizarlas va contra sus condiciones de uso.

## Arquitectura

```text
install.bat · install.sh · install.py   # instaladores (Windows / Linux-macOS / lógica común)
bin/                      # lanzadores del comando umbra (umbra.cmd y umbra para Git Bash)
umbra/
├── cli.py · menu.py      # entrada y menú principal
├── ui.py · case.py       # interfaz (Rich) y casos con bitácora
├── lookups.py            # consultas a fuentes públicas reutilizables
├── tools/                # una opción del menú por fichero
├── core/                 # motor de pivotes del recon automático
│   ├── entities.py · scope.py · engine.py · module.py · net.py · storage.py · known.py
└── modules/              # módulos del recon automático (dns, crtsh, rdap, ripestat, internetdb, wayback, pivot)
```

Para añadir una opción al menú: crea `umbra/tools/mi_opcion.py` con una función `run(case)` y añádela a `SECTIONS` en `menu.py`. La lógica que no depende de la red conviene dejarla en funciones puras, para poder testearla.

## Tests

Instala también las dependencias de desarrollo y lanza pytest con el Python del entorno virtual:

```bash
.\install.bat --dev
```
```bash
.venv\Scripts\python -m pytest
```

En Linux y macOS: `sh install.sh --dev` y `.venv/bin/python -m pytest`. El CI de GitHub Actions ejecuta los mismos tests en Linux y Windows en cada push.

## Aviso legal

Umbra está pensada para formación, investigación autorizada y defensa de tus propios activos. Que una información sea pública no te da permiso para recopilarla sobre cualquiera: **los datos personales están protegidos por el RGPD y la LOPDGDD**, y publicar datos de alguien sin su consentimiento es *doxing*. Usa el egosurfing contigo mismo, la validación en vivo solo dentro de un alcance autorizado, y no accedas a dispositivos ajenos ni pruebes contraseñas por defecto. La carpeta `cases/` está en `.gitignore` para que no subas por error lo que investigas.

## Licencia

[MIT](LICENSE).

*Creado por [umbyx-ai](https://github.com/umbyx-ai)* 👻
