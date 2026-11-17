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

Requiere Python 3.11 o superior. Funciona en Windows, Linux y macOS sin Git Bash ni binarios externos.

```bash
git clone https://github.com/umbyx-ai/umbra.git
cd umbra
python -m venv .venv
# Windows:  .venv\Scripts\activate      Linux/macOS:  source .venv/bin/activate
pip install -e ".[dev]"
```

## Uso

```bash
umbra                       # abre el menú
umbra run example.com       # recon pasivo automático sin menú (para scripts)
umbra cases                 # casos guardados
```

En Windows, si `umbra` no arranca porque PowerShell tiene los scripts deshabilitados o porque el Control inteligente de aplicaciones de Windows 11 dice *"Una directiva de Control de aplicaciones bloqueó este archivo"*, ejecútalo como módulo de Python (no hace falta activar el entorno):

```bash
.venv\Scripts\python -m umbra
```

Al arrancar eliges un **caso** (por ejemplo `practica-dns`). Todo lo que haces queda en `cases/<caso>/bitacora.md` con fecha y hora, junto a los ficheros generados: listas de subdominios, URLs de Wayback, imágenes ELA, informes de recon... Esa bitácora es la base de tu informe.

En cualquier pregunta, `0` vuelve al menú. Las tablas de enlaces te preguntan cuáles abrir en el navegador (`1,3`, `t` para todos o Enter para ninguno).

### Claves opcionales

Todo funciona sin cuentas. Si defines estas variables de entorno, algunas opciones dan más resultados:

| Variable | Para qué |
|---|---|
| `SHODAN_API_KEY` | Búsquedas por API en la opción 2 y recuento de hosts por favicon en la 7 |
| `HUNTER_API_KEY` | Más emails en el *domain search* y verificación de emails (Hunter.io, plan gratuito) |
| `HIBP_API_KEY` | Have I Been Pwned además de XposedOrNot en la opción 14 |

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

```bash
pytest
```

## Aviso legal

Umbra está pensada para formación, investigación autorizada y defensa de tus propios activos. Que una información sea pública no te da permiso para recopilarla sobre cualquiera: **los datos personales están protegidos por el RGPD y la LOPDGDD**, y publicar datos de alguien sin su consentimiento es *doxing*. Usa el egosurfing contigo mismo, la validación en vivo solo dentro de un alcance autorizado, y no accedas a dispositivos ajenos ni pruebes contraseñas por defecto. La carpeta `cases/` está en `.gitignore` para que no subas por error lo que investigas.

## Licencia

[MIT](LICENSE).

*Creado por [umbyx-ai](https://github.com/umbyx-ai)* 👻
