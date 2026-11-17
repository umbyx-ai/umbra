"""Metadatos de archivos: EXIF y GPS de fotos, PDF y documentos de Office/LibreOffice.

También analiza carpetas enteras (al estilo FOCA: qué usuarios, software y
dispositivos aparecen) y limpia los metadatos de una foto antes de publicarla.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from xml.etree import ElementTree

from PIL import ExifTags, Image, ImageOps

from umbra import ui, web
from umbra.case import Case

IMAGE_EXT = {".jpg", ".jpeg", ".jpe", ".tif", ".tiff", ".png", ".webp"}
PDF_EXT = {".pdf"}
OOXML_EXT = {".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm"}
ODF_EXT = {".odt", ".ods", ".odp", ".odg"}
SUPPORTED = IMAGE_EXT | PDF_EXT | OOXML_EXT | ODF_EXT

EXIF_FIELDS = {
    "Make": "Fabricante", "Model": "Modelo", "BodySerialNumber": "Nº de serie", "CameraOwnerName": "Propietario",
    "LensMake": "Fabricante lente", "LensModel": "Lente", "LensSerialNumber": "Nº serie lente",
    "Software": "Software", "DateTimeOriginal": "Fecha de captura", "DateTimeDigitized": "Fecha digitalización",
    "DateTime": "Fecha modificación", "OffsetTimeOriginal": "Zona horaria", "Artist": "Autor",
    "Copyright": "Copyright", "ImageDescription": "Descripción", "XPAuthor": "Autor (Windows)",
    "XPComment": "Comentario (Windows)", "XPKeywords": "Etiquetas (Windows)", "HostComputer": "Equipo",
    "UserComment": "Comentario",
}
DOC_LABELS = {
    "creator": "Autor", "lastModifiedBy": "Modificado por", "created": "Creado", "modified": "Modificado",
    "title": "Título", "subject": "Asunto", "description": "Descripción", "keywords": "Palabras clave",
    "revision": "Revisión", "lastPrinted": "Impreso", "Application": "Software", "AppVersion": "Versión",
    "Company": "Empresa", "Manager": "Responsable", "Template": "Plantilla", "TotalTime": "Minutos de edición",
    "initial-creator": "Autor original", "creation-date": "Creado", "date": "Modificado",
    "generator": "Software", "editing-cycles": "Revisiones", "printed-by": "Impreso por",
}
PEOPLE_KEYS = {"Autor", "Modificado por", "Autor original", "Impreso por", "Responsable", "Propietario",
               "Autor (Windows)", "Copyright"}
SOFTWARE_KEYS = {"Software", "Productor", "Creador (app)", "Plantilla"}
DEVICE_KEYS = {"Fabricante", "Modelo", "Nº de serie", "Equipo", "Lente"}


@dataclass
class FileMeta:
    path: Path
    kind: str
    fields: dict[str, str] = field(default_factory=dict)
    gps: tuple[float, float] | None = None
    altitude: float | None = None
    error: str = ""

    def values(self, keys: set[str]) -> set[str]:
        return {v for k, v in self.fields.items() if k in keys and v}


# --- imágenes ----------------------------------------------------------------

def _num(value) -> float:
    if isinstance(value, tuple) and len(value) == 2:
        return value[0] / value[1] if value[1] else 0.0
    return float(value)


def dms_to_decimal(dms, ref) -> float | None:
    """Convierte grados/minutos/segundos EXIF a grados decimales."""
    try:
        degrees, minutes, seconds = (_num(x) for x in dms)
    except (TypeError, ValueError, ZeroDivisionError):
        return None
    decimal = degrees + minutes / 60 + seconds / 3600
    if str(ref).strip().upper() in ("S", "W"):
        decimal = -decimal
    return round(decimal, 6)


def _decode(tag: str, value) -> str:
    if isinstance(value, tuple) and value and all(isinstance(x, int) for x in value):
        value = bytes(value)
    if isinstance(value, bytes):
        if tag.startswith("XP"):
            return value.decode("utf-16-le", "ignore").rstrip("\x00")
        if tag == "UserComment":
            head, body = value[:8], value[8:]
            enc = "utf-16" if head.startswith(b"UNICODE") else "latin-1"
            return body.decode(enc, "ignore").strip("\x00 ")
        return value.decode("utf-8", "ignore").strip("\x00 ") if len(value) < 300 else f"<{len(value)} bytes>"
    return str(value).strip().strip("\x00")


def image_metadata(path: Path) -> FileMeta:
    meta = FileMeta(path, "imagen")
    with Image.open(path) as img:
        meta.fields["Formato"] = f"{img.format} {img.width}x{img.height}"
        exif = img.getexif()
        merged = dict(exif)
        try:
            merged.update(exif.get_ifd(ExifTags.IFD.Exif))
        except (KeyError, ValueError):
            pass
        for tag_id, value in merged.items():
            name = ExifTags.TAGS.get(tag_id, str(tag_id))
            if name in EXIF_FIELDS and (text := _decode(name, value)):
                meta.fields[EXIF_FIELDS[name]] = text
        try:
            gps = {ExifTags.GPSTAGS.get(k, k): v for k, v in exif.get_ifd(ExifTags.IFD.GPSInfo).items()}
        except (KeyError, ValueError):
            gps = {}
        if "GPSLatitude" in gps and "GPSLongitude" in gps:
            lat = dms_to_decimal(gps["GPSLatitude"], gps.get("GPSLatitudeRef", "N"))
            lon = dms_to_decimal(gps["GPSLongitude"], gps.get("GPSLongitudeRef", "E"))
            if lat is not None and lon is not None and not (lat == 0 and lon == 0):
                meta.gps = (lat, lon)
        if "GPSAltitude" in gps:
            try:
                meta.altitude = round(_num(gps["GPSAltitude"]), 1)
            except (TypeError, ValueError, ZeroDivisionError):
                pass
        # Bloques de texto (PNG): a veces incluyen el prompt de una IA generativa
        for key, value in img.info.items():
            if isinstance(value, str) and value.strip() and "xmp" not in key.lower():
                meta.fields[f"Texto '{key}'"] = value.strip()[:500]
        xmp = img.info.get("xmp") or img.info.get("XML:com.adobe.xmp")
        if isinstance(xmp, bytes):
            xmp = xmp.decode("utf-8", "ignore")
        if isinstance(xmp, str):
            for label, pattern in (("Software", r"CreatorTool[=>\"']+([^<\"']+)"), ("Autor", r"<dc:creator>.*?<rdf:li[^>]*>([^<]+)")):
                if (m := re.search(pattern, xmp, re.S)) and label not in meta.fields:
                    meta.fields[label] = m.group(1).strip()
    return meta


def strip_image(path: Path) -> Path:
    """Guarda una copia sin metadatos (aplica antes la rotación para que no se gire)."""
    out = path.with_name(f"{path.stem}_sin_metadatos{path.suffix}")
    with Image.open(path) as img:
        fmt = img.format
        img = ImageOps.exif_transpose(img)
        if img.mode == "P":
            img = img.convert("RGBA")
        clean = Image.frombytes(img.mode, img.size, img.tobytes())  # solo píxeles: nada de EXIF/XMP/ICC
    if fmt == "JPEG" and clean.mode not in ("RGB", "L"):
        clean = clean.convert("RGB")
    clean.save(out, format=fmt, **({"quality": 95} if fmt == "JPEG" else {}))
    return out


# --- documentos --------------------------------------------------------------

def pdf_metadata(path: Path) -> FileMeta:
    from pypdf import PdfReader

    meta = FileMeta(path, "pdf")
    reader = PdfReader(path)
    if reader.is_encrypted:
        try:
            reader.decrypt("")
        except Exception:  # noqa: BLE001
            meta.error = "PDF cifrado"
            return meta
    info = reader.metadata or {}
    labels = {"/Title": "Título", "/Author": "Autor", "/Subject": "Asunto", "/Keywords": "Palabras clave",
              "/Creator": "Creador (app)", "/Producer": "Productor", "/CreationDate": "Creado", "/ModDate": "Modificado"}
    for key, value in info.items():
        text = str(value).strip()
        if text:
            meta.fields[labels.get(key, key.lstrip("/"))] = _pdf_date(text) if "Date" in key else text
    meta.fields["Páginas"] = str(len(reader.pages))
    try:
        xmp = reader.xmp_metadata
        if xmp is not None:
            if xmp.dc_creator and "Autor" not in meta.fields:
                meta.fields["Autor"] = ", ".join(xmp.dc_creator)
            if xmp.xmp_creator_tool and "Creador (app)" not in meta.fields:
                meta.fields["Creador (app)"] = xmp.xmp_creator_tool
    except Exception:  # noqa: BLE001 - XMP mal formado: no es grave
        pass
    return meta


def _pdf_date(raw: str) -> str:
    m = re.match(r"D:(\d{4})(\d{2})(\d{2})(\d{2})?(\d{2})?", raw)
    if not m:
        return raw
    y, mo, d, h, mi = m.groups()
    return f"{d}/{mo}/{y}" + (f" {h}:{mi or '00'}" if h else "")


def _xml_fields(data: bytes) -> dict[str, str]:
    out: dict[str, str] = {}
    root = ElementTree.fromstring(data)
    for el in root.iter():
        local = el.tag.rsplit("}", 1)[-1]
        if el.text and el.text.strip() and not list(el):
            out[local] = el.text.strip()
    return out


def office_metadata(path: Path) -> FileMeta:
    meta = FileMeta(path, "documento")
    with zipfile.ZipFile(path) as z:
        names = set(z.namelist())
        raw: dict[str, str] = {}
        for member in ("docProps/core.xml", "docProps/app.xml", "meta.xml"):
            if member in names and z.getinfo(member).file_size < 5_000_000:
                raw.update(_xml_fields(z.read(member)))
    for key, value in raw.items():
        if key in DOC_LABELS:
            meta.fields[DOC_LABELS[key]] = value
    return meta


def analyze(path: Path) -> FileMeta:
    ext = path.suffix.lower()
    try:
        if ext in IMAGE_EXT:
            return image_metadata(path)
        if ext in PDF_EXT:
            return pdf_metadata(path)
        if ext in OOXML_EXT | ODF_EXT:
            return office_metadata(path)
    except Exception as exc:  # noqa: BLE001 - un fichero roto no para el análisis de la carpeta
        return FileMeta(path, "error", error=f"{exc.__class__.__name__}: {exc}")
    return FileMeta(path, "no soportado", error="formato no soportado")


def map_links(lat: float, lon: float) -> list[tuple[str, str]]:
    return [
        ("Google Maps", f"https://www.google.com/maps?q={lat},{lon}"),
        ("OpenStreetMap", f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=17/{lat}/{lon}"),
        ("Google Earth", f"https://earth.google.com/web/search/{lat},{lon}"),
    ]


async def reverse_geocode(http, lat: float, lon: float) -> str | None:
    data = await http.get_json(
        "https://nominatim.openstreetmap.org/reverse",
        params={"format": "jsonv2", "lat": str(lat), "lon": str(lon), "zoom": "16", "accept-language": "es"},
        retries=1,
    )
    return (data or {}).get("display_name")


# --- interacción -------------------------------------------------------------

def _show_file(case: Case, meta: FileMeta) -> None:
    if meta.error:
        ui.error(f"{meta.path.name}: {meta.error}")
        return
    rows = list(meta.fields.items())
    if meta.gps:
        rows.append(("GPS", f"{meta.gps[0]}, {meta.gps[1]}" + (f" · {meta.altitude} m" if meta.altitude else "")))
    if not rows or rows == [("Formato", meta.fields.get("Formato"))]:
        ui.info("No tiene metadatos interesantes (las redes sociales suelen borrarlos al subir la foto).")
    ui.kv(rows, title=f"{meta.path.name} ({meta.kind})")
    body = ui.md_table(["Campo", "Valor"], rows)
    if meta.gps:
        lat, lon = meta.gps
        ui.warn("La foto tiene coordenadas GPS: revela dónde se hizo.")
        if ui.confirm("¿Buscar la dirección aproximada? (OpenStreetMap Nominatim)", default=True):
            with ui.status("Consultando Nominatim…"):
                address = web.run(lambda http, _dns: reverse_geocode(http, lat, lon))
            if address:
                ui.ok(f"Dirección aproximada: {address}")
                body += f"\n\n**Dirección aproximada:** {address}"
        ui.links(map_links(lat, lon), title="Ver en el mapa")
        body += "\n\n" + ui.md_links(map_links(lat, lon))
    if shutil.which("exiftool") and ui.confirm("Tienes exiftool instalado: ¿ver TODOS los metadatos?", default=False):
        out = subprocess.run(["exiftool", "-a", "-G1", "-s", str(meta.path)], capture_output=True, text=True,
                             encoding="utf-8", errors="replace", check=False)
        ui.console.print(out.stdout[:12000], markup=False)
    case.log("Metadatos", meta.path.name, body)


def _folder(case: Case, folder: Path) -> None:
    files = [p for p in sorted(folder.rglob("*")) if p.is_file() and p.suffix.lower() in SUPPORTED][:1000]
    if not files:
        ui.info("No hay ficheros compatibles en esa carpeta.")
        return
    results: list[FileMeta] = []
    with ui.status(f"Analizando {len(files)} ficheros…"):
        results = [analyze(p) for p in files]
    ui.table(
        ["Fichero", "Tipo", "Autor / usuario", "Software", "Dispositivo", "GPS"],
        [(m.path.name, m.kind, m.values(PEOPLE_KEYS), m.values(SOFTWARE_KEYS), m.values(DEVICE_KEYS),
          f"{m.gps[0]}, {m.gps[1]}" if m.gps else "") for m in results],
        title=f"{len(results)} ficheros",
    )
    people = sorted(set().union(*(m.values(PEOPLE_KEYS) for m in results)))
    software = sorted(set().union(*(m.values(SOFTWARE_KEYS) for m in results)))
    devices = sorted(set().union(*(m.values(DEVICE_KEYS) for m in results)))
    with_gps = [m for m in results if m.gps]
    summary = [("Usuarios / autores", people), ("Software", software), ("Dispositivos", devices),
               ("Con GPS", [m.path.name for m in with_gps])]
    ui.kv(summary, title="Resumen (lo que un atacante aprendería)")
    ui.note("Los nombres de usuario y versiones de software sirven para phishing dirigido y para buscar vulnerabilidades.")
    case.log("Metadatos (carpeta)", str(folder), ui.md_table(["Qué", "Encontrado"], summary))


def run(case: Case) -> None:
    ui.title("Metadatos de archivos", "Fotos (EXIF, GPS), PDF y documentos de Office o LibreOffice.")
    choice = ui.choose([
        ("1", "Analizar un fichero"),
        ("2", "Analizar una carpeta entera (estilo FOCA)"),
        ("3", "Limpiar los metadatos de una foto"),
        ("0", "Volver"),
    ])
    if choice == "0":
        return
    path = ui.ask_path("Ruta (puedes arrastrar el fichero a la terminal)")
    if choice == "2":
        if not path.is_dir():
            ui.warn("Eso no es una carpeta.")
            return
        _folder(case, path)
    elif choice == "1":
        if path.is_dir():
            ui.warn("Eso es una carpeta: usa la opción 2.")
            return
        _show_file(case, analyze(path))
    elif choice == "3":
        if path.suffix.lower() not in IMAGE_EXT:
            ui.warn("Solo puedo limpiar imágenes (JPG, PNG, TIFF, WebP).")
            return
        out = strip_image(path)
        left = image_metadata(out)
        leftover = {k: v for k, v in left.fields.items() if k != "Formato"}
        ui.ok(f"Copia limpia guardada en {out}" + (" (sin GPS ni EXIF)" if not leftover and not left.gps else ""))
        ui.note("El original no se toca. Las JPG se recomprimen al 95 % de calidad.")
        case.log("Metadatos", path.name, f"Copia sin metadatos: `{out}`")
