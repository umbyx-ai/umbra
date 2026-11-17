"""IMINT: búsqueda inversa de imágenes, geolocalización y análisis forense (ELA)."""

from __future__ import annotations

import io
from pathlib import Path
from urllib.parse import quote

from PIL import Image, ImageChops, ImageEnhance

from umbra import ui
from umbra.case import Case, case_slug
from umbra.tools.metadata import IMAGE_EXT, image_metadata, map_links

UPLOAD_PAGES = [
    ("Google Lens", "https://lens.google.com/"),
    ("Bing Visual Search", "https://www.bing.com/visualsearch"),
    ("Yandex Imágenes", "https://yandex.com/images/"),
    ("TinEye", "https://tineye.com/"),
]
ENGINE_TIPS = [
    ("Google Lens", "Lugares, monumentos, productos y textos."),
    ("Yandex", "Muy bueno con caras y paisajes; da resultados distintos a Google."),
    ("Bing", "Alternativa a Google, útil para objetos y compras."),
    ("TinEye", "Copias exactas: encuentra el origen y la primera vez que se publicó."),
]
GEO_RESOURCES = [
    ("Picarta (IA, de pago)", "https://picarta.ai/"),
    ("GeoSpy (IA, de pago)", "https://app.geospy.ai/"),
    ("SunCalc (hora por la sombra)", "https://www.suncalc.org/"),
    ("Overpass Turbo (buscar en OSM)", "https://overpass-turbo.eu/"),
    ("GeoGuessr (práctica)", "https://www.geoguessr.com/"),
    ("WorldGuessr (práctica gratis)", "https://www.worldguessr.com/"),
    ("FreeGuessr (práctica gratis)", "https://freeguessr.com/"),
]
FORENSIC_RESOURCES = [
    ("Forensically (ELA, ruido, clonado)", "https://29a.ch/photo-forensics/"),
    ("FotoForensics (tutorial ELA)", "https://fotoforensics.com/tutorial.php?tt=ela"),
    ("Hive: detector de imágenes IA", "https://thehive.ai/demos"),
    ("Illuminarty: detector IA", "https://app.illuminarty.ai/"),
]


def reverse_links(image_url: str) -> list[tuple[str, str]]:
    u = quote(image_url, safe="")
    return [
        ("Google Lens", f"https://lens.google.com/uploadbyurl?url={u}"),
        ("Bing", f"https://www.bing.com/images/search?view=detailv2&iss=sbi&form=SBIVSP&sbisrc=UrlPaste&q=imgurl:{u}"),
        ("Yandex", f"https://yandex.com/images/search?rpt=imageview&url={u}"),
        ("TinEye", f"https://tineye.com/search?url={u}"),
    ]


def error_level_analysis(path: Path, quality: int = 90) -> tuple[Image.Image, int]:
    """Recomprime la imagen y amplifica las diferencias.

    Las zonas pegadas o retocadas suelen comprimirse distinto que el resto y
    destacan en la imagen resultante. Devuelve (imagen ELA, diferencia máxima).
    """
    with Image.open(path) as img:
        original = img.convert("RGB")
    buffer = io.BytesIO()
    original.save(buffer, "JPEG", quality=quality)
    buffer.seek(0)
    with Image.open(buffer) as resaved:
        diff = ImageChops.difference(original, resaved.convert("RGB"))
    max_diff = max(high for _, high in diff.getextrema()) or 1
    return ImageEnhance.Brightness(diff).enhance(255.0 / max_diff), max_diff


def reverse(case: Case) -> None:
    ui.title("Búsqueda inversa de imágenes", "Buscar con una imagen en vez de con texto.")
    ui.table(["Buscador", "Para qué va mejor"], ENGINE_TIPS)
    ui.note("Cada buscador da resultados distintos: prueba siempre varios.")
    raw = ui.ask("URL de la imagen o ruta de un fichero local")
    target = raw.strip().strip('"').strip("'")
    if target.lower().startswith(("http://", "https://")):
        items = reverse_links(target)
        ui.links(items, title="Buscar esta imagen en")
        case.log("Búsqueda inversa", target, ui.md_links(items))
        return

    path = Path(target).expanduser()
    if not path.is_file():
        ui.warn("No encuentro ese fichero.")
        return
    if path.suffix.lower() in IMAGE_EXT:
        try:
            meta = image_metadata(path)
        except Exception:  # noqa: BLE001
            meta = None
        if meta and meta.gps:
            ui.ok(f"¡La foto tiene GPS! {meta.gps[0]}, {meta.gps[1]}: quizá no necesites la búsqueda inversa.")
            ui.links(map_links(*meta.gps), title="Ver en el mapa")
        elif meta:
            ui.info("No tiene coordenadas GPS: toca buscarla por su contenido.")
    ui.info("Los buscadores no aceptan ficheros locales por URL: te abro sus páginas y la carpeta con la foto para arrastrarla.")
    ui.reveal(path)
    ui.links(UPLOAD_PAGES, title="Sube la imagen en")
    ui.links(GEO_RESOURCES, title="Geolocalización: pistas visuales, IA y práctica")
    case.log("Búsqueda inversa", path.name, ui.md_links(UPLOAD_PAGES))


def ela(case: Case) -> None:
    ui.title("¿Imagen manipulada? (ELA)", "Error Level Analysis: resalta zonas que se han comprimido distinto.")
    path = ui.ask_path("Ruta de la imagen (mejor JPG)")
    if path.suffix.lower() not in IMAGE_EXT:
        ui.warn("Formato no soportado.")
        return
    quality_raw = ui.ask("Calidad de recompresión (75-95)", default="90")
    quality = min(max(int(quality_raw), 75), 95) if quality_raw.isdigit() else 90
    with ui.status("Calculando ELA…"):
        result, max_diff = error_level_analysis(path, quality)
        out = case.dir / f"ela_{case_slug(path.stem)}.png"
        result.save(out)
    ui.ok(f"Resultado guardado en {out}")
    ui.kv([
        ("Diferencia máxima", f"{max_diff} / 255"),
        ("Cómo leerlo", "Bordes y texturas brillan siempre. Sospecha de zonas planas que brillan mucho más que su entorno."),
        ("Falsos positivos", "Fotos pasadas por WhatsApp, recortadas o mejoradas con filtros dan resultados engañosos."),
    ])
    if path.suffix.lower() == ".png":
        ui.warn("Es un PNG (sin pérdida): el ELA es mucho menos fiable.")
    ui.open_path(out)
    ui.links(FORENSIC_RESOURCES, title="Contrasta con otras herramientas (y detectores de IA)")
    case.log("ELA", path.name, f"Diferencia máxima {max_diff}/255 con calidad {quality}. Resultado: `{out.name}`")
