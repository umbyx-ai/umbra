"""Tests de la lógica pura de las herramientas del menú (sin red)."""

import base64
import hashlib
import zipfile

from PIL import Image

from umbra import lookups
from umbra.tools import archive, devices, dnsmail, dorks, egosurf, emails, favicon, images, leaks, metadata, subdomains
from umbra.tools.probe import ProbeResult, extract_title, parse_hosts
from umbra.tools.usernames import SITES, Site, evaluate
from umbra.tools.whois import summarize_prefixes

# --- buscadores ----------------------------------------------------------------


def test_build_dork():
    parts = dorks.DorkParts(site="example.com", filetypes=["pdf", "docx"], intitle="index of",
                            phrase="curriculum vitae", exclude=["www.example.com"])
    assert dorks.build_dork(parts) == (
        'site:example.com (filetype:pdf | filetype:docx) intitle:"index of" "curriculum vitae" -www.example.com'
    )
    assert dorks.build_dork(dorks.DorkParts()) == ""


def test_domain_templates_and_links():
    templates = dorks.domain_templates("example.com", "Example")
    assert all("example" in q.lower() for _, _, q in templates)
    assert dorks.search_links("a b")[0][1] == "https://www.google.com/search?q=a+b"


def test_device_query_and_fofa_base64():
    assert devices.build_query("camera", {"country": "ES", "city": "La Rapita", "port": ""}) == 'camera country:ES city:"La Rapita"'
    fofa = dict(devices.engine_links('title="x"'))["FOFA"]
    assert base64.b64encode(b'title="x"').decode().replace("=", "%3D") in fofa


# --- infraestructura -----------------------------------------------------------


def test_parse_soa():
    soa = dnsmail.parse_soa("ns1.example.com. john\\.doe.example.com. 2024031501 7200 3600 1209600 3600")
    assert soa["servidor_primario"] == "ns1.example.com"
    assert soa["contacto"] == "john.doe@example.com"
    assert soa["ultima_modificacion"] == "15/03/2024"


def test_spf_ranges_and_mail_verdict():
    assert dnsmail.spf_ranges(["v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 include:x.com -all"]) == [
        "192.0.2.0/24", "2001:db8::/32"]
    assert "Google Workspace" in dnsmail.mail_verdict("ex.com", [(1, "aspmx.l.google.com")], set(), [])
    assert "on-premise" in dnsmail.mail_verdict("ex.com", [(10, "mail.ex.com")], set(), ["OVH SAS"])
    assert "no recibe" in dnsmail.mail_verdict("ex.com", [], set(), [])


def test_interesting_subdomains():
    assert subdomains.interesting("vpn2.corp.example.com", "example.com") == [
        "acceso remoto (vpn)", "administración (corp)"]
    assert subdomains.interesting("www.example.com", "example.com") == []
    assert subdomains.interesting("dev-api.example.com", "example.com") == ["desarrollo/pruebas (dev)", "APIs (api)"]


def test_passive_dns_parsers():
    assert lookups.parse_hackertarget("a.example.com,1.2.3.4\nother.org,5.6.7.8\n", "example.com") == {
        "a.example.com": "1.2.3.4"}
    text = ";;Subdomains For: \x1b[0;36mexample\x1b[0m.com\nwww.example.com\nmail.example.com\nevil.org\n"
    assert lookups.parse_thc(text, "example.com") == {"www.example.com", "mail.example.com"}


def test_whois_highlights_and_rdap_ip():
    text = "% comentario\nRegistrar: Ejemplo S.L.\nRegistrant Organization: ACME\nRegistrar: Ejemplo S.L.\nFoo: bar\n"
    assert lookups.whois_highlights(text) == [("Registrar", "Ejemplo S.L."), ("Registrant Organization", "ACME")]
    rdap = {
        "name": "CLOUDFLARENET", "startAddress": "1.1.1.0", "endAddress": "1.1.1.255", "country": "AU",
        "cidr0_cidrs": [{"v4prefix": "1.1.1.0", "length": 24}],
        "entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "Cloudflare, Inc."]]],
                      "entities": [{"roles": ["abuse"], "vcardArray": ["vcard", [["email", {}, "text", "abuse@cf.com"]]]}]}],
    }
    info = lookups.parse_rdap_ip(rdap)
    assert info["organizacion"] == "Cloudflare, Inc."
    assert info["cidr"] == ["1.1.1.0/24"]
    assert info["abuse"] == ["abuse@cf.com"]


def test_prefix_summary_sorted():
    v4, v6 = summarize_prefixes(["10.0.0.0/8", "2001:db8::/32", "1.1.1.0/24"])
    assert v4 == ["1.1.1.0/24", "10.0.0.0/8"] and v6 == ["2001:db8::/32"]


def test_wayback_helpers():
    rows = [["timestamp", "original", "statuscode"], ["20200101000000", "https://ex.com/api/v1/users?id=1&debug=1", "200"]]
    parsed = archive.parse_cdx(rows)
    assert parsed == [("20200101000000", "https://ex.com/api/v1/users?id=1&debug=1", "200")]
    urls = [u for _, u, _ in parsed]
    assert archive.api_endpoints(urls) == ["ex.com/api/v1/users"]
    assert set(archive.parameters(urls)) == {"id", "debug"}


def test_murmur3_matches_mmh3_reference():
    assert favicon.murmur3_32(b"foo") == -156908512  # mmh3.hash("foo")
    assert favicon.favicon_hash(b"\x00\x01") == 454610886  # mmh3.hash(base64.encodebytes(b"\x00\x01"))


def test_icon_urls():
    html = '<link rel="shortcut icon" href="/static/fav.png"><link rel="stylesheet" href="x.css">'
    assert favicon.icon_urls(html, "https://ex.com/a/") == ["https://ex.com/static/fav.png", "https://ex.com/favicon.ico"]


def test_probe_helpers():
    assert parse_hosts("https://a.example.com/login, b.example.com\n1.1.1.1 nope!") == [
        "a.example.com", "b.example.com", "1.1.1.1"]
    assert extract_title("<html><title>\n Iniciar sesión &amp; más </title>") == "Iniciar sesión & más"
    assert ProbeResult("x", status=403, title="Admin Panel").flags == ["restringido (403)", "posible panel de acceso"]


# --- IMINT ---------------------------------------------------------------------


def _jpeg_with_gps(path):
    img = Image.new("RGB", (64, 48), "white")
    exif = img.getexif()
    exif[0x010F] = "UmbraCam"  # Make
    exif[0x0110] = "Modelo X"  # Model
    gps = exif.get_ifd(0x8825)
    gps.update({1: "N", 2: (40.0, 34.0, 24.6), 3: "E", 4: (0.0, 35.0, 58.2)})
    img.save(path, exif=exif)


def test_image_metadata_gps_and_strip(tmp_path):
    path = tmp_path / "foto.jpg"
    _jpeg_with_gps(path)
    meta = metadata.analyze(path)
    assert meta.fields["Fabricante"] == "UmbraCam"
    assert meta.gps == (40.5735, 0.5995)
    clean = metadata.strip_image(path)
    after = metadata.image_metadata(clean)
    assert after.gps is None and "Fabricante" not in after.fields


def test_dms_to_decimal_south_west():
    assert metadata.dms_to_decimal((33, 51, 54), "S") == -33.865
    assert metadata.dms_to_decimal("roto", "N") is None


def test_office_metadata(tmp_path):
    path = tmp_path / "informe.docx"
    core = (
        '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
        'xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:creator>jgarcia</dc:creator>'
        "<cp:lastModifiedBy>Administrador</cp:lastModifiedBy></cp:coreProperties>"
    )
    app = '<Properties xmlns="x"><Application>Microsoft Office Word</Application><Company>ACME</Company></Properties>'
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("docProps/core.xml", core)
        z.writestr("docProps/app.xml", app)
    meta = metadata.analyze(path)
    assert meta.fields["Autor"] == "jgarcia"
    assert meta.values(metadata.PEOPLE_KEYS) == {"jgarcia", "Administrador"}
    assert meta.fields["Empresa"] == "ACME"


def test_broken_file_does_not_crash(tmp_path):
    path = tmp_path / "roto.pdf"
    path.write_bytes(b"esto no es un pdf")
    assert metadata.analyze(path).kind == "error"


def test_ela_and_reverse_links(tmp_path):
    path = tmp_path / "a.jpg"
    Image.new("RGB", (32, 32), "red").save(path, quality=80)
    result, max_diff = images.error_level_analysis(path)
    assert result.size == (32, 32) and max_diff >= 1
    links = dict(images.reverse_links("https://x.com/a b.jpg"))
    assert links["TinEye"] == "https://tineye.com/search?url=https%3A%2F%2Fx.com%2Fa%20b.jpg"


# --- SOCMINT -------------------------------------------------------------------


def test_extract_emails():
    text = 'Escríbenos a <a href="mailto:Info@Example.com">info</a>, juan [at] example [dot] com · logo@2x.png'
    assert emails.extract_emails(text) == {"info@example.com", "juan@example.com"}


def test_email_permutations_and_pattern():
    perms = emails.permutations("José Luis", "García", "Pérez", "acme.es")
    assert perms[:3] == ["jose@acme.es", "jose.garcia@acme.es", "josegarcia@acme.es"]
    assert "jgarciaperez@acme.es" in perms and "joseluis.garcia@acme.es" in perms
    assert len(perms) == len(set(perms))
    assert emails.infer_pattern(["ana.lopez@a.es", "pep.ruiz@a.es", "info@a.es"]) == "{nombre}.{apellido}"
    assert emails.infer_pattern(["dmarc-ruf@iana.org", "iana@iana.org"]) is None


def test_role_accounts():
    assert emails.is_role("dmarc-ruf@iana.org") and emails.is_role("iana@iana.org") and emails.is_role("info@x.es")
    assert not emails.is_role("ana.lopez@acme.es")


def test_gravatar_hash():
    assert lookups.gravatar_md5(" Test@Example.com ") == hashlib.md5(b"test@example.com").hexdigest()


def test_username_evaluation():
    status = Site("A", "x", "https://a/{u}")
    assert evaluate(status, 200, "") is True
    assert evaluate(status, 404, "") is False
    assert evaluate(status, 429, "") is None
    text = Site("B", "x", "https://b/{u}", method="missing_text", text="not found")
    assert evaluate(text, 200, "user not found here") is False
    jsonl = Site("C", "x", "https://c/{u}", method="json_list")
    assert evaluate(jsonl, 200, "[]") is False and evaluate(jsonl, 200, '[{"id":1}]') is True
    assert len({s.name for s in SITES}) == len(SITES)


def test_pwned_passwords_parsing():
    suffix = hashlib.sha1(b"password").hexdigest().upper()[5:]
    body = f"0018A45C4D1DEF81644B54AB7F969B88D65:1\n{suffix}:52256179\nFFFF:0\n"
    assert leaks.pwned_count(body, suffix) == 52256179
    assert leaks.pwned_count(body, "NOPE") == 0


def test_parse_xon():
    data = {"ExposedBreaches": {"breaches_details": [{"breach": "Adobe"}]}, "ExposedPastes": [1, 2]}
    assert leaks.parse_xon(data) == ([{"breach": "Adobe"}], 2)
    assert leaks.parse_xon(None) == ([], 0)


def test_egosurf_dorks():
    assert egosurf.phone_variants("+34 600 11 22 33")[0] == "600112233"
    dorks_ = dict(egosurf.ego_dorks(name="Ana López", dni="12345678Z"))
    assert dorks_["Tu nombre"] == '"Ana López"'
    assert dorks_["Tu DNI"] == '"12345678Z" | "12345678"'
    assert egosurf.ego_dorks() == []
