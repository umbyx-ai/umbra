from umbra.core.entities import Severity
from umbra.modules.crtsh import parse_crtsh
from umbra.modules.dns_records import analyze_dmarc, analyze_spf, dmarc_report_emails
from umbra.modules.rdap import parse_rdap_domain
from umbra.modules.wayback import classify_urls


def titles(checks):
    return {c.title: c.severity for c in checks}


def test_parse_crtsh():
    data = [
        {"name_value": "www.example.com\n*.api.example.com", "common_name": "example.com"},
        {"name_value": "EXAMPLE.com\nadmin@example.com\nother.org\nssl@ca.org", "common_name": "mail.example.com"},
    ]
    subs, emails = parse_crtsh(data, "example.com")
    assert subs == {"www.example.com", "api.example.com", "mail.example.com"}
    assert emails == {"admin@example.com"}


def test_spf_missing():
    assert titles(analyze_spf(["google-site-verification=abc"])) == {"Sin registro SPF": Severity.LOW}


def test_spf_softfail_and_senders():
    checks = analyze_spf(["v=spf1 include:_spf.google.com include:sendgrid.net ~all"])
    assert titles(checks)["SPF en modo softfail (~all)"] is Severity.INFO
    senders = next(c for c in checks if c.title.startswith("Servicios"))
    assert senders.data["servicios"] == ["Google Workspace", "SendGrid"]


def test_spf_plus_all_is_high():
    assert Severity.HIGH in titles(analyze_spf(["v=spf1 a mx +all"])).values()
    assert Severity.HIGH in titles(analyze_spf(["v=spf1 all"])).values()


def test_spf_duplicated():
    checks = analyze_spf(["v=spf1 -all", "v=spf1 ~all"])
    assert checks[0].severity is Severity.MEDIUM


def test_spf_redirect_without_all_is_fine():
    assert titles(analyze_spf(["v=spf1 redirect=_spf.example.com"])) == {}


def test_dmarc():
    assert titles(analyze_dmarc([]))["Sin registro DMARC"] is Severity.MEDIUM
    none = ["v=DMARC1; p=none; rua=mailto:d@example.com,mailto:x@rua.agari.com!10m"]
    assert analyze_dmarc(none)[0].severity is Severity.LOW
    assert dmarc_report_emails(none) == ["d@example.com", "x@rua.agari.com"]
    assert analyze_dmarc(["v=DMARC1; p=reject"])[0].severity is Severity.INFO


def test_parse_rdap_domain():
    data = {
        "events": [
            {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2027-08-13T04:00:00Z"},
        ],
        "entities": [{
            "roles": ["registrar"],
            "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Registrar S.A."]]],
        }],
        "nameservers": [{"ldhName": "A.IANA-SERVERS.NET"}],
        "secureDNS": {"delegationSigned": True},
        "status": ["client delete prohibited"],
    }
    info = parse_rdap_domain(data)
    assert info["registrador"] == "Registrar S.A."
    assert info["creado"] == "1995-08-14T04:00:00Z"
    assert info["nameservers"] == ["a.iana-servers.net"]
    assert info["dnssec"] is True


def test_classify_urls():
    result = classify_urls(
        [
            "http://www.example.com/",
            "https://dev.example.com:8443/docs/manual.PDF",
            "https://example.com/backup/db.sql",
            "https://example.com/wp-login.php",
            "https://example.com/administrators-guide",
            "http://[broken",
        ],
        "example.com",
    )
    assert result.hosts == {"www.example.com", "dev.example.com"}
    assert list(result.documents) == ["https://dev.example.com:8443/docs/manual.PDF"]
    assert list(result.sensitive) == ["https://example.com/backup/db.sql"]
    assert list(result.logins) == ["https://example.com/wp-login.php"]
