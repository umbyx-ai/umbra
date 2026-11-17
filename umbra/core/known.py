"""Base de conocimiento: huellas de proveedores y servicios conocidos.

Ampliar estas tablas es la forma más fácil de que Umbra "sepa" más cosas
sin tocar la lógica de los módulos.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence

Table = Sequence[tuple[re.Pattern[str], str]]


def _compile(rows: Iterable[tuple[str, str]]) -> list[tuple[re.Pattern[str], str]]:
    return [(re.compile(pattern, re.IGNORECASE), name) for pattern, name in rows]


def match_provider(value: str, table: Table) -> str | None:
    for pattern, name in table:
        if pattern.search(value):
            return name
    return None


FREE_EMAIL_PROVIDERS = frozenset({
    "gmail.com", "googlemail.com", "outlook.com", "outlook.es", "hotmail.com", "hotmail.es",
    "live.com", "msn.com", "yahoo.com", "yahoo.es", "icloud.com", "me.com", "proton.me",
    "protonmail.com", "gmx.com", "gmx.es", "aol.com", "yandex.com", "zoho.com",
    "tutanota.com", "mail.com",
})

# Host MX -> proveedor de correo
MX_PROVIDERS = _compile([
    (r"(^|\.)(google|googlemail)\.com$", "Google Workspace"),
    (r"\.mail\.protection\.outlook\.com$", "Microsoft 365"),
    (r"\.pphosted\.com$", "Proofpoint"),
    (r"\.mimecast\.com$", "Mimecast"),
    (r"\.iphmx\.com$", "Cisco Secure Email"),
    (r"\.messagelabs\.com$", "Symantec Email Security"),
    (r"\.barracudanetworks\.com$", "Barracuda"),
    (r"\.zoho\.(com|eu|in)$", "Zoho Mail"),
    (r"\.protonmail\.ch$", "Proton Mail"),
    (r"\.icloud\.com$", "iCloud Mail"),
    (r"\.mailgun\.org$", "Mailgun"),
    (r"\.amazonaws\.com$", "Amazon SES / WorkMail"),
    (r"\.ovh\.net$", "OVHcloud"),
    (r"\.ionos\.(es|com|de|fr|co\.uk)$", "IONOS"),
    (r"\.secureserver\.net$", "GoDaddy"),
    (r"\.yandex\.(net|ru)$", "Yandex 360"),
])

# Host NS -> proveedor DNS
NS_PROVIDERS = _compile([
    (r"\.ns\.cloudflare\.com$", "Cloudflare"),
    (r"\.awsdns-\d+\.(com|net|org|co\.uk)$", "AWS Route 53"),
    (r"\.azure-dns\.(com|net|org|info)$", "Azure DNS"),
    (r"\.googledomains\.com$", "Google Cloud DNS"),
    (r"\.domaincontrol\.com$", "GoDaddy"),
    (r"\.ovh\.net$", "OVHcloud"),
    (r"\.ui-dns\.(com|org|de|biz)$", "IONOS"),
    (r"\.akam\.net$", "Akamai"),
    (r"\.nsone\.net$", "NS1"),
    (r"\.dnsmadeeasy\.com$", "DNS Made Easy"),
    (r"\.digitalocean\.com$", "DigitalOcean"),
    (r"\.registrar-servers\.com$", "Namecheap"),
    (r"\.hostinger\.com$", "Hostinger"),
])

# include:/redirect= de SPF -> servicio que envía correo en nombre del dominio
SPF_SENDERS = _compile([
    (r"(^|\.)_spf\.google\.com$", "Google Workspace"),
    (r"(^|\.)spf\.protection\.outlook\.com$", "Microsoft 365"),
    (r"(^|\.)sendgrid\.net$", "SendGrid"),
    (r"(^|\.)mailgun\.org$", "Mailgun"),
    (r"(^|\.)mcsv\.net$", "Mailchimp"),
    (r"(^|\.)mandrillapp\.com$", "Mailchimp Transactional"),
    (r"(^|\.)amazonses\.com$", "Amazon SES"),
    (r"(^|\.)(salesforce|exacttarget)\.com$", "Salesforce"),
    (r"(^|\.)zendesk\.com$", "Zendesk"),
    (r"(^|\.)hubspotemail\.net$", "HubSpot"),
    (r"(^|\.)zoho\.(com|eu)$", "Zoho"),
    (r"(^|\.)freshdesk\.com$", "Freshdesk"),
    (r"(^|\.)sparkpostmail\.com$", "SparkPost"),
    (r"(^|\.)mailjet\.com$", "Mailjet"),
    (r"(^|\.)(sendinblue|brevo)\.com$", "Brevo"),
    (r"(^|\.)pphosted\.com$", "Proofpoint"),
    (r"(^|\.)mimecast\.com$", "Mimecast"),
])

# Prefijo de registro TXT de verificación -> servicio de terceros que usa la organización
TXT_VERIFICATIONS: list[tuple[str, str]] = [
    ("google-site-verification=", "Google (Search Console / Workspace)"),
    ("ms=", "Microsoft 365"),
    ("facebook-domain-verification=", "Meta / Facebook"),
    ("apple-domain-verification=", "Apple"),
    ("atlassian-domain-verification=", "Atlassian"),
    ("docusign=", "DocuSign"),
    ("adobe-idp-site-verification=", "Adobe"),
    ("stripe-verification=", "Stripe"),
    ("zoom_verify_", "Zoom"),
    ("globalsign-domain-verification=", "GlobalSign"),
    ("onetrust-domain-verification=", "OneTrust"),
    ("dropbox-domain-verification=", "Dropbox"),
    ("yandex-verification", "Yandex"),
    ("cisco-ci-domain-verification=", "Cisco"),
    ("webexdomainverification", "Cisco Webex"),
    ("amazonses:", "Amazon SES"),
    ("knowbe4-site-verification=", "KnowBe4"),
    ("openai-domain-verification=", "OpenAI"),
    ("have-i-been-pwned-verification=", "Have I Been Pwned"),
    ("teamviewer-sso-verification=", "TeamViewer"),
    ("postman-domain-verification=", "Postman"),
    ("mongodb-site-verification=", "MongoDB Atlas"),
]


def match_verifications(txts: Iterable[str]) -> list[str]:
    found: list[str] = []
    for txt in txts:
        t = txt.strip().lower()
        for prefix, service in TXT_VERIFICATIONS:
            if t.startswith(prefix) and service not in found:
                found.append(service)
    return found


# Titular de un ASN -> CDN / cloud (IPs compartidas: cuidado al atribuirlas)
HOSTING_ORGS = _compile([
    (r"cloudflare", "Cloudflare"),
    (r"akamai", "Akamai"),
    (r"amazon|aws", "Amazon Web Services"),
    (r"google", "Google Cloud"),
    (r"microsoft", "Microsoft Azure"),
    (r"fastly", "Fastly"),
    (r"incapsula|imperva", "Imperva"),
    (r"sucuri", "Sucuri"),
    (r"ovh", "OVHcloud"),
    (r"hetzner", "Hetzner"),
    (r"digitalocean", "DigitalOcean"),
    (r"linode|akamai connected cloud", "Linode / Akamai Cloud"),
    (r"oracle", "Oracle Cloud"),
])

# Puertos que no deberían estar abiertos a Internet sin una buena razón
RISKY_PORTS = {
    21: "FTP", 23: "Telnet", 135: "MS RPC", 139: "NetBIOS", 161: "SNMP", 445: "SMB",
    1433: "MS SQL Server", 1521: "Oracle DB", 2375: "Docker API sin TLS", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5601: "Kibana", 5900: "VNC", 5985: "WinRM",
    6379: "Redis", 8291: "MikroTik Winbox", 9200: "Elasticsearch", 11211: "Memcached",
    27017: "MongoDB",
}
