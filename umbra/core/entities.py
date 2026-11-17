"""Modelo de datos: entidades, relaciones y hallazgos.

Todo lo que Umbra descubre es una de estas tres cosas:

- ``Entity``:   un nodo del grafo (dominio, IP, email, usuario...).
- ``Relation``: una arista dirigida entre dos entidades
                (``www.example.com --resolves_to--> 93.184.215.14``).
- ``Finding``:  un dato o conclusión sobre una entidad ("DMARC en p=none").
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any
from urllib.parse import urlsplit


class EntityType(StrEnum):
    DOMAIN = "domain"
    IP = "ip"
    EMAIL = "email"
    URL = "url"
    ASN = "asn"
    ORG = "org"
    USERNAME = "username"
    PHONE = "phone"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return _SEVERITY_ORDER.index(self)


_SEVERITY_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH]

_LABEL = r"(?!-)[a-z0-9_-]{1,63}(?<!-)"
_DOMAIN_RE = re.compile(rf"^(?=.{{1,253}}$)(?:{_LABEL}\.)+(?:[a-z]{{2,63}}|xn--[a-z0-9-]{{1,59}})$")
_ASN_RE = re.compile(r"^(?:as)?(\d{1,10})$", re.IGNORECASE)
_PHONE_RE = re.compile(r"^\+\d[\d\s().-]{6,20}$")
_USERNAME_RE = re.compile(r"^@?\w[\w.-]{1,63}$")
_EMAIL_LOCAL_RE = re.compile(r"^[a-z0-9!#$%&'*+/=?^_`{|}~.-]{1,64}$")


def _normalize_domain(raw: str) -> str:
    d = raw.strip().lower().rstrip(".")
    if d.startswith("*."):
        d = d[2:]
    try:
        d = d.encode("idna").decode("ascii")  # bücher.de -> xn--bcher-kva.de
    except UnicodeError as exc:
        raise ValueError(f"dominio no válido: {raw!r}") from exc
    if not _DOMAIN_RE.match(d):
        raise ValueError(f"dominio no válido: {raw!r}")
    return d


def normalize(type_: EntityType, value: str) -> str:
    """Devuelve la forma canónica de un valor, o lanza ``ValueError`` si no es válido."""
    v = value.strip()
    if not v:
        raise ValueError("valor vacío")
    match type_:
        case EntityType.DOMAIN:
            return _normalize_domain(v)
        case EntityType.IP:
            return str(ipaddress.ip_address(v))
        case EntityType.EMAIL:
            local, sep, domain = v.rpartition("@")
            local = local.lower()
            if not sep or not _EMAIL_LOCAL_RE.match(local):
                raise ValueError(f"email no válido: {value!r}")
            return f"{local}@{_normalize_domain(domain)}"
        case EntityType.ASN:
            m = _ASN_RE.match(v)
            if not m:
                raise ValueError(f"ASN no válido: {value!r}")
            return f"AS{int(m.group(1))}"
        case EntityType.URL:
            parts = urlsplit(v)
            if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
                raise ValueError(f"URL no válida: {value!r}")
            return v
        case EntityType.PHONE:
            digits = re.sub(r"[\s().-]", "", v)
            if not re.fullmatch(r"\+\d{7,15}", digits):
                raise ValueError(f"teléfono no válido (usa formato internacional +34...): {value!r}")
            return digits
        case EntityType.USERNAME:
            return v.lstrip("@")
        case _:
            return v


@dataclass(frozen=True, slots=True)
class Entity:
    type: EntityType
    value: str

    @classmethod
    def of(cls, type_: EntityType | str, value: str) -> Entity:
        """Crea una entidad normalizada. Lanza ``ValueError`` si el valor no es válido."""
        t = EntityType(type_)
        return cls(t, normalize(t, value))

    @classmethod
    def try_of(cls, type_: EntityType | str, value: str) -> Entity | None:
        """Como ``of`` pero devuelve ``None`` en vez de lanzar (útil con datos sucios)."""
        try:
            return cls.of(type_, value)
        except ValueError:
            return None

    @property
    def key(self) -> str:
        return f"{self.type}:{self.value}"

    def __str__(self) -> str:
        return self.key


def is_public_ip(entity: Entity) -> bool:
    return entity.type is EntityType.IP and ipaddress.ip_address(entity.value).is_global


def detect(raw: str) -> Entity:
    """Adivina el tipo de entidad de lo que escribe el usuario."""
    v = raw.strip()
    if not v:
        raise ValueError("objetivo vacío")
    try:
        return Entity(EntityType.IP, str(ipaddress.ip_address(v)))
    except ValueError:
        pass
    if re.match(r"^https?://", v, re.IGNORECASE):
        return Entity.of(EntityType.URL, v)
    if re.fullmatch(r"as\d{1,10}", v, re.IGNORECASE):
        return Entity.of(EntityType.ASN, v)
    if "@" in v and not v.startswith("@"):
        return Entity.of(EntityType.EMAIL, v)
    if _PHONE_RE.match(v):
        return Entity.of(EntityType.PHONE, v)
    if domain := Entity.try_of(EntityType.DOMAIN, v):
        return domain
    if _USERNAME_RE.match(v):
        return Entity.of(EntityType.USERNAME, v)
    raise ValueError(f"no sé qué tipo de entidad es {raw!r}; indícalo con --type")


@dataclass(frozen=True, slots=True)
class Relation:
    source: Entity
    target: Entity
    label: str
    module: str = ""


@dataclass(slots=True)
class Finding:
    entity: Entity
    title: str
    severity: Severity = Severity.INFO
    data: dict[str, Any] = field(default_factory=dict)
    module: str = ""


Event = Relation | Finding
