import pytest

from umbra.core.entities import Entity, detect
from umbra.core.entities import EntityType as T
from umbra.core.scope import Scope


@pytest.mark.parametrize(
    ("raw", "type_", "value"),
    [
        ("Example.COM.", T.DOMAIN, "example.com"),
        ("*.dev.example.com", T.DOMAIN, "dev.example.com"),
        ("bücher.de", T.DOMAIN, "xn--bcher-kva.de"),
        ("8.8.8.8", T.IP, "8.8.8.8"),
        ("2001:4860:4860:0000::8888", T.IP, "2001:4860:4860::8888"),
        ("Admin@Example.com", T.EMAIL, "admin@example.com"),
        ("as13335", T.ASN, "AS13335"),
        ("https://example.com/login", T.URL, "https://example.com/login"),
        ("+34 600 11 22 33", T.PHONE, "+34600112233"),
        ("@some_user", T.USERNAME, "some_user"),
    ],
)
def test_detect(raw, type_, value):
    entity = detect(raw)
    assert entity.type is type_
    assert entity.value == value


@pytest.mark.parametrize("raw", ["", "no es nada!!", "-bad-.com"])
def test_detect_rejects_garbage(raw):
    with pytest.raises(ValueError):
        detect(raw)


def test_try_of_returns_none_on_invalid():
    assert Entity.try_of(T.DOMAIN, "not a domain") is None
    assert Entity.try_of(T.IP, "999.1.1.1") is None


def test_scope_domain():
    scope = Scope.from_seed(Entity.of(T.DOMAIN, "example.com"))
    assert scope.allows_expansion(Entity.of(T.DOMAIN, "a.b.example.com"))
    assert scope.allows_expansion(Entity.of(T.EMAIL, "info@example.com"))
    assert not scope.allows_expansion(Entity.of(T.DOMAIN, "notexample.com"))
    assert not scope.allows_expansion(Entity.of(T.DOMAIN, "example.com.evil.org"))
    assert scope.allows_expansion(Entity.of(T.IP, "1.1.1.1"))


def test_scope_ignores_free_email_providers():
    assert Scope.from_seed(Entity.of(T.EMAIL, "someone@gmail.com")).roots == frozenset()
    assert Scope.from_seed(Entity.of(T.EMAIL, "someone@example.com")).roots == {"example.com"}


def test_scope_extra_roots():
    scope = Scope.from_seed(Entity.of(T.DOMAIN, "example.com"), extra=["Example.ORG"])
    assert scope.roots == {"example.com", "example.org"}
