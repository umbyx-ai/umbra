"""Pruebas del motor con módulos falsos: sin red."""

import asyncio

from umbra.core.context import Context
from umbra.core.engine import Engine
from umbra.core.entities import Entity, Severity
from umbra.core.entities import EntityType as T
from umbra.core.module import Module
from umbra.core.scope import Scope
from umbra.core.storage import Store

CALLS: list[str] = []


class FakeDns(Module):
    name = "fake_dns"
    description = "test"
    consumes = frozenset({T.DOMAIN})

    async def run(self, entity, ctx):
        CALLS.append(entity.value)
        if entity.value == "example.com":
            yield self.link(entity, Entity.of(T.DOMAIN, "www.example.com"), "subdomain")
            yield self.link(entity, Entity.of(T.DOMAIN, "mx.thirdparty.org"), "mail_server")
            yield self.finding(entity, "Sin registro DMARC", Severity.MEDIUM)
        yield self.link(entity, Entity.of(T.IP, "93.184.215.14"), "resolves_to")


class Boom(Module):
    name = "boom"
    description = "test"
    consumes = frozenset({T.IP})

    async def run(self, entity, ctx):
        raise RuntimeError("se rompió")
        yield  # pragma: no cover


def run_engine(tmp_path, depth):
    CALLS.clear()
    seed = Entity.of(T.DOMAIN, "example.com")
    ctx = Context(http=None, dns=None, scope=Scope.from_seed(seed))
    store = Store(tmp_path / "case.db")
    engine = Engine([FakeDns(), Boom()], ctx, store, max_depth=depth)
    stats = asyncio.run(engine.investigate(seed))
    return store, stats


def test_pivots_inside_scope_only(tmp_path):
    store, stats = run_engine(tmp_path, depth=3)
    assert sorted(CALLS) == ["example.com", "www.example.com"]  # el MX de terceros no se expande
    keys = {e["key"] for e in store.entities()}
    assert {"domain:example.com", "domain:www.example.com", "domain:mx.thirdparty.org", "ip:93.184.215.14"} <= keys
    assert stats.findings == 1


def test_failing_module_is_recorded_not_fatal(tmp_path):
    store, stats = run_engine(tmp_path, depth=3)
    assert stats.errors == 1  # la IP se expande una sola vez aunque la descubran dos dominios
    assert store.errors()[0]["message"] == "se rompió"


def test_depth_limit(tmp_path):
    _, stats = run_engine(tmp_path, depth=0)
    assert CALLS == ["example.com"]
    assert stats.errors == 0  # la IP (profundidad 1) no llega a expandirse
