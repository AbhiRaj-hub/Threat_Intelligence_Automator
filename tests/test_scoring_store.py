from datetime import datetime, timedelta, timezone

from tia.models import IOC
from tia.scoring import score_ioc
from tia.storage import Store

SRC = {"a": {"weight": 0.6}, "b": {"weight": 0.5}, "rss": {"weight": 0.3}}
CONF = {"half_life_days": {"ip": 14}}
NOW = datetime.now(timezone.utc)


def row(sources, enr=None, age=0, typ="ip"):
    return {"sources": sources, "enrichment": enr or {}, "type": typ,
            "last_seen": (NOW - timedelta(days=age)).isoformat()}


def test_multi_source_beats_single():
    assert score_ioc(row(["a", "b"]), SRC, CONF, NOW) > score_ioc(row(["a"]), SRC, CONF, NOW)


def test_rss_prefix_weight():
    assert score_ioc(row(["rss:foo"]), SRC, CONF, NOW) == 30


def test_decay_halves_at_half_life():
    fresh = score_ioc(row(["a"]), SRC, CONF, NOW)
    assert abs(score_ioc(row(["a"], age=14), SRC, CONF, NOW) - fresh / 2) <= 1


def test_enrichment_adjusts():
    base = score_ioc(row(["a"]), SRC, CONF, NOW)
    assert score_ioc(row(["a"], {"virustotal": {"checked": True, "malicious": 20}}), SRC, CONF, NOW) > base
    assert score_ioc(row(["a"], {"virustotal": {"checked": True, "malicious": 0}}), SRC, CONF, NOW) < base
    assert score_ioc(row(["a"], {"abuseipdb": {"score": 90}}), SRC, CONF, NOW) > base


def test_upsert_merges():
    s = Store(":memory:")
    assert s.upsert(IOC("ip", "1.2.3.4", "a", tags=["x"])) is True
    assert s.upsert(IOC("ip", "1.2.3.4", "b", tags=["y"])) is False
    r = s.rows()[0]
    assert r["sources"] == ["a", "b"] and r["tags"] == ["x", "y"] and s.stats()["total"] == 1
