import csv

import yaml

from tia import config, pipeline
from tia.collectors.base import Collector
from tia.models import IOC
from tia.outputs import sentinel, sigma
from tia.storage import Store


class Fake(Collector):
    name = "feodo"

    def fetch(self, client):
        return [IOC("ip", "45.9.9.9", "feodo"), IOC("domain", "evil.xyz", "feodo"),
                IOC("sha256", "d" * 64, "feodo"), IOC("url", "http://bad.test/x", "feodo"),
                IOC("domain", "meh.top", "rss:blog")]


class Boom(Collector):
    name = "boom"

    def fetch(self, client):
        raise RuntimeError("down")


def test_end_to_end(tmp_path):
    cfg = config.load("config")
    store = Store(":memory:")
    stats = pipeline.collect(cfg, store, collector_list=[Fake({}, set()), Boom({}, set())])
    assert stats["feodo"]["new"] == 5 and "error" in stats["boom"]  # failures are isolated
    pipeline.score(cfg, store)
    res = pipeline.export(cfg, store, str(tmp_path))
    assert res["published"] == 4 and res["review"] == 0  # rss-only domain (35) is below review (40)

    for f in (tmp_path / "sigma").glob("*.yml"):
        r = yaml.safe_load(f.read_text())
        assert r["title"] and r["logsource"] and r["detection"]["condition"] and r["level"]
    assert (tmp_path / "blocklists" / "ips.txt").read_text().strip() == "45.9.9.9"
    rows = list(csv.reader((tmp_path / "sentinel" / "TIA-IOCs.csv").open()))
    assert rows[0][0] == "SearchKey" and len(rows) == 5
    assert "evil.xyz" in (tmp_path / "sigma" / "tia_dns_domains_1.yml").read_text()
    assert list(tmp_path.glob("digest-*.md"))


def test_sigma_ids_deterministic():
    rows = [{"type": "ip", "value": "1.1.1.1", "score": 90}]
    a, b = sigma.build_rules(rows), sigma.build_rules(rows)
    assert a["tia_net_ips_1.yml"]["id"] == b["tia_net_ips_1.yml"]["id"]


def test_kql_references_watchlist():
    assert sentinel.WATCHLIST_ALIAS in sentinel.KQL


def test_dotenv_loading(tmp_path, monkeypatch):
    (tmp_path / ".env").write_text('\ufeff# c\nABUSECH_AUTH_KEY="abc"\nVT_API_KEY=xyz\n', encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ABUSECH_AUTH_KEY", raising=False)
    monkeypatch.delenv("VT_API_KEY", raising=False)
    config.load_dotenv()
    import os
    assert os.environ["ABUSECH_AUTH_KEY"] == "abc" and os.environ["VT_API_KEY"]
