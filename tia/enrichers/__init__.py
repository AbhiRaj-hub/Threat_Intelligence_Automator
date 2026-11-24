from __future__ import annotations

import logging

import httpx

from .abuseipdb import AbuseIPDB
from .virustotal import VirusTotal

log = logging.getLogger(__name__)
CACHE_TTL = 7 * 86400


def build(cfg):
    ens = [VirusTotal(cfg.keys.get("virustotal", "")), AbuseIPDB(cfg.keys.get("abuseipdb", ""))]
    return [e for e in ens if e.enabled()]


def enrich_pending(store, enrichers, budget: int = 25, min_score: int = 30,
                   client: httpx.Client | None = None) -> int:
    """Enrich the highest-scoring un-enriched IOCs, bounded by an API-call budget."""
    if not enrichers:
        return 0
    client = client or httpx.Client()
    calls = 0
    for row in store.rows(min_score=min_score):
        for en in enrichers:
            if calls >= budget:
                return calls
            if row["type"] not in en.types or en.name in row["enrichment"]:
                continue
            ck = f"{en.name}:{row['key']}"
            data = store.cache_get(ck, CACHE_TTL)
            if data is None:
                try:
                    data = en.lookup(client, row["type"], row["value"])
                except Exception as exc:  # one bad lookup must not kill the run
                    log.warning("%s lookup failed for %s: %s", en.name, row["key"], exc)
                    continue
                calls += 1
                if data is not None:
                    store.cache_set(ck, data)
            if data is not None:
                store.set_enrichment(row["key"], en.name, data)
    return calls
