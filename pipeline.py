from __future__ import annotations

import csv
import logging
from datetime import date
from pathlib import Path

import httpx

from . import collectors, enrichers
from .outputs import digest, sentinel, sigma
from .scoring import rescore_all
from .storage import Store

log = logging.getLogger(__name__)


def collect(cfg, store: Store, client: httpx.Client | None = None, collector_list=None) -> dict:
    client = client or httpx.Client()
    stats = {}
    for c in collector_list if collector_list is not None else collectors.build(cfg):
        try:
            iocs = c.fetch(client)
        except Exception as exc:  # isolate collector failures
            log.error("collector %s failed: %s", c.name, exc)
            stats[c.name] = {"error": str(exc)}
            continue
        new = sum(store.upsert(i) for i in iocs)
        stats[c.name] = {"fetched": len(iocs), "new": new}
        log.info("%s: fetched=%d new=%d", c.name, len(iocs), new)
    return stats


def score(cfg, store: Store) -> int:
    return rescore_all(store, cfg.sources, cfg.scoring)


def enrich(cfg, store: Store, client=None) -> int:
    e = cfg.scoring.get("enrichment", {})
    return enrichers.enrich_pending(store, enrichers.build(cfg), e.get("budget_per_run", 25),
                                    e.get("min_score", 30), client)


def export(cfg, store: Store, out_dir: str | None = None) -> dict:
    out = Path(out_dir or cfg.out_dir)
    publish_at = cfg.scoring.get("publish_threshold", 70)
    review_at = cfg.scoring.get("review_threshold", 40)
    all_rows = store.rows()
    publish = [r for r in all_rows if r["score"] >= publish_at]
    review = [r for r in all_rows if review_at <= r["score"] < publish_at]

    for sub in ("sigma", "sentinel", "blocklists"):
        (out / sub).mkdir(parents=True, exist_ok=True)

    (out / f"digest-{date.today().isoformat()}.md").write_text(digest.build(all_rows, publish_at, review_at), encoding="utf-8")
    for name, text in sigma.render(sigma.build_rules(publish)).items():
        (out / "sigma" / name).write_text(text, encoding="utf-8")
    (out / "sentinel" / f"{sentinel.WATCHLIST_ALIAS}.csv").write_text(sentinel.watchlist_csv(publish), encoding="utf-8")
    (out / "sentinel" / "queries.kql").write_text(sentinel.KQL, encoding="utf-8")
    for t, fname in (("ip", "ips.txt"), ("domain", "domains.txt"), ("url", "urls.txt")):
        (out / "blocklists" / fname).write_text("\n".join(r["value"] for r in publish if r["type"] == t) + "\n", encoding="utf-8")
    with open(out / "review_queue.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["score", "type", "value", "sources", "tags", "context"])
        for r in review:
            w.writerow([r["score"], r["type"], r["value"], ";".join(r["sources"]), ";".join(r["tags"]), r["context"]])
    return {"published": len(publish), "review": len(review), "out_dir": str(out)}


def run_once(cfg, store: Store, client=None) -> dict:
    result = {"collect": collect(cfg, store, client)}
    result["scored"] = score(cfg, store)       # pre-score so enrichment targets the best candidates
    result["enrich_calls"] = enrich(cfg, store, client)
    result["rescored"] = score(cfg, store)
    result["export"] = export(cfg, store)
    return result
