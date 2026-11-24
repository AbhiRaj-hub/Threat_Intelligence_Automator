from __future__ import annotations

from datetime import datetime, timezone


def _age_days(iso: str, now: datetime) -> float:
    return max((now - datetime.fromisoformat(iso)).total_seconds() / 86400, 0.0)


def source_weight(source: str, conf: dict, default: float = 0.3) -> float:
    base = source.split(":", 1)[0]  # "rss:thehackernews" -> "rss"
    return float(conf.get(base, {}).get("weight", default))


def score_ioc(row: dict, source_conf: dict, scoring_conf: dict, now: datetime | None = None) -> int:
    """0-100 confidence: noisy-OR over source weights, enrichment adjustments, exponential age decay."""
    now = now or datetime.now(timezone.utc)
    p_miss = 1.0
    for s in row["sources"]:
        p_miss *= 1 - source_weight(s, source_conf, scoring_conf.get("default_weight", 0.3))
    score = 1 - p_miss

    enr = row.get("enrichment", {})
    vt = enr.get("virustotal")
    if vt and vt.get("checked"):
        mal = vt.get("malicious", 0)
        score += 0.20 if mal >= 10 else 0.10 if mal >= 3 else (-0.15 if mal == 0 else 0)
    ab = enr.get("abuseipdb")
    if ab:
        score += 0.15 if ab.get("score", 0) >= 75 else 0.05 if ab.get("score", 0) >= 25 else 0

    half = scoring_conf.get("half_life_days", {}).get(row["type"], 30)
    decay = 0.5 ** (_age_days(row["last_seen"], now) / half)
    return round(max(0.0, min(1.0, score)) * decay * 100)


def rescore_all(store, source_conf: dict, scoring_conf: dict) -> int:
    n = 0
    for row in store.rows():
        store.set_score(row["key"], score_ioc(row, source_conf, scoring_conf))
        n += 1
    store.commit()
    return n
