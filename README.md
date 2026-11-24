# Threat Intel Automator

Collects threat intelligence, normalizes and scores indicators, optionally enriches them, and emits
detection-ready output: **Sigma rules**, **Microsoft Sentinel watchlist + KQL**, blocklists and a daily digest.

```
Collectors → Normalize/Dedupe → Store (SQLite) → Enrich (VT, AbuseIPDB) → Score → Export
 urlhaus        defang, validate,     merge sources      cached, budgeted      noisy-OR +     Sigma / KQL /
 feodo          allowlist, dedupe     per indicator      free-tier friendly    age decay      blocklists / digest
 cisa_kev / rss
```

## Quick start
```bash
pip install -r requirements.txt
cp .env.example .env            # API keys; auto-loaded (Windows: copy .env.example .env)
python -m tia run               # collect -> score -> enrich -> rescore -> export
python -m tia watch --every 60  # run hourly
python -m tia stats
```
Docker: `docker compose up -d --build`

Individual stages: `collect`, `score`, `enrich`, `export`.

## Output (`output/`)
| Path | Contents |
|---|---|
| `digest-YYYY-MM-DD.md` | Counts, new KEVs, top indicators (defanged) |
| `sigma/*.yml` | DNS, network, proxy and process-hash rules (deterministic UUIDs, max 500 values/rule) |
| `sentinel/TIA-IOCs.csv` | Watchlist (alias `TIA-IOCs`, SearchKey = `SearchKey`) |
| `sentinel/queries.kql` | Hunting queries joining the watchlist to DNS / network / file events |
| `blocklists/{ips,domains,urls}.txt` | Plain blocklists |
| `review_queue.csv` | Medium-confidence IOCs for analyst approval |

## Review gate
Score >= `publish_threshold` (70) is auto-published. `review_threshold` (40) to 69 goes to `review_queue.csv`.
Tune in `config/scoring.yaml`. Source trust weights are in `config/sources.yaml`.

## Scoring
`confidence = (1 - Π(1 - source_weight)) ± enrichment`, multiplied by `0.5^(age_days / half_life)` per IOC type.
Independent sources corroborate each other; stale IOCs fade out automatically.

## Add a source
1. Create `tia/collectors/mysource.py` subclassing `Collector` (implement a pure `parse()` and `fetch()`).
2. Register it in `tia/collectors/__init__.py`.
3. Add it to `config/sources.yaml` with a weight.

## Notes
- **URLhaus needs a free Auth-Key** (https://auth.abuse.ch/). Put `ABUSECH_AUTH_KEY=...` in `.env`; without it the collector is reported as `skipped`. The key sits in the export URL path, so keep it out of logs and screenshots (httpx request logging is muted for this reason).
- Domain/IP blocklists can hit shared hosting or CDNs. Keep `config/allowlist.yaml` current and review before enforcing.
- RSS sources only yield URLs/domains the author defanged, to avoid turning article links into IOCs.
- Tests: `pip install -r requirements-dev.txt && pytest`

## Roadmap
FastAPI + dashboard, STIX 2.1 / MISP export, OTX collector, ATT&CK technique mapping, Teams/Slack alerting.
