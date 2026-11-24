"""Generate Sigma rules from high-confidence IOCs (detection-as-code)."""
from __future__ import annotations

import uuid
from datetime import date

import yaml

MAX_VALUES = 500
NS = uuid.UUID("6f1c3d9e-2b7a-4c55-9a1e-7d3f5a8b9c01")


def _rule(title, desc, logsource, detection, level, tags, values):
    rid = uuid.uuid5(NS, title + "|" + "|".join(sorted(map(str, values))))
    return {
        "title": title, "id": str(rid), "status": "experimental", "description": desc,
        "author": "Threat Intel Automator", "date": date.today().isoformat(),
        "logsource": logsource, "detection": detection,
        "falsepositives": ["Shared hosting / CDN infrastructure", "Stale indicators"],
        "level": level, "tags": tags,
    }


def build_rules(rows: list[dict]) -> dict[str, dict]:
    by: dict[str, list[dict]] = {}
    for r in rows:
        by.setdefault(r["type"], []).append(r)
    rules: dict[str, dict] = {}

    def chunks(items):
        for i in range(0, len(items), MAX_VALUES):
            yield i // MAX_VALUES + 1, items[i:i + MAX_VALUES]

    def level(rs):
        return "high" if min(r["score"] for r in rs) >= 85 else "medium"

    for n, part in chunks(by.get("domain", [])):
        vals = [r["value"] for r in part]
        rules[f"tia_dns_domains_{n}.yml"] = _rule(
            f"TIA - DNS Query to Known Malicious Domain ({n})", "Domains from curated threat intel feeds.",
            {"category": "dns"},
            {"selection_exact": {"query": vals},
             "selection_sub": {"query|endswith": ["." + v for v in vals]},
             "condition": "1 of selection*"},
            level(part), ["attack.command-and-control", "attack.t1071.004"], vals)

    for n, part in chunks(by.get("ip", [])):
        vals = [r["value"] for r in part]
        rules[f"tia_net_ips_{n}.yml"] = _rule(
            f"TIA - Connection to Known Malicious IP ({n})", "IPs from curated threat intel feeds (botnet C2 etc.).",
            {"category": "network_connection", "product": "windows"},
            {"selection": {"DestinationIp": vals}, "condition": "selection"},
            level(part), ["attack.command-and-control", "attack.t1071"], vals)

    for n, part in chunks(by.get("url", [])):
        vals = [r["value"] for r in part]
        rules[f"tia_proxy_urls_{n}.yml"] = _rule(
            f"TIA - Proxy Access to Known Malicious URL ({n})", "URLs from malware distribution feeds.",
            {"category": "proxy"},
            {"selection": {"c-uri|contains": vals}, "condition": "selection"},
            level(part), ["attack.initial-access", "attack.t1189"], vals)

    hashes = [(r["type"].upper(), r["value"], r) for t in ("sha256", "sha1", "md5") for r in by.get(t, [])]
    for n, part in chunks(hashes):
        vals = [f"{algo}={v}" for algo, v, _ in part]
        rules[f"tia_proc_hashes_{n}.yml"] = _rule(
            f"TIA - Execution of Known Malicious File Hash ({n})", "File hashes from threat intel feeds.",
            {"category": "process_creation", "product": "windows"},
            {"selection": {"Hashes|contains": vals}, "condition": "selection"},
            level([r for *_, r in part]), ["attack.execution"], vals)
    return rules


def render(rules: dict[str, dict]) -> dict[str, str]:
    return {name: yaml.safe_dump(rule, sort_keys=False, width=120) for name, rule in rules.items()}
