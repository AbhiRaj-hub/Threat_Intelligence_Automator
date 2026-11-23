from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone


def build(rows: list[dict], publish_at: int, review_at: int, top_n: int = 25) -> str:
    now = datetime.now(timezone.utc)
    since = (now - timedelta(days=1)).isoformat(timespec="seconds")
    new = [r for r in rows if r["first_seen"] >= since]
    src = Counter(s.split(":")[0] for r in rows for s in r["sources"])
    typ = Counter(r["type"] for r in rows)
    kev = [r for r in new if r["type"] == "cve"]
    lines = [
        f"# Threat Intel Digest - {now:%Y-%m-%d}", "",
        f"**Total tracked:** {len(rows)}  |  **New (24h):** {len(new)}  |  "
        f"**Auto-publish (>= {publish_at}):** {sum(r['score'] >= publish_at for r in rows)}  |  "
        f"**Needs review ({review_at}-{publish_at - 1}):** {sum(review_at <= r['score'] < publish_at for r in rows)}",
        "", "## By type", "", *[f"- {t}: {n}" for t, n in typ.most_common()],
        "", "## By source", "", *[f"- {s}: {n}" for s, n in src.most_common()],
    ]
    if kev:
        lines += ["", "## Newly exploited vulnerabilities (CISA KEV)", ""]
        lines += [f"- **{r['value']}** - {r['context']}" + (" 🔴 ransomware" if "ransomware" in r["tags"] else "") for r in kev[:20]]
    lines += ["", f"## Top {top_n} indicators", "", "| Score | Type | Indicator | Sources | Tags |", "|---|---|---|---|---|"]
    for r in rows[:top_n]:
        val = r["value"].replace(".", "[.]").replace("http", "hxxp").replace("|", "\\|")  # defang for safe viewing
        lines.append(f"| {r['score']} | {r['type']} | `{val[:90]}` | {', '.join(r['sources'])} | {', '.join(r['tags'])} |")
    return "\n".join(lines) + "\n"
