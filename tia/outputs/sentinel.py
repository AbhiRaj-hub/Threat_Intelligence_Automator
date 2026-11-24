"""Microsoft Sentinel outputs: watchlist CSV + KQL hunting queries."""
from __future__ import annotations

import csv
import io

WATCHLIST_ALIAS = "TIA-IOCs"
CSV_TYPES = {"ip", "domain", "url", "md5", "sha1", "sha256"}


def watchlist_csv(rows: list[dict]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["SearchKey", "IndicatorType", "Score", "Sources", "Tags", "FirstSeen"])
    for r in rows:
        if r["type"] in CSV_TYPES:
            w.writerow([r["value"], r["type"], r["score"], ";".join(r["sources"]), ";".join(r["tags"]), r["first_seen"]])
    return buf.getvalue()


KQL = f"""// Threat Intel Automator - hunting queries. Upload sentinel/{WATCHLIST_ALIAS}.csv as a watchlist
// with alias '{WATCHLIST_ALIAS}' and SearchKey = SearchKey.
let iocs = _GetWatchlist('{WATCHLIST_ALIAS}') | extend Score = toint(Score);

// 1) DNS lookups of malicious domains
DnsEvents
| where TimeGenerated > ago(1d)
| join kind=inner (iocs | where IndicatorType == "domain") on $left.Name == $right.SearchKey
| project TimeGenerated, Computer, ClientIP, Name, Score, Sources, Tags

;
// 2) Outbound connections to malicious IPs (Defender for Endpoint)
DeviceNetworkEvents
| where TimeGenerated > ago(1d)
| join kind=inner (iocs | where IndicatorType == "ip") on $left.RemoteIP == $right.SearchKey
| project TimeGenerated, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort, Score, Sources

;
// 3) Known-bad file hashes
DeviceFileEvents
| where TimeGenerated > ago(1d)
| join kind=inner (iocs | where IndicatorType == "sha256") on $left.SHA256 == $right.SearchKey
| project TimeGenerated, DeviceName, FileName, FolderPath, SHA256, Score
"""
