from __future__ import annotations

from .base import Enricher

_PATH = {"ip": "ip_addresses", "domain": "domains", "md5": "files", "sha1": "files", "sha256": "files"}


class VirusTotal(Enricher):
    name = "virustotal"
    types = tuple(_PATH)
    min_interval = 15.5  # free tier: 4 req/min

    def lookup(self, client, ioc_type, value):
        self._throttle()
        r = client.get(f"https://www.virustotal.com/api/v3/{_PATH[ioc_type]}/{value}",
                       headers={"x-apikey": self.api_key}, timeout=30)
        if r.status_code == 404:
            return {"checked": False, "not_found": True}
        r.raise_for_status()
        a = r.json()["data"]["attributes"]
        s = a.get("last_analysis_stats", {})
        return {
            "checked": True,
            "malicious": s.get("malicious", 0),
            "suspicious": s.get("suspicious", 0),
            "harmless": s.get("harmless", 0),
            "reputation": a.get("reputation", 0),
        }
