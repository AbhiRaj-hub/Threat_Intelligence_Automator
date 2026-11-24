from __future__ import annotations

from .base import Enricher


class AbuseIPDB(Enricher):
    name = "abuseipdb"
    types = ("ip",)
    min_interval = 1.0

    def lookup(self, client, ioc_type, value):
        self._throttle()
        r = client.get("https://api.abuseipdb.com/api/v2/check",
                       params={"ipAddress": value, "maxAgeInDays": 90},
                       headers={"Key": self.api_key, "Accept": "application/json"}, timeout=30)
        r.raise_for_status()
        d = r.json()["data"]
        return {"score": d.get("abuseConfidenceScore", 0), "reports": d.get("totalReports", 0),
                "country": d.get("countryCode"), "isp": d.get("isp")}
