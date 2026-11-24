from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from ..models import IOC
from .base import Collector, http_get


class CisaKev(Collector):
    """CISA Known Exploited Vulnerabilities catalog."""

    name = "cisa_kev"

    def parse(self, text: str) -> list[IOC]:
        recent_days = int(self.conf.get("recent_days", 30))
        cutoff = (datetime.now(timezone.utc) - timedelta(days=recent_days)).date().isoformat()
        out = []
        for v in json.loads(text).get("vulnerabilities", []):
            if v.get("dateAdded", "") < cutoff:
                continue
            tags = ["kev"]
            if str(v.get("knownRansomwareCampaignUse", "")).lower() == "known":
                tags.append("ransomware")
            ctx = f"{v.get('vendorProject', '')} {v.get('product', '')}: {v.get('vulnerabilityName', '')} (added {v.get('dateAdded')}, due {v.get('dueDate')})"
            out.append(IOC("cve", v["cveID"], self.name, tags=tags, context=ctx.strip()))
        return out

    def fetch(self, client):
        return self.parse(http_get(client, self.conf["url"]).text)
