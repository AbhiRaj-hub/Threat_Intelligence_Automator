from __future__ import annotations

from ..models import IOC
from ..normalize import clean_url
from .base import Collector, CollectorSkipped, http_get


class URLhaus(Collector):
    """abuse.ch URLhaus recent malware URLs (authenticated plain-text export; free Auth-Key required)."""

    name = "urlhaus"

    def parse(self, text: str) -> list[IOC]:
        out = []
        for line in text.splitlines():
            line = line.strip()
            if line.lower().startswith("http"):
                out.append(IOC("url", clean_url(line), self.name, tags=["malware-distribution"]))
        return out

    def fetch(self, client):
        key = self.keys.get("abusech", "")
        if not key:
            raise CollectorSkipped("ABUSECH_AUTH_KEY not set (free key: https://auth.abuse.ch/)")
        url = self.conf["url"].replace("{auth_key}", key)
        return self.parse(http_get(client, url, redact=key).text)
