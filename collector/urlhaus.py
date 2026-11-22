from __future__ import annotations

from ..models import IOC
from ..normalize import clean_url
from .base import Collector, http_get


class URLhaus(Collector):
    """abuse.ch URLhaus recent malware URLs (plain text feed)."""

    name = "urlhaus"

    def parse(self, text: str) -> list[IOC]:
        out = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.lower().startswith("http"):
                out.append(IOC("url", clean_url(line), self.name, tags=["malware-distribution"]))
        return out

    def fetch(self, client):
        headers = {"Auth-Key": self.keys["abusech"]} if self.keys.get("abusech") else None
        return self.parse(http_get(client, self.conf["url"], headers).text)
