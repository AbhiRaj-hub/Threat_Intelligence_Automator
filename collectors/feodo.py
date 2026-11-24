from __future__ import annotations

from ..models import IOC
from ..normalize import is_public_ip
from .base import Collector, http_get


class Feodo(Collector):
    """abuse.ch Feodo Tracker botnet C2 IP blocklist."""

    name = "feodo"

    def parse(self, text: str) -> list[IOC]:
        out = []
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith("#") and is_public_ip(line):
                out.append(IOC("ip", line, self.name, tags=["botnet-c2"]))
        return out

    def fetch(self, client):
        headers = {"Auth-Key": self.keys["abusech"]} if self.keys.get("abusech") else None
        return self.parse(http_get(client, self.conf["url"], headers).text)
