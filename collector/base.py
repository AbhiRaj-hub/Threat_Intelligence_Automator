from __future__ import annotations

import logging
import time

import httpx

from ..models import IOC

log = logging.getLogger(__name__)
UA = "ThreatIntelAutomator/0.1 (+https://github.com/AbhiRaj-hub)"


def http_get(client: httpx.Client, url: str, headers: dict | None = None, retries: int = 3) -> httpx.Response:
    last: Exception | None = None
    for attempt in range(retries):
        try:
            r = client.get(url, headers={"User-Agent": UA, **(headers or {})}, timeout=30, follow_redirects=True)
            r.raise_for_status()
            return r
        except (httpx.HTTPError, httpx.TransportError) as exc:
            last = exc
            log.warning("GET %s failed (%s), attempt %d/%d", url, exc, attempt + 1, retries)
            time.sleep(2 ** attempt)
    raise RuntimeError(f"GET {url} failed after {retries} attempts: {last}")


class Collector:
    """One collector per source. Subclasses implement parse() (pure, testable) and fetch()."""

    name = "base"

    def __init__(self, conf: dict, allowlist: set[str], keys: dict | None = None):
        self.conf = conf
        self.allowlist = allowlist
        self.keys = keys or {}

    def fetch(self, client: httpx.Client) -> list[IOC]:
        raise NotImplementedError
