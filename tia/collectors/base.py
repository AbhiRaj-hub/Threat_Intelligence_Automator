from __future__ import annotations

import logging
import time

import httpx

from ..models import IOC

log = logging.getLogger(__name__)
UA = "ThreatIntelAutomator/0.1 (+https://github.com/AbhiRaj-hub)"


class CollectorSkipped(Exception):
    """Raised when a collector cannot run for a known, non-error reason (e.g. missing API key)."""


def http_get(client: httpx.Client, url: str, headers: dict | None = None, retries: int = 3,
             redact: str | None = None) -> httpx.Response:
    """GET with retries for transient failures only. 4xx (except 429) fails fast; `redact` hides secrets in messages."""
    def safe(msg: str) -> str:
        return msg.replace(redact, "***") if redact else msg

    last = "unknown error"
    for attempt in range(retries):
        try:
            r = client.get(url, headers={"User-Agent": UA, **(headers or {})}, timeout=30, follow_redirects=True)
            r.raise_for_status()
            return r
        except httpx.HTTPStatusError as exc:
            code = exc.response.status_code
            if 400 <= code < 500 and code != 429:
                raise RuntimeError(safe(f"GET {url} returned HTTP {code}; not retrying")) from None
            last = f"HTTP {code}"
        except httpx.HTTPError as exc:
            last = type(exc).__name__ + (f": {exc}" if str(exc) else "")
        log.warning(safe(f"GET {url} failed ({last}), attempt {attempt + 1}/{retries}"))
        time.sleep(2 ** attempt)
    raise RuntimeError(safe(f"GET {url} failed after {retries} attempts: {last}"))


class Collector:
    """One collector per source. Subclasses implement parse() (pure, testable) and fetch()."""

    name = "base"

    def __init__(self, conf: dict, allowlist: set[str], keys: dict | None = None):
        self.conf = conf
        self.allowlist = allowlist
        self.keys = keys or {}

    def fetch(self, client: httpx.Client) -> list[IOC]:
        raise NotImplementedError
