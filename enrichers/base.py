from __future__ import annotations

import time


class Enricher:
    name = "base"
    types: tuple[str, ...] = ()
    min_interval = 0.0  # seconds between API calls (free-tier friendly)

    def __init__(self, api_key: str):
        self.api_key = api_key
        self._last = 0.0

    def enabled(self) -> bool:
        return bool(self.api_key)

    def _throttle(self) -> None:
        wait = self.min_interval - (time.time() - self._last)
        if wait > 0:
            time.sleep(wait)
        self._last = time.time()

    def lookup(self, client, ioc_type: str, value: str) -> dict | None:
        raise NotImplementedError
