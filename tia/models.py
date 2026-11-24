from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

IOC_TYPES = ("ip", "domain", "url", "md5", "sha1", "sha256", "email", "cve")


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class IOC:
    type: str
    value: str
    source: str
    tags: list[str] = field(default_factory=list)
    context: str = ""
    seen: str = field(default_factory=utcnow)

    @property
    def key(self) -> str:
        return f"{self.type}:{self.value}"
