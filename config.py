from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class Config:
    sources: dict
    allowlist: set[str]
    scoring: dict
    db_path: str = "data/tia.db"
    out_dir: str = "output"
    keys: dict = field(default_factory=dict)


def _yaml(path: Path) -> dict:
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def load(config_dir: str | None = None) -> Config:
    d = Path(config_dir or os.getenv("TIA_CONFIG_DIR", "config"))
    allow = _yaml(d / "allowlist.yaml").get("domains", [])
    return Config(
        sources=_yaml(d / "sources.yaml").get("sources", {}),
        allowlist={a.lower() for a in allow},
        scoring=_yaml(d / "scoring.yaml"),
        db_path=os.getenv("TIA_DB", "data/tia.db"),
        out_dir=os.getenv("TIA_OUT", "output"),
        keys={
            "abusech": os.getenv("ABUSECH_AUTH_KEY", ""),
            "virustotal": os.getenv("VT_API_KEY", ""),
            "abuseipdb": os.getenv("ABUSEIPDB_API_KEY", ""),
        },
    )
