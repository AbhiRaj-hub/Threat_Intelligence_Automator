from .cisa_kev import CisaKev
from .feodo import Feodo
from .rss import Rss
from .urlhaus import URLhaus

REGISTRY = {c.name: c for c in (URLhaus, Feodo, CisaKev, Rss)}


def build(cfg):
    """Instantiate every enabled collector listed in sources.yaml."""
    out = []
    for name, conf in cfg.sources.items():
        if conf.get("enabled", True) and name in REGISTRY:
            out.append(REGISTRY[name](conf, cfg.allowlist, cfg.keys))
    return out
