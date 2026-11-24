from __future__ import annotations

import argparse
import json
import logging
import time

from . import config, pipeline
from .storage import Store


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="tia", description="Threat Intel Automator")
    p.add_argument("command", choices=["run", "collect", "enrich", "score", "export", "stats", "watch"])
    p.add_argument("--config-dir")
    p.add_argument("--every", type=int, default=60, help="minutes between runs (watch)")
    p.add_argument("-v", "--verbose", action="store_true")
    a = p.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    for noisy in ("httpx", "httpcore"):  # their request logs include full URLs (API keys live in some paths)
        logging.getLogger(noisy).setLevel(logging.WARNING)

    cfg = config.load(a.config_dir)
    store = Store(cfg.db_path)
    if a.command == "watch":
        while True:
            print(json.dumps(pipeline.run_once(cfg, store), indent=2))
            time.sleep(a.every * 60)
    result = {
        "run": lambda: pipeline.run_once(cfg, store),
        "collect": lambda: pipeline.collect(cfg, store),
        "enrich": lambda: {"api_calls": pipeline.enrich(cfg, store)},
        "score": lambda: {"scored": pipeline.score(cfg, store)},
        "export": lambda: pipeline.export(cfg, store),
        "stats": lambda: store.stats(),
    }[a.command]()
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
