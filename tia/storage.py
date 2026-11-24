from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

from .models import IOC, utcnow

SCHEMA = """
CREATE TABLE IF NOT EXISTS iocs (
  key TEXT PRIMARY KEY, type TEXT NOT NULL, value TEXT NOT NULL,
  first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
  sources TEXT NOT NULL DEFAULT '[]', tags TEXT NOT NULL DEFAULT '[]',
  context TEXT NOT NULL DEFAULT '', score INTEGER NOT NULL DEFAULT 0,
  enrichment TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_iocs_score ON iocs(score);
CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(type);
CREATE TABLE IF NOT EXISTS cache (key TEXT PRIMARY KEY, ts REAL NOT NULL, data TEXT NOT NULL);
"""


def _row(r: sqlite3.Row) -> dict:
    d = dict(r)
    d["sources"] = json.loads(d["sources"])
    d["tags"] = json.loads(d["tags"])
    d["enrichment"] = json.loads(d["enrichment"])
    return d


class Store:
    def __init__(self, path: str = "data/tia.db"):
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)

    def upsert(self, ioc: IOC) -> bool:
        """Insert or merge an IOC. Returns True when it was new."""
        cur = self.db.execute("SELECT * FROM iocs WHERE key=?", (ioc.key,)).fetchone()
        if cur is None:
            self.db.execute(
                "INSERT INTO iocs(key,type,value,first_seen,last_seen,sources,tags,context) VALUES(?,?,?,?,?,?,?,?)",
                (ioc.key, ioc.type, ioc.value, ioc.seen, ioc.seen,
                 json.dumps([ioc.source]), json.dumps(sorted(set(ioc.tags))), ioc.context),
            )
            self.db.commit()
            return True
        r = _row(cur)
        sources = sorted(set(r["sources"]) | {ioc.source})
        tags = sorted(set(r["tags"]) | set(ioc.tags))
        self.db.execute(
            "UPDATE iocs SET last_seen=?, sources=?, tags=?, context=? WHERE key=?",
            (ioc.seen, json.dumps(sources), json.dumps(tags), r["context"] or ioc.context, ioc.key),
        )
        self.db.commit()
        return False

    def rows(self, min_score: int | None = None, max_score: int | None = None,
             ioc_type: str | None = None, since: str | None = None) -> list[dict]:
        q, args = "SELECT * FROM iocs WHERE 1=1", []
        if min_score is not None:
            q += " AND score>=?"; args.append(min_score)
        if max_score is not None:
            q += " AND score<?"; args.append(max_score)
        if ioc_type:
            q += " AND type=?"; args.append(ioc_type)
        if since:
            q += " AND first_seen>=?"; args.append(since)
        q += " ORDER BY score DESC, last_seen DESC"
        return [_row(r) for r in self.db.execute(q, args)]

    def set_score(self, key: str, score: int) -> None:
        self.db.execute("UPDATE iocs SET score=? WHERE key=?", (score, key))

    def set_enrichment(self, key: str, name: str, data: dict) -> None:
        r = self.db.execute("SELECT enrichment FROM iocs WHERE key=?", (key,)).fetchone()
        enr = json.loads(r["enrichment"])
        enr[name] = data
        self.db.execute("UPDATE iocs SET enrichment=? WHERE key=?", (json.dumps(enr), key))
        self.db.commit()

    def commit(self) -> None:
        self.db.commit()

    def cache_get(self, key: str, ttl: float) -> dict | None:
        r = self.db.execute("SELECT ts,data FROM cache WHERE key=?", (key,)).fetchone()
        if r and time.time() - r["ts"] < ttl:
            return json.loads(r["data"])
        return None

    def cache_set(self, key: str, data: dict) -> None:
        self.db.execute("INSERT OR REPLACE INTO cache(key,ts,data) VALUES(?,?,?)", (key, time.time(), json.dumps(data)))
        self.db.commit()

    def stats(self) -> dict:
        by_type = {r["type"]: r["n"] for r in self.db.execute("SELECT type, COUNT(*) n FROM iocs GROUP BY type")}
        return {"total": sum(by_type.values()), "by_type": by_type}
