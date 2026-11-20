from datetime import datetime, timedelta, timezone
from taxii2client.v21 import Server

def fetch_stix_objects(
    discovery_url: str,
    user: str | None = None,
    password: str | None = None,
    hours_back: int = 24,
    limit: int = 100,
) -> list[dict]:
    server = Server(discovery_url, user=user or None, password=password or None)
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours_back)).isoformat()
    collected = []

    for api_root in server.api_roots:
        for collection in api_root.collections:
            if not collection.can_read:
                continue
            try:
                bundle = collection.get_objects(added_after=cutoff, limit=limit)
                objects = bundle.get("objects", []) if isinstance(bundle, dict) else []
                collected.extend(objects)
            except Exception as exc:
                print(f"[!] Skipping collection {collection.title}: {exc}")

    return collected
