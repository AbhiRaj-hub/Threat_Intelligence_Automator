from __future__ import annotations

import re
import xml.etree.ElementTree as ET

from ..models import IOC
from ..normalize import extract, extract_defanged_only
from .base import Collector, http_get

_TAG = re.compile(r"<[^>]+>")


def _text(el: ET.Element | None) -> str:
    return "".join(el.itertext()) if el is not None else ""


class Rss(Collector):
    """Generic RSS/Atom collector for advisories and threat reports.

    Hashes/IPs/CVEs are extracted normally; URLs and domains only when the author defanged them
    (otherwise every article link would become an IOC).
    """

    name = "rss"

    def parse(self, xml_text: str, feed_name: str = "feed") -> list[IOC]:
        root = ET.fromstring(xml_text)
        entries = root.findall(".//item") + root.findall(".//{http://www.w3.org/2005/Atom}entry")
        out: list[IOC] = []
        for e in entries:
            title = _text(e.find("title")) or _text(e.find("{http://www.w3.org/2005/Atom}title"))
            body = " ".join(
                _text(e.find(tag))
                for tag in ("description", "{http://purl.org/rss/1.0/modules/content/}encoded",
                            "{http://www.w3.org/2005/Atom}summary", "{http://www.w3.org/2005/Atom}content")
            )
            body = _TAG.sub(" ", body)
            link = _text(e.find("link")) or (e.find("{http://www.w3.org/2005/Atom}link") or ET.Element("x")).get("href", "")
            pairs = extract(body, self.allowlist, types=("ip", "md5", "sha1", "sha256", "cve", "email"))
            pairs += extract_defanged_only(body, self.allowlist)
            for t, v in pairs:
                out.append(IOC(t, v, f"rss:{feed_name}", tags=["report"], context=f"{title.strip()} {link}".strip()))
        return out

    def fetch(self, client):
        out: list[IOC] = []
        for feed in self.conf.get("feeds", []):
            out += self.parse(http_get(client, feed["url"]).text, feed["name"])
        return out
