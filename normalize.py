"""IOC extraction, defang/refang, validation and allowlisting."""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

DEFANG_RE = re.compile(r"\[\.\]|\(\.\)|\[dot\]|\(dot\)|hxxp|\[:\]|\[://\]|\[at\]|\[@\]", re.I)

_REFANG = [
    (re.compile(r"hxxp", re.I), "http"),
    (re.compile(r"\[\.\]|\(\.\)|\[dot\]|\(dot\)", re.I), "."),
    (re.compile(r"\[://\]"), "://"),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[at\]|\[@\]", re.I), "@"),
]

URL_RE = re.compile(r"\bhttps?://[^\s<>\"'\)\]]+", re.I)
EMAIL_RE = re.compile(r"\b[a-z0-9._%+-]+@(?:[a-z0-9-]+\.)+[a-z]{2,24}\b", re.I)
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.I)
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
HASH_RES = {
    "sha256": re.compile(r"\b[a-f0-9]{64}\b", re.I),
    "sha1": re.compile(r"\b[a-f0-9]{40}\b", re.I),
    "md5": re.compile(r"\b[a-f0-9]{32}\b", re.I),
}
# Things that look like domains but are really filenames.
FILE_EXTS = {
    "exe", "dll", "php", "html", "htm", "js", "py", "txt", "png", "jpg", "jpeg", "gif",
    "pdf", "zip", "rar", "doc", "docx", "xls", "xlsx", "ps1", "bat", "sh", "json", "xml",
    "css", "md", "csv", "log", "tmp", "bin", "msi", "iso", "lnk", "vbs", "jar", "yml", "yaml",
}


def refang(text: str) -> str:
    for rx, rep in _REFANG:
        text = rx.sub(rep, text)
    return text


def is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (
        ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
        or ip.is_reserved or ip.is_unspecified
    )


def is_allowlisted(host: str, allowlist) -> bool:
    host = host.lower().rstrip(".")
    return any(host == a or host.endswith("." + a) for a in allowlist)


def clean_url(url: str) -> str:
    return url.rstrip(".,;:!?'\"")


def normalize_value(ioc_type: str, value: str) -> str:
    value = value.strip()
    if ioc_type in ("domain", "email", "md5", "sha1", "sha256"):
        return value.lower().rstrip(".")
    if ioc_type == "cve":
        return value.upper()
    if ioc_type == "url":
        return clean_url(value)
    return value


def extract(text: str, allowlist=frozenset(), types=None) -> list[tuple[str, str]]:
    """Extract (type, value) IOCs from free text. Handles defanged input."""
    want = set(types) if types else None
    text = refang(text)
    found: dict[tuple[str, str], None] = {}

    def add(t: str, v: str) -> None:
        if want is None or t in want:
            found[(t, normalize_value(t, v))] = None

    for m in URL_RE.finditer(text):
        add("url", m.group(0))
    text = URL_RE.sub(" ", text)

    for m in EMAIL_RE.finditer(text):
        add("email", m.group(0))
    text = EMAIL_RE.sub(" ", text)

    for t, rx in HASH_RES.items():
        for m in rx.finditer(text):
            add(t, m.group(0))

    for m in CVE_RE.finditer(text):
        add("cve", m.group(0))

    for m in IPV4_RE.finditer(text):
        if is_public_ip(m.group(0)):
            add("ip", m.group(0))

    for m in DOMAIN_RE.finditer(text):
        d = m.group(0).lower()
        tld = d.rsplit(".", 1)[-1]
        if tld in FILE_EXTS or is_allowlisted(d, allowlist):
            continue
        add("domain", d)

    return list(found)


def extract_defanged_only(text: str, allowlist=frozenset(), types=("url", "domain")) -> list[tuple[str, str]]:
    """Noisy sources (news/blogs): only trust URLs/domains the author deliberately defanged."""
    tokens = [t for t in re.findall(r"\S+", text) if DEFANG_RE.search(t)]
    return extract(" ".join(tokens), allowlist, types)


def url_host(url: str) -> str:
    return (urlparse(url).hostname or "").lower()
