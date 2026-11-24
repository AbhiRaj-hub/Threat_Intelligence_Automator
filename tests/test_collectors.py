import json
from datetime import date, timedelta

from tia.collectors.cisa_kev import CisaKev
from tia.collectors.feodo import Feodo
from tia.collectors.rss import Rss
from tia.collectors.urlhaus import URLhaus


def test_urlhaus():
    txt = "# comment\nhttp://1.2.3.4/a.sh\n\nhttps://bad.example/x\n"
    iocs = URLhaus({}, set()).parse(txt)
    assert [i.value for i in iocs] == ["http://1.2.3.4/a.sh", "https://bad.example/x"]


def test_feodo_skips_private_and_comments():
    iocs = Feodo({}, set()).parse("# x\n45.9.9.9\n10.0.0.1\n")
    assert [i.value for i in iocs] == ["45.9.9.9"]


def test_kev_recent_only():
    today = date.today().isoformat()
    old = (date.today() - timedelta(days=400)).isoformat()
    data = {"vulnerabilities": [
        {"cveID": "CVE-2026-0001", "vendorProject": "V", "product": "P", "vulnerabilityName": "N",
         "dateAdded": today, "dueDate": today, "knownRansomwareCampaignUse": "Known"},
        {"cveID": "CVE-2020-0001", "dateAdded": old}]}
    iocs = CisaKev({"recent_days": 30}, set()).parse(json.dumps(data))
    assert len(iocs) == 1 and "ransomware" in iocs[0].tags


def test_rss_only_trusts_defanged_domains():
    xml = """<rss><channel><item><title>Campaign</title><link>https://news.example/a</link>
    <description>&lt;p&gt;C2: evil-c2[.]xyz, IP 8.8.4.4, read more at blog.example.com sha
    %s CVE-2025-1111&lt;/p&gt;</description></item></channel></rss>""" % ("c" * 64)
    got = {(i.type, i.value) for i in Rss({}, set()).parse(xml, "t")}
    assert ("domain", "evil-c2.xyz") in got and ("ip", "8.8.4.4") in got
    assert ("sha256", "c" * 64) in got and ("cve", "CVE-2025-1111") in got
    assert ("domain", "blog.example.com") not in got


import httpx
import pytest

from tia.collectors.base import CollectorSkipped, http_get


def test_urlhaus_skips_without_key():
    with pytest.raises(CollectorSkipped):
        URLhaus({"url": "https://h.test/{auth_key}/u.txt"}, set(), {"abusech": ""}).fetch(httpx.Client())


def test_urlhaus_builds_authed_url_and_parses():
    seen = []

    def handler(req):
        seen.append(req.url.path)
        return httpx.Response(200, text="# hdr\nhttp://bad.test/a\n")

    c = URLhaus({"url": "https://h.test/v2/{auth_key}/urls_recent.txt"}, set(), {"abusech": "KEY123"})
    iocs = c.fetch(httpx.Client(transport=httpx.MockTransport(handler)))
    assert seen == ["/v2/KEY123/urls_recent.txt"] and [i.value for i in iocs] == ["http://bad.test/a"]


def test_http_get_fails_fast_on_4xx_and_redacts_secret():
    calls = []

    def handler(req):
        calls.append(1)
        return httpx.Response(410)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    with pytest.raises(RuntimeError) as e:
        http_get(client, "https://x.test/SECRETKEY/f.txt", redact="SECRETKEY")
    assert len(calls) == 1 and "SECRETKEY" not in str(e.value) and "410" in str(e.value)
