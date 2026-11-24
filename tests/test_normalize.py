from tia.normalize import extract, refang, is_public_ip


def test_refang():
    assert refang("hxxps://evil[.]example[.]org/a") == "https://evil.example.org/a"


def test_extract_all_types():
    h256 = "a" * 64
    text = f"C2 at 8[.]8[.]4[.]4 and evil-domain[.]xyz, {h256}, CVE-2024-3400, bad@phish.ru, hxxp://x.test/p.exe"
    got = set(extract(text))
    assert ("ip", "8.8.4.4") in got
    assert ("domain", "evil-domain.xyz") in got
    assert ("sha256", h256) in got
    assert ("cve", "CVE-2024-3400") in got
    assert ("email", "bad@phish.ru") in got
    assert ("url", "http://x.test/p.exe") in got


def test_private_ips_filtered():
    assert not is_public_ip("10.0.0.1") and not is_public_ip("192.168.1.1") and not is_public_ip("127.0.0.1")
    assert extract("10.1.2.3 and 192.168.0.9") == []


def test_allowlist_and_filenames():
    got = extract("see www.google.com and update.exe and evil.top", allowlist={"google.com"})
    assert got == [("domain", "evil.top")]


def test_hash_lengths_not_confused():
    got = dict.fromkeys(t for t, _ in extract("d41d8cd98f00b204e9800998ecf8427e " + "b" * 40))
    assert set(got) == {"md5", "sha1"}
