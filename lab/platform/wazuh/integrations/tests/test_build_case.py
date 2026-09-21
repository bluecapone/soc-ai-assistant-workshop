import importlib.util, pathlib
p = pathlib.Path(__file__).resolve().parents[1] / "custom-w2thive.py"
spec = importlib.util.spec_from_file_location("w2thive", p)
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)

def alert(rule_id, level, data, full="", **kw):
    return {"rule": {"id": rule_id, "level": level, "description": "d", "groups": ["web", "attack"]},
            "data": data, "timestamp": "2026-09-18T10:00:00+0000",
            "agent": {"name": "web-prod-01"}, "full_log": full, **kw}

def test_sqli_evidence_reads_status_and_bytes():
    case, _ = m.build_case(alert("100110", 10,
        {"srcip": "203.0.113.99", "url": "/search?q=%27UNION", "id": "200", "bytes": "4213"}))
    assert "### Evidence" in case["description"]
    assert "200" in case["description"] and "4213" in case["description"]

def test_phishing_hash_is_named_and_observable():
    case, obs = m.build_case(alert("100170", 9,
        {"srcip": "203.0.113.99", "mail_from": "x@bad.top", "mail_to": "a@b",
         "verdict": "suspicious", "url": "http://bad.top/login",
         "attachment": "invoice.pdf", "sha256": "a" * 64}))
    assert "a" * 64 in case["description"]                      # hash named in description
    assert any(o["dataType"] == "hash" and o["data"] == "a" * 64 for o in obs)
    # narrative consistency: updated SUMMARY["100170"] language
    assert "suspicious" in case["description"]
    assert "verdict=phishing" not in case["description"]
    assert "double file extension" not in case["description"]

def test_pivot_hint_present():
    case, _ = m.build_case(alert("100140", 10,
        {"srcip": "10.20.0.10", "dst_host": "bad-c2.example.net", "dstip": "154.91.63.98"}))
    assert "data.srcip:10.20.0.10" in case["description"]
    # narrative consistency: updated SUMMARY["100140"] language
    assert "beacon" in case["description"]
    assert "command endpoint" not in case["description"]

def test_backup_twin_has_evidence():
    case, _ = m.build_case(alert("100143", 7,
        {"srcip": "10.20.0.10", "dstip": "10.20.0.50", "dst_host": "backup-storage",
         "bytes": "3221225472", "user_agent": "Veeam Backup/12.1"}))
    assert "### Evidence" in case["description"]

def test_cdn_twin_has_evidence():
    case, _ = m.build_case(alert("100141", 5,
        {"srcip": "10.20.0.10", "dstip": "203.0.113.40", "dst_host": "assets.akamai.net",
         "cat": "cdn"}))
    assert "### Evidence" in case["description"]

def test_phishing_ioc_flags():
    case, obs = m.build_case(alert("100170", 9,
        {"srcip": "203.0.113.99", "mail_from": "x@bad.top", "mail_to": "a@b",
         "verdict": "suspicious", "url": "http://bad.top/login",
         "attachment": "invoice.pdf", "sha256": "a" * 64}))
    mail_obs = [o for o in obs if o["dataType"] == "mail" and o["message"] == "email sender"]
    assert mail_obs and mail_obs[0]["ioc"] is True
    fname_obs = [o for o in obs if o["dataType"] == "filename" and o["message"] == "email attachment"]
    assert fname_obs and fname_obs[0]["ioc"] is True
    hash_obs = [o for o in obs if o["dataType"] == "hash"]
    assert hash_obs and hash_obs[0]["ioc"] is True

def test_clean_mail_has_no_none_hash_observable():
    case, obs = m.build_case(alert("100171", 4,
        {"srcip": "35.235.240.10", "mail_from": "x@bankofwonderland.example",
         "mail_to": "a@b", "verdict": "clean", "attachment": "stmt.pdf", "sha256": "none"}))
    assert not any(o["dataType"] == "hash" for o in obs)

def test_webshell_upload_carries_srcip_and_upload_language():
    case, obs = m.build_case(alert("100131", 10,
        {"srcip": "45.9.148.20", "method": "POST", "url": "/upload"}))
    assert "45.9.148.20" in case["description"]
    assert "upload" in case["description"].lower()
    assert "file-integrity" not in case["description"].lower()
    assert any(o["dataType"] == "ip" and o["data"] == "45.9.148.20" for o in obs)

def test_webshell_execution_names_the_uploaded_script():
    case, _ = m.build_case(alert("100130", 12,
        {"srcip": "45.9.148.20", "url": "/files/shell1a2b.php?cmd=id", "id": "200"}))
    assert "/files/shell1a2b.php" in case["description"]
    assert "command endpoint" not in case["description"]


def test_bruteforce_breakthrough_renders_srcip_and_compromise_language():
    case, obs = m.build_case(alert("100162", 12, {"srcip": "45.9.148.20", "dstuser": "deploy"}))
    assert "45.9.148.20" in case["description"]
    assert "breakthrough" in case["description"].lower() or "repeated failed" in case["description"].lower()
    assert any(o["dataType"] == "ip" and o["data"] == "45.9.148.20" for o in obs)


def _first_link_url(md):
    """The href of the first Markdown [text](href) link, read up to the first ')'."""
    i = md.index("](") + 2
    return md[i:md.index(")", i)]


def test_case_links_to_wazuh_discover_on_srcip():
    case, _ = m.build_case(alert("100120", 10, {"srcip": "203.0.113.10", "url": "/login"}))
    d = case["description"]
    assert "`data.srcip:203.0.113.10`" in d                       # human-readable pivot text
    url = _first_link_url(d)
    assert url.startswith("http://wazuh.localhost/app/data-explorer/discover#")
    # The rison parens are percent-encoded, so the ')' that closes the Markdown link is the
    # real end of the URL — the captured href still carries the whole encoded query blob.
    assert "_q=" in url and "data.srcip%3A203.0.113.10" in url
    assert "(" not in url and ")" not in url                      # Markdown-safe: no raw parens


def test_case_link_falls_back_to_rule_id_without_srcip():
    case, _ = m.build_case(alert("100131", 10, {"url": "/upload"}))   # no srcip on the alert
    url = _first_link_url(case["description"])
    assert "rule.id%3A100131" in url


def test_dashboard_url_is_configurable():
    # The link must point at the browser-reachable base, overridable for other deployments.
    old = m.WAZUH_DASHBOARD_URL
    m.WAZUH_DASHBOARD_URL = "https://siem.example.test"
    try:
        assert m.wazuh_discover_url("rule.id:100120").startswith("https://siem.example.test/app/")
    finally:
        m.WAZUH_DASHBOARD_URL = old
