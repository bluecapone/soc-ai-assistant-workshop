import importlib.util, pathlib

BASE = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("breadcrumbs", BASE / "breadcrumbs.py")
bc = importlib.util.module_from_spec(spec); spec.loader.exec_module(bc)

ISO = "2026-09-19T10:00:00.000+0000"


def test_exfil_breadcrumbs_are_db_and_fileserver():
    docs = bc.breadcrumb_docs("exfil", ISO)
    ids = sorted(d["rule"]["id"] for d in docs)
    hosts = sorted(d["data"]["host"] for d in docs)
    assert ids == ["100221", "100222"]
    assert hosts == ["database-01", "fileserver-01"]
    for d in docs:
        assert d["@timestamp"] == ISO
        assert "exfiltration" in d["rule"]["groups"]


def test_phishing_breadcrumbs_are_workstation_and_dc():
    docs = bc.breadcrumb_docs("phishing", ISO)
    ids = sorted(d["rule"]["id"] for d in docs)
    hosts = sorted(d["data"]["host"] for d in docs)
    assert ids == ["100223", "100224"]
    assert hosts == ["dc-01", "workstation-finance-01"]


def test_ssh_brute_breadcrumb_is_dc_lateral_from_web():
    docs = bc.breadcrumb_docs("ssh_brute", ISO)
    assert len(docs) == 1
    d = docs[0]
    assert d["rule"]["id"] == "100225"
    assert d["data"]["host"] == "dc-01"
    assert d["data"]["src_ip"] == "10.20.0.10"
    assert d["data"]["user"] == "svc_webapp"
    assert "lateral_movement" in d["rule"]["groups"]


def test_button_without_breadcrumb_returns_empty():
    assert bc.breadcrumb_docs("recon_scan", ISO) == []
    assert bc.breadcrumb_docs("sqli", ISO) == []


def test_breadcrumb_doc_has_wazuh_shape():
    d = bc.breadcrumb_docs("exfil", ISO)[0]
    assert d["manager"]["name"] == "wazuh.manager"
    assert d["rule"]["level"] >= 1
    assert isinstance(d["full_log"], str) and d["full_log"]


def test_new_ids_are_not_in_the_integrator_forward_list():
    ossec = (BASE.parents[1] / "platform/wazuh/ossec.conf").read_text()
    forward_line = [l for l in ossec.splitlines() if "<rule_id>" in l][0]
    for rid in ["100221", "100222", "100223", "100224", "100225"]:
        assert rid not in forward_line
