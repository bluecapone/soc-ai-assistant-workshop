import importlib.util, pathlib

spec = importlib.util.spec_from_file_location(
    "events",
    pathlib.Path(__file__).resolve().parents[1] / "events.py",
)
ev = importlib.util.module_from_spec(spec); spec.loader.exec_module(ev)

ISO = "2026-09-19T10:00:00.000+0000"


def test_build_doc_has_wazuh_shape_and_rule_id():
    doc = ev.build_doc(ISO, "100201", 3, "desc", ["windows", "ambient"],
                       "windows-security", "/var/log/host/dc-01/security.log",
                       {"host": "dc-01"}, "raw line")
    assert doc["@timestamp"] == ISO and doc["timestamp"] == ISO
    assert doc["rule"]["id"] == "100201" and doc["rule"]["level"] == 3
    assert doc["manager"]["name"] == "wazuh.manager"
    assert doc["data"]["host"] == "dc-01"
    assert doc["full_log"] == "raw line"


def test_dc_logon_is_100201_on_dc_host():
    doc = ev.dc_logon(ISO, "sarah.mitchell", "workstation-finance-01", "10.20.20.11")
    assert doc["rule"]["id"] == "100201"
    assert doc["data"]["host"] == "dc-01"
    assert doc["data"]["user"] == "sarah.mitchell"
    assert doc["data"]["src_ip"] == "10.20.20.11"
    assert "authentication_success" in doc["rule"]["groups"]
    assert "sarah.mitchell" in doc["full_log"]


def test_db_query_is_100202_from_web_service_account():
    doc = ev.db_query(ISO, "svc_webapp", "SELECT", 42, "10.20.0.10")
    assert doc["rule"]["id"] == "100202"
    assert doc["data"]["host"] == "database-01"
    assert doc["data"]["db_user"] == "svc_webapp"
    assert doc["data"]["src_ip"] == "10.20.0.10"
    assert "database" in doc["rule"]["groups"]


def test_fs_access_is_100203():
    doc = ev.fs_access(ISO, "david.chen", "finance", "/reports/Q3.xlsx", "open", "10.20.20.31")
    assert doc["rule"]["id"] == "100203"
    assert doc["data"]["host"] == "fileserver-01"
    assert doc["data"]["share"] == "finance"


def test_mail_flow_is_100204_and_clean():
    doc = ev.mail_flow(ISO, "news@vendor.example", "james.okonkwo@bankofwonderland.example", "198.51.100.20")
    assert doc["rule"]["id"] == "100204"
    assert doc["data"]["host"] == "mail-gateway-01"
    assert doc["data"]["verdict"] == "clean"
    assert doc["data"]["src_ip"] == "198.51.100.20"


def test_proxy_browse_is_100205_categorised():
    doc = ev.proxy_browse(ISO, "10.20.20.41", "docs.python.org", "technology", 8421)
    assert doc["rule"]["id"] == "100205"
    assert doc["data"]["host"] == "proxy-01"
    assert doc["data"]["cat"] == "technology"


def test_vpn_session_is_100206():
    doc = ev.vpn_session(ISO, "laura.gomez", "203.0.113.200", "connect")
    assert doc["rule"]["id"] == "100206"
    assert doc["data"]["host"] == "vpn-corp-01"
    assert doc["data"]["src_ip"] == "203.0.113.200"
    assert doc["data"]["event"] == "connect"


def test_edr_event_host_is_the_workstation():
    doc = ev.edr_event(ISO, "workstation-hr-01", "aisha.khan", "logon", "interactive")
    assert doc["rule"]["id"] == "100207"
    assert doc["data"]["host"] == "workstation-hr-01"
    assert doc["data"]["user"] == "aisha.khan"


def test_backup_job_is_100208():
    doc = ev.backup_job(ISO, "Nightly-CoreBank", "Success", 734003200)
    assert doc["rule"]["id"] == "100208"
    assert doc["data"]["host"] == "backup-01"
    assert doc["data"]["status"] == "Success"


def test_all_host_rule_ids_covered():
    assert ev.HOST_RULE_IDS == ["100201", "100202", "100203", "100204",
                                "100205", "100206", "100207", "100208"]
