import importlib.util, pathlib
p = pathlib.Path(__file__).resolve().parents[1] / "custom-w2thive.py"
spec = importlib.util.spec_from_file_location("w2thive", p)
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)

def alert(rule_id, level, data, groups=("web", "attack")):
    return {"rule": {"id": rule_id, "level": level, "description": "d", "groups": list(groups)},
            "data": data, "timestamp": "2026-09-19T10:00:00+0000",
            "agent": {"name": "web-prod-01"}, "full_log": ""}

def test_merge_key_inbound_is_srcip():
    assert m.merge_key(alert("100110", 10, {"srcip": "45.9.148.20"})) == "45.9.148.20"

def test_merge_key_outbound_is_dstip():
    assert m.merge_key(alert("100142", 11, {"srcip": "10.20.0.10", "dstip": "154.91.63.98"})) == "154.91.63.98"

def test_merge_key_internal_only_is_empty():
    assert m.merge_key(alert("100143", 3, {"srcip": "10.20.0.10", "dstip": "10.20.10.40"})) == ""

def test_is_attack_true():
    assert m.is_attack(alert("100110", 10, {"srcip": "45.9.148.20"})) is True

def test_is_attack_false_for_benign():
    assert m.is_attack(alert("100143", 3, {"srcip": "10.20.0.10"}, groups=("backup", "benign"))) is False


def test_state_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(m, "STATE_DIR", str(tmp_path))
    m.remember_case("1.2.3.4", "~123", now=1000.0)
    assert m.lookup_case("1.2.3.4", now=1001.0) == "~123"


def test_state_expires_after_ttl(tmp_path, monkeypatch):
    monkeypatch.setattr(m, "STATE_DIR", str(tmp_path))
    monkeypatch.setattr(m, "INCIDENT_TTL", 900)
    m.remember_case("1.2.3.4", "~123", now=1000.0)
    assert m.lookup_case("1.2.3.4", now=1000.0 + 901) == ""


def test_state_missing_is_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(m, "STATE_DIR", str(tmp_path))
    assert m.lookup_case("9.9.9.9", now=1.0) == ""


def test_route_alert_creates_then_appends_and_triages_once(tmp_path, monkeypatch):
    monkeypatch.setattr(m, "STATE_DIR", str(tmp_path))
    monkeypatch.setattr(m, "N8N_TRIGGER_DELAY", 0)
    calls = {"create": 0, "append": 0, "notify": 0}
    monkeypatch.setattr(m, "create_case",
                        lambda *a, **k: (calls.__setitem__("create", calls["create"] + 1) or "~C1"))
    monkeypatch.setattr(m, "append_to_case",
                        lambda *a, **k: calls.__setitem__("append", calls["append"] + 1))
    monkeypatch.setattr(m, "notify_n8n",
                        lambda *a, **k: calls.__setitem__("notify", calls["notify"] + 1))
    up = alert("100131", 10, {"srcip": "45.9.148.20", "method": "POST", "url": "/upload"})
    ex = alert("100130", 12, {"srcip": "45.9.148.20", "url": "/files/x.php?cmd=id"})
    m.route_alert("http://th", "k", up)
    m.route_alert("http://th", "k", ex)
    assert calls == {"create": 1, "append": 1, "notify": 1}

def test_route_alert_benign_creates_standalone_and_triages(tmp_path, monkeypatch):
    monkeypatch.setattr(m, "STATE_DIR", str(tmp_path))
    monkeypatch.setattr(m, "N8N_TRIGGER_DELAY", 0)
    calls = {"create": 0, "notify": 0}
    monkeypatch.setattr(m, "create_case",
                        lambda *a, **k: (calls.__setitem__("create", calls["create"] + 1) or "~B1"))
    monkeypatch.setattr(m, "notify_n8n",
                        lambda *a, **k: calls.__setitem__("notify", calls["notify"] + 1))
    b = alert("100143", 3, {"srcip": "10.20.0.10", "dstip": "10.20.10.40"}, groups=("backup", "benign"))
    m.route_alert("http://th", "k", b)
    assert calls == {"create": 1, "notify": 1}


def test_benign_success_merges_into_open_attack_case(tmp_path, monkeypatch):
    monkeypatch.setattr(m, "STATE_DIR", str(tmp_path))
    monkeypatch.setattr(m, "N8N_TRIGGER_DELAY", 0)
    calls = {"create": 0, "append": 0, "notify": 0}
    monkeypatch.setattr(m, "create_case", lambda *a, **k: (calls.__setitem__("create", calls["create"] + 1) or "~C1"))
    monkeypatch.setattr(m, "append_to_case", lambda *a, **k: calls.__setitem__("append", calls["append"] + 1))
    monkeypatch.setattr(m, "notify_n8n", lambda *a, **k: calls.__setitem__("notify", calls["notify"] + 1))
    brute = alert("100120", 10, {"srcip": "45.9.148.20"})
    success = alert("100121", 3, {"srcip": "45.9.148.20"}, groups=("authentication_success", "benign"))
    m.route_alert("http://th", "k", brute)
    m.route_alert("http://th", "k", success)
    assert calls == {"create": 1, "append": 1, "notify": 1}


def test_benign_external_with_no_incident_is_standalone(tmp_path, monkeypatch):
    monkeypatch.setattr(m, "STATE_DIR", str(tmp_path))
    monkeypatch.setattr(m, "N8N_TRIGGER_DELAY", 0)
    calls = {"create": 0, "append": 0, "notify": 0}
    monkeypatch.setattr(m, "create_case", lambda *a, **k: (calls.__setitem__("create", calls["create"] + 1) or "~C1"))
    monkeypatch.setattr(m, "append_to_case", lambda *a, **k: calls.__setitem__("append", calls["append"] + 1))
    monkeypatch.setattr(m, "notify_n8n", lambda *a, **k: calls.__setitem__("notify", calls["notify"] + 1))
    crawler = alert("100151", 3, {"srcip": "203.0.113.10"}, groups=("web", "benign"))
    m.route_alert("http://th", "k", crawler)
    assert calls == {"create": 1, "append": 0, "notify": 1}
