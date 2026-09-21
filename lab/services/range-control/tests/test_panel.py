import os, sys, tempfile, importlib.util, pathlib

_TMP = tempfile.mkdtemp()
os.environ["ACTION_LOG"] = os.path.join(_TMP, "actions.log")
os.environ["HOSTLOG_DIR"] = os.path.join(_TMP, "host")
os.environ["MALICIOUS_IPS_FILE"] = os.path.join(_TMP, "mal.txt")
with open(os.environ["MALICIOUS_IPS_FILE"], "w") as fh:
    fh.write("203.0.113.66\n")

BASE = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
spec = importlib.util.spec_from_file_location("panelapp", BASE / "app.py")
appmod = importlib.util.module_from_spec(spec); spec.loader.exec_module(appmod)
client = appmod.app.test_client()

def test_preview_attack_returns_pool_ip_as_source():
    d = client.post("/preview", json={"id": "sqli"}).get_json()
    assert d == {"ip": "203.0.113.66", "kind": "attacker", "role": "source"}

def test_preview_outbound_role_is_destination():
    assert client.post("/preview", json={"id": "exfil"}).get_json()["role"] == "destination"

def test_preview_benign_has_label_no_ip():
    d = client.post("/preview", json={"id": "backup"}).get_json()
    assert d["kind"] == "benign" and d["label"] and d["ip"] == ""

def test_fire_passes_attacker_ip_to_inbound(monkeypatch):
    seen = {}
    def fake_run(cmd, env=None, **kw):
        seen["env"] = env
        class R: returncode = 0; stdout = "ok"; stderr = ""
        return R()
    monkeypatch.setattr(appmod.subprocess, "run", fake_run)
    client.post("/fire", json={"id": "sqli", "ip": "203.0.113.66"})
    assert seen["env"]["ATTACKER_IP"] == "203.0.113.66"

def test_fire_passes_dest_ip_to_outbound(monkeypatch):
    seen = {}
    def fake_run(cmd, env=None, **kw):
        seen["env"] = env
        class R: returncode = 0; stdout = "ok"; stderr = ""
        return R()
    monkeypatch.setattr(appmod.subprocess, "run", fake_run)
    client.post("/fire", json={"id": "exfil", "ip": "203.0.113.66"})
    assert seen["env"]["MALICIOUS_DEST_IP"] == "203.0.113.66"

def test_no_source_ip_panel_in_render():
    html = client.get("/").get_data(as_text=True)
    assert "Your source IPs" not in html

def test_request_urls_carry_no_action_id():
    # Ad-blockers / privacy extensions (net::ERR_BLOCKED_BY_CLIENT) match on the request
    # URL. The action id and IP must ride in the POST body so no blocklist keyword
    # (e.g. "beacon" in c2_beacon/cdn_beacon) ever lands in a URL the browser fetches.
    html = client.get("/").get_data(as_text=True)
    assert "'/fire/'" not in html, "action id must not be built into the fire URL"
    assert "'/preview/'" not in html, "action id must not be built into the preview URL"
    assert "fetch('/fire'" in html and "fetch('/preview'" in html
