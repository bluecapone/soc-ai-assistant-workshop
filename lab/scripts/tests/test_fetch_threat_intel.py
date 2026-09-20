# lab/scripts/tests/test_fetch_threat_intel.py
import importlib.util, pathlib
spec = importlib.util.spec_from_file_location(
    "fetch_threat_intel",
    pathlib.Path(__file__).resolve().parents[1] / "fetch_threat_intel.py",
)
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)

TF = {"query_status": "ok", "data": [
    {"ioc_type": "ip:port", "ioc": "154.91.63.98:8084", "threat_type": "botnet_cc",
     "malware_printable": "VShell", "confidence_level": 100},
    {"ioc_type": "domain", "ioc": "bad-c2.example.net", "threat_type": "botnet_cc",
     "malware_printable": "QakBot", "confidence_level": 90},
    {"ioc_type": "domain", "ioc": "lowconf.example", "threat_type": "botnet_cc",
     "malware_printable": "X", "confidence_level": 40},
    {"ioc_type": "url", "ioc": "http://x.example/a", "threat_type": "payload_delivery",
     "malware_printable": "Y", "confidence_level": 100},
]}
TF_PD = {"query_status": "ok", "data": [
    {"ioc_type": "domain", "ioc": "phish-delivery.example.com", "threat_type": "payload_delivery",
     "malware_printable": "Emotet", "confidence_level": 90},
    {"ioc_type": "url", "ioc": "http://phish-delivery.example.com/payload", "threat_type": "payload_delivery",
     "malware_printable": "Emotet", "confidence_level": 90},
    {"ioc_type": "ip:port", "ioc": "10.0.0.1:443", "threat_type": "botnet_cc",
     "malware_printable": "AsyncRAT", "confidence_level": 80},
]}
MB = {"query_status": "ok", "data": [
    {"sha256_hash": "a" * 64, "md5_hash": "b" * 32, "file_name": "invoice.exe",
     "file_type": "exe", "signature": "AgentTesla"},
    {"sha256_hash": "c" * 64, "md5_hash": "d" * 32, "file_name": "x",
     "file_type": "elf", "signature": None},
]}
UH = {"query_status": "ok", "urls": [
    {"url": "http://phish.example/login", "url_status": "online", "host": "phish.example"},
    {"url": "http://off.example/x", "url_status": "offline", "host": "off.example"},
]}

def test_threatfox_keeps_high_confidence_c2_ip_and_domain():
    rows = m.threatfox_rows(TF)
    vals = {(r["type"], r["value"], r["role"]) for r in rows}
    assert ("ip", "154.91.63.98", "c2") in vals          # port stripped
    assert ("domain", "bad-c2.example.net", "c2") in vals
    assert all(r["value"] != "lowconf.example" for r in rows)  # confidence < 75 dropped

def test_malwarebazaar_keeps_signed_attachment_types():
    rows = m.malwarebazaar_rows(MB)
    assert {"type": "sha256", "value": "a" * 64, "role": "malware",
            "label": "AgentTesla", "source": "MalwareBazaar"} in rows
    assert all(r["value"] != "c" * 64 for r in rows)     # signature None dropped

def test_threatfox_keeps_payload_delivery_as_phishing():
    rows = m.threatfox_rows(TF_PD)
    vals = {(r["type"], r["value"], r["role"]) for r in rows}
    assert ("domain", "phish-delivery.example.com", "phishing") in vals
    assert ("url", "http://phish-delivery.example.com/payload", "phishing") in vals
    assert ("ip", "10.0.0.1", "c2") in vals

def test_to_csv_header_and_dedup():
    rows = [{"type": "ip", "value": "1.2.3.4", "role": "c2", "label": "L", "source": "S"},
            {"type": "ip", "value": "1.2.3.4", "role": "c2", "label": "L", "source": "S"}]
    out = m.to_csv(rows).splitlines()
    assert out[0] == "type,value,role,label,source"
    assert len(out) == 2  # header + one deduped row

def test_labels_have_no_commas():
    rows = m.malwarebazaar_rows({"query_status": "ok", "data": [
        {"sha256_hash": "e" * 64, "md5_hash": "f" * 32, "file_name": "x",
         "file_type": "doc", "signature": "Foo, Bar"}]})
    assert all("," not in r["label"] for r in rows)
