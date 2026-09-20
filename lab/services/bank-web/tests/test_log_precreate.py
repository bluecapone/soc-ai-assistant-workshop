"""bank-web must pre-create its log files at startup.

Wazuh's logcollector reads a just-appeared file from its current end, so if access.log
and auth.log only appear on the first HTTP request, the first burst of events (a fired
attack right after the stack starts) is missed and never becomes a case. This test uses
its own throwaway log dir so no other test's requests can create the files for it.
"""
import importlib.util
import os
import pathlib
import tempfile

_LOG = tempfile.mkdtemp(prefix="bankweb-precreate-")
_prev = os.environ.get("BANKWEB_LOG_DIR")
os.environ["BANKWEB_LOG_DIR"] = _LOG
os.environ.setdefault("BANKWEB_UPLOAD_DIR", tempfile.mkdtemp(prefix="bankweb-precreate-up-"))

_p = pathlib.Path(__file__).resolve().parents[1] / "app.py"
_spec = importlib.util.spec_from_file_location("bankweb_precreate", _p)
_m = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_m)

# Restore the shared env so other test modules keep their own log dir.
if _prev is None:
    os.environ.pop("BANKWEB_LOG_DIR", None)
else:
    os.environ["BANKWEB_LOG_DIR"] = _prev


def test_access_and_auth_logs_exist_after_startup():
    for name in ("access.log", "auth.log"):
        assert os.path.exists(os.path.join(_LOG, name)), f"{name} not pre-created at startup"
