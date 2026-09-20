"""Point log/upload dirs at throwaway temp dirs before app.py is imported."""
import os
import tempfile

os.environ.setdefault("BANKWEB_LOG_DIR", tempfile.mkdtemp(prefix="bankweb-log-"))
os.environ.setdefault("BANKWEB_UPLOAD_DIR", tempfile.mkdtemp(prefix="bankweb-uploads-"))
