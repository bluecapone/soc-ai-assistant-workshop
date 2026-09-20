"""
Deliberately vulnerable target for the SOC AI Automation lab.

This app exists to be attacked from the range control panel and to emit clean,
fixed-format logs that Wazuh detects. It is intentionally insecure. Never expose it
to a real network. Every vulnerability here is on purpose.

Log contract:
  access.log:  bankweb srcip=<client_ip> method=<method> url=<path> status=<code> bytes=<n> ua="<ua>"
  auth.log:    <ts> authresult=<success|failure> user=<user> src_ip=<client_ip>

The access line is written as key=value fields (not Combined Log Format). Wazuh's
built-in web-accesslog decoder only claims lines carrying a CLF request-line
("<method> <path> HTTP/x"), so this shape sidesteps it and our bankweb-access decoder
owns the line — otherwise the built-in decoder wins and none of the custom web rules fire.

client_ip is the X-Forwarded-For value when present (that is how the range control
panel re-stamps the attacker IP per run), otherwise the socket peer.
"""

import base64
import os
import sqlite3
import subprocess
from datetime import datetime, timezone

from flask import Flask, request, Response, send_from_directory

# Favicon: an original card-suit heart mark, inlined so there's no separate file.
_FAVICON_SVG = (
    "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'>"
    "<rect width='32' height='32' rx='6' fill='#1b2a4a'/>"
    "<path d='M16 26 C4 17 7 8 13 11 C15 12 16 13 16 13 C16 13 17 12 19 11 "
    "C25 8 28 17 16 26 Z' fill='#d13b5e'/></svg>"
)
FAVICON = "data:image/svg+xml;base64," + base64.b64encode(_FAVICON_SVG.encode()).decode()

LOG_DIR = os.environ.get("BANKWEB_LOG_DIR", "/var/log/bank-web")
UPLOAD_DIR = os.environ.get("BANKWEB_UPLOAD_DIR", "/uploads")
DB_PATH = "/tmp/target.db"
PORT = int(os.environ.get("TARGET_PORT", "8080"))

COMPANY = "Unsecure Bank of Wonderland"
TAGLINE = "Down the rabbit hole with your data."

os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Pre-create the log files so Wazuh's logcollector opens and tails them from the start.
# Without this they only appear on the first request, and logcollector misses that first
# batch (it reads a just-appeared file from its current end) - so an attack fired right
# after the stack boots produces no alert and no case.
for _f in ("access.log", "auth.log"):
    open(os.path.join(LOG_DIR, _f), "a").close()

app = Flask(__name__)


# --------------------------------------------------------------------------- #
# Logging                                                                      #
# --------------------------------------------------------------------------- #
def client_ip() -> str:
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "-"


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S %z")


def _append(filename: str, line: str) -> None:
    with open(os.path.join(LOG_DIR, filename), "a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def log_auth(result: str, user: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S%z")
    _append("auth.log", f"{ts} authresult={result} user={user} src_ip={client_ip()}")


@app.after_request
def access_log(resp: Response) -> Response:
    # Don't log the brand asset, favicon, or container health-probe requests as traffic.
    if request.path.startswith("/brand") or request.path in ("/favicon.ico", "/healthz"):
        return resp
    body_len = resp.calculate_content_length()
    line = (
        f'bankweb srcip={client_ip()} '
        f'method={request.method} url={request.full_path.rstrip("?")} '
        f'status={resp.status_code} bytes={body_len if body_len is not None else 0} '
        f'ua="{request.headers.get("User-Agent", "-")}"'
    )
    _append("access.log", line)
    return resp


@app.route("/healthz")
def healthz():
    # Liveness probe for the container healthcheck; excluded from access.log above so it
    # never shows up as traffic in the SIEM.
    return "ok", 200


# --------------------------------------------------------------------------- #
# Database (intentionally SQL-injectable)                                      #
# --------------------------------------------------------------------------- #
def init_db() -> None:
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT);
        CREATE TABLE IF NOT EXISTS products (id INTEGER, name TEXT);
        """
    )
    cur = db.execute("SELECT count(*) FROM users")
    if cur.fetchone()[0] == 0:
        db.executemany(
            "INSERT INTO users VALUES (?, ?)",
            [("admin", "S0cAdmin!2026"), ("sarah.mitchell", "hunter2")],
        )
        db.executemany(
            "INSERT INTO products VALUES (?, ?)",
            [(1, "Current Account"), (2, "Rabbit-Hole Savings"), (3, "Cheshire Credit Card")],
        )
    db.commit()
    db.close()


# --------------------------------------------------------------------------- #
# Presentation                                                                 #
# --------------------------------------------------------------------------- #
CSS = """
:root{
  --bg:#eef2f9; --card:#ffffff; --ink:#16233d; --muted:#5b6b86; --line:#dbe2ee;
  --navy:#1b2a4a; --accent:#2b59ff; --heart:#d13b5e; --ok:#1f9d64;
  --serif:Georgia,"Times New Roman",serif;
  --sans:system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);line-height:1.55}
a{color:var(--accent);text-decoration:none}
.top{background:var(--navy);color:#fff;border-bottom:3px solid var(--heart)}
.top .wrap{max-width:1000px;margin:0 auto;display:flex;align-items:center;gap:16px;padding:14px 22px}
.logo{height:40px;width:auto;display:block;background:#fff;border-radius:6px;padding:3px 6px}
.brand{font-family:var(--serif);font-weight:700;font-size:20px;letter-spacing:.2px}
.brand .suit{color:var(--heart)}
.tag{margin-left:auto;color:#c7d2e8;font-size:12.5px;font-style:italic}
.notice{background:#fff7d6;border-bottom:1px solid #f0e2a8;color:#6b5a12;font-size:13px}
.notice .wrap{max-width:1000px;margin:0 auto;padding:8px 22px}
.notice b{color:#8a6d0b}
main{max-width:1000px;margin:26px auto;padding:0 22px;display:grid;
  grid-template-columns:1.3fr 1fr;gap:26px}
@media (max-width:760px){main{grid-template-columns:1fr}}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;
  box-shadow:0 1px 2px rgba(20,35,61,.05)}
.card h2{margin:0;padding:16px 20px;border-bottom:1px solid var(--line);font-size:15px;
  font-family:var(--serif)}
.card .body{padding:20px}
label{display:block;font-size:12.5px;color:var(--muted);margin:0 0 4px}
input[type=text],input[type=password],input[type=search]{width:100%;padding:10px 12px;
  border:1px solid var(--line);border-radius:8px;font-size:14px;font-family:var(--sans);
  background:#fbfcfe;margin-bottom:14px}
input:focus{outline:2px solid var(--accent);outline-offset:1px;border-color:var(--accent)}
button{background:var(--navy);color:#fff;border:0;border-radius:8px;padding:11px 18px;
  font-size:14px;font-weight:600;cursor:pointer;font-family:var(--sans)}
button:hover{background:#24365e}
.hint{font-size:12px;color:var(--muted);margin-top:2px}
.accounts{list-style:none;margin:0;padding:0}
.accounts li{display:flex;justify-content:space-between;padding:11px 0;border-bottom:1px dashed var(--line);font-size:14px}
.accounts li:last-child{border:0}
.accounts .bal{font-variant-numeric:tabular-nums;color:var(--muted)}
.jokes{margin:14px 0 0;padding:0;list-style:none;color:var(--muted);font-size:12.5px}
.jokes li{padding:3px 0;padding-left:18px;position:relative}
.jokes li::before{content:"\\2660";position:absolute;left:0;color:var(--heart)}
footer{max-width:1000px;margin:10px auto 40px;padding:0 22px;color:var(--muted);font-size:12px}
.result{max-width:1000px;margin:26px auto;padding:0 22px}
.badge{display:inline-block;font-size:11px;padding:3px 8px;border-radius:20px;
  background:#e9eefb;color:var(--accent);margin-left:8px;vertical-align:middle}
"""


def shell(inner: str) -> str:
    return f"""<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>{COMPANY}</title><link rel="icon" href="{FAVICON}"><style>{CSS}</style></head><body>
<div class=top><div class=wrap>
  <span class=brand>Unsecure Bank of Wonderland <span class=suit>&#9829;</span></span>
  <span class=tag>{TAGLINE}</span>
</div></div>
<div class=notice><div class=wrap>
  <b>Service notice:</b> our public banking site is reachable from the entire internet,
  which we consider a feature. Two-factor authentication remains disabled for your convenience.
</div></div>
{inner}
<footer>&copy; Unsecure Bank of Wonderland. Deposits are insured by good intentions.
This is a deliberately vulnerable lab target. Do not enter real data.</footer>
</body></html>"""


def portal() -> str:
    inner = """
<main>
  <section class=card>
    <h2>Online Banking Login</h2>
    <div class=body>
      <form method=post action="/login">
        <label for=u>Username</label>
        <input id=u name=username type=text autocomplete=off placeholder="e.g. admin">
        <label for=p>Password</label>
        <input id=p name=password type=password autocomplete=off placeholder="any password, really">
        <button type=submit>Sign in</button>
        <div class=hint>Forgot your password? So did we. Any password is a good password.</div>
      </form>
    </div>
  </section>

  <section class=card>
    <h2>Account Search</h2>
    <div class=body>
      <form method=get action="/search">
        <label for=q>Find a product or account</label>
        <input id=q name=q type=search placeholder="savings, credit, current...">
        <button type=submit>Search</button>
      </form>
      <ul class=jokes>
        <li>Single sign-on. Single password. Single point of failure.</li>
        <li>Your data is stored exactly where you'd expect: everywhere.</li>
        <li>Security review scheduled for the second Tuesday of never.</li>
      </ul>
    </div>
  </section>
</main>
"""
    return shell(inner)


# --------------------------------------------------------------------------- #
# Routes                                                                       #
# --------------------------------------------------------------------------- #
@app.route("/")
def index() -> str:
    return portal()


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return portal()
    user = request.values.get("username", "")
    pwd = request.values.get("password", "")

    db = sqlite3.connect(DB_PATH)
    # VULNERABLE: string-formatted SQL. SQLi payloads land straight in the query,
    # and a tautology (' OR '1'='1) authenticates without a password.
    query = f"SELECT * FROM users WHERE username = '{user}' AND password = '{pwd}'"
    try:
        row = db.execute(query).fetchone()
    except sqlite3.Error as exc:
        db.close()
        log_auth("failure", user)
        return Response(shell(f'<div class=result><div class=card><div class=body>'
                              f'Database error: {exc}</div></div></div>'), status=500)
    db.close()

    if row:
        log_auth("success", user)
        body = (f'<div class=result><div class=card><h2>Welcome back'
                f'<span class=badge>signed in</span></h2><div class=body>'
                f'Hello, <b>{user}</b>. Your Rabbit-Hole Savings balance is '
                f'&pound;2,147,483,647. Please do not check how we calculated that.'
                f'</div></div></div>')
        return Response(shell(body), status=200)
    log_auth("failure", user)
    return Response(shell('<div class=result><div class=card><h2>Sign-in failed</h2>'
                          '<div class=body>Invalid credentials. Have you tried a '
                          'different password? Or the same one, louder?</div></div></div>'),
                    status=401)


@app.route("/search")
def search():
    term = request.args.get("q", "")
    db = sqlite3.connect(DB_PATH)
    # VULNERABLE: injectable search.
    query = f"SELECT name FROM products WHERE name LIKE '%{term}%'"
    try:
        rows = db.execute(query).fetchall()
    except sqlite3.Error as exc:
        db.close()
        return Response(shell(f'<div class=result><div class=card><div class=body>'
                              f'Search error: {exc}</div></div></div>'), status=500)
    db.close()
    items = "".join(
        f'<li><span>{r[0]}</span><span class=bal>&pound;{(i + 1) * 1000:,}.00</span></li>'
        for i, r in enumerate(rows)
    ) or '<li>No matching products. Everything is on fire, but nothing matched.</li>'
    body = (f'<div class=result><div class=card><h2>Search results</h2>'
            f'<div class=body><ul class=accounts>{items}</ul></div></div></div>')
    return Response(shell(body), status=200)


@app.route("/upload", methods=["POST"])
def upload():
    f = request.files.get("file")
    if not f:
        return Response("no file", status=400)
    # VULNERABLE: no type/extension check. A web shell lands in a watched dir,
    # which Wazuh FIM (syscheck) detects as a new file under /uploads.
    dest = os.path.join(UPLOAD_DIR, os.path.basename(f.filename))
    f.save(dest)
    return Response(f"stored {dest}", status=201)


@app.route("/run")
def run_cmd():
    # VULNERABLE: command injection. The web shell / RCE stage calls this.
    host = request.args.get("host", "")
    if not host:
        return Response("missing host", status=400)
    try:
        out = subprocess.run(
            f"ping -c1 {host}", shell=True, capture_output=True, timeout=5, text=True
        )
        return Response(out.stdout + out.stderr, mimetype="text/plain")
    except subprocess.SubprocessError as exc:
        return Response(str(exc), status=500)


@app.route("/files/<path:name>")
def files(name: str):
    return send_from_directory(UPLOAD_DIR, name)


@app.route("/download")
def download():
    # VULNERABLE: path traversal. Joins the parameter under a base dir with no sanitisation, so
    # ../ walks escape the web root and the file contents are returned (HTTP 200). This is what
    # makes the path-traversal attack produce real evidence: a 200 with the file bytes.
    name = request.args.get("file", "")
    base = "/var/www/public"
    target = os.path.normpath(os.path.join(base, name))
    try:
        with open(target, "rb") as fh:
            return Response(fh.read(), mimetype="text/plain")
    except OSError:
        return Response("not found", status=404)


@app.route("/canary/<token>")
def canary(token: str):
    # A hit here is a near-zero-false-positive detection: nothing benign ever
    # requests this path. The Wazuh rule keys on the /canary/ prefix.
    return Response(f"canary {token} tripped", status=200)


# Runs at import so it also initialises under gunicorn (idempotent).
init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
