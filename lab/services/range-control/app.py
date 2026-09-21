"""
Range control panel — the attendee's attack console.

A script-runner web UI: each button shells out to a script under scripts/ that runs a
real action against the target web app. Attack buttons have benign twins with the same
log shape, so dismissing the false positive without missing the real chain is the
triage lesson. The attack-to-detection map is the CHAIN and DECOYS tables below.

It injects nothing into TheHive directly. Cases arrive through the real path:
target logs -> Wazuh -> TheHive -> n8n.
"""

import base64
import json
import os
import subprocess
from datetime import datetime, timezone

from flask import Flask, Response, request
from breadcrumbs import emit_breadcrumbs
from network import NETWORK, network_map_html, network_table_html, MAP_CSS

# Favicon: an original targeting-reticle mark, inlined so there's no separate file.
_FAVICON_SVG = (
    "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'>"
    "<rect width='32' height='32' rx='6' fill='#0a0e14'/>"
    "<circle cx='16' cy='16' r='9' fill='none' stroke='#f5a623' stroke-width='2'/>"
    "<path d='M16 3v6M16 23v6M3 16h6M23 16h6' stroke='#f5a623' stroke-width='2'/>"
    "<circle cx='16' cy='16' r='2.6' fill='#ff4d4d'/></svg>"
)
FAVICON = "data:image/svg+xml;base64," + base64.b64encode(_FAVICON_SVG.encode()).decode()

PORT = int(os.environ.get("PANEL_PORT", "8000"))
TARGET = os.environ.get("TARGET_BASE_URL", "http://bank-web:8080")
SCRIPTS = os.path.join(os.path.dirname(__file__), "scripts")

# Every fired action is appended here as one line, so the panel's activity log survives a
# refresh and there is a durable record on disk. Mounted to ./logs on the host (compose).
ACTION_LOG = os.environ.get("ACTION_LOG", "/var/log/range/actions.log")
try:
    os.makedirs(os.path.dirname(ACTION_LOG), exist_ok=True)
except OSError:
    pass

# Pre-create the SSH/mail log files so Wazuh's logcollector opens and tails them from the
# start. Without this the files only appear on the first button press, and logcollector
# misses that first batch (it starts reading a just-appeared file from its current end).
HOSTLOG_DIR = os.environ.get("HOSTLOG_DIR", "/var/log/host")
try:
    os.makedirs(HOSTLOG_DIR, exist_ok=True)
    for _f in ("auth.log", "maillog", "proxy.log", "dataxfer.log"):
        open(os.path.join(HOSTLOG_DIR, _f), "a").close()
except OSError:
    pass
ATTACKER_IP = os.environ.get("ATTACKER_IP", "")   # every attack comes from this IP
BENIGN_IP = os.environ.get("BENIGN_IP", "")       # every benign action comes from this IP

# id -> (label, kind, rule, script, blurb). The attack chain is rendered in this order.
CHAIN = [
    ("recon_scan",   ("Recon scan",     100100, "recon_scan.sh",   "Directory and parameter sweep. Maps the app and trips the 404-burst rule.")),
    ("sqli",         ("SQL injection",  100110, "sqli.sh",         "Injects on the login and search endpoints. Auth bypass and data theft.")),
    ("brute_force",  ("Brute force",    100120, "brute_force.sh",  "Credential spray against the admin login from one source.")),
    ("webshell_rce", ("Web shell + RCE",100130, "webshell_rce.sh", "Uploads a shell to the web root, then runs a command on the host.")),
    ("c2_beacon",    ("C2 beacon",      100140, "c2_beacon.sh",    "The compromised host calls out to a flagged command-and-control domain.")),
    ("exfil",        ("Data exfiltration",100142, "exfil.sh",      "The compromised host ships gigabytes of data out to an external server.")),
    ("path_traversal",("Path traversal",100150, "path_traversal.sh","Walks out of the web root to read system files like /etc/passwd.")),
    ("ssh_brute",    ("SSH brute force",100160, "ssh_brute.sh",    "Password spray against the host's SSH from the attacker IP that breaks through to a login. The takeover.")),
    ("phishing",     ("Phishing email", 100170, "phishing.sh",     "A credential-harvesting email delivered to a finance user.")),
]

# Benign twins: same log shape as an attack, harmless intent. The decoys to dismiss.
DECOYS = [
    ("backup",          ("Backup job",      100143, "backup.sh",          "Nightly backup to the internal server via Veeam. Looks like exfiltration.")),
    ("admin_login",     ("Admin login",     100121, "admin_login.sh",     "A real admin mistypes then succeeds. Looks like brute force.")),
    ("cdn_beacon",      ("CDN beacon",      100141, "cdn_beacon.sh",      "Marketing bot calling a known CDN. Looks like C2.")),
    ("crawler",         ("Heavy crawler",   100151, "crawler.sh",         "Legitimate high-volume crawler. Looks like a scan.")),
    ("ssh_admin",       ("Admin SSH login", 100161, "ssh_admin.sh",       "An engineer logs in over SSH from the IT workstation. Same event as the compromise, clean source.")),
    ("newsletter",      ("Newsletter email",100171, "newsletter.sh",      "A real newsletter to the same user. Looks like the phish.")),
]

# What each service is, for the panel's directory. (label, url, port, blurb, user, pass)
SERVICES = [
    ("Bank website", "http://web.localhost",     "8080", "The victim: the bank's public-facing site. You are the outside attacker who compromised it.", "", ""),
    ("TheHive",         "http://thehive.localhost", "9000", "Case management. Your attacks become cases the AI triages.", "analyst@brucon.local", "brucon2026"),
    ("n8n",             "http://n8n.localhost",      "5678", "The workflow editor where you build the triage automation.", "admin@brucon.local", "Brucon2026"),
    ("Wazuh SIEM",      "http://wazuh.localhost",   "8443", "The SIEM dashboard with raw detections.", "admin", "brucon2026"),
]

ALL = dict(CHAIN + DECOYS)
KIND = {bid: "ATTACK" for bid, _ in CHAIN}
KIND.update({bid: "BENIGN" for bid, _ in DECOYS})

# Buttons whose malicious IP is the destination, not the source.
OUTBOUND = {"c2_beacon", "exfil"}
# Decoy -> the clean source shown in the confirm dialog.
BENIGN_SOURCE = {
    "backup": "internal backup server (clean)",
    "admin_login": "internal IT workstation (clean)",
    "cdn_beacon": "internal marketing host (clean)",
    "crawler": "external crawler (clean)",
    "ssh_admin": "internal IT workstation (clean)",
    "newsletter": "external mail sender (clean)",
}


def _malicious_pool():
    path = os.environ.get("MALICIOUS_IPS_FILE", "/app/threat-intel/malicious-ips.txt")
    ips = []
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    ips.append(line.split()[0])
    except OSError:
        pass
    return ips


def pick_malicious_ip():
    import random
    pool = _malicious_pool()
    return random.choice(pool) if pool else "185.220.101.44"


app = Flask(__name__)


def record_action(label: str, kind: str, rule, status: str, ip: str = "") -> None:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {kind:<6} {label} (rule {rule}) [{ip or '-'}] - {status}\n"
    try:
        with open(ACTION_LOG, "a", encoding="utf-8") as fh:
            fh.write(line)
    except OSError:
        pass


def fire_button(bid, entry, attack):
    label, rule, _script, blurb = entry
    cls = "atk" if attack else "ben"
    atk_js = "true" if attack else "false"
    return (
        f'<button class="node {cls}" onclick="fire(\'{bid}\',\'{label}\',{atk_js},this)">'
        f'<span class="rid">{rule}</span>'
        f'<span class="lbl">{label}</span>'
        f'<span class="blurb">{blurb}</span>'
        f'</button>'
    )


def service_card(name, url, port, blurb, user, pw):
    if user:
        creds = (
            '<div class=creds>'
            f'<button class=chip onclick="cp(event,\'{user}\')">{user}<span class=cpi>copy</span></button>'
            f'<button class=chip onclick="cp(event,\'{pw}\')">{pw}<span class=cpi>copy</span></button>'
            '</div>'
        )
    else:
        creds = '<div class=creds><span class=nocred>no login needed</span></div>'
    return (
        f'<div class=svc title="{blurb}">'
        f'<a class=svc-name href="{url}" target="_blank" rel="noopener">{name} &#8599;</a>'
        f'<div class=svc-url>{url} <span class=svc-port>:{port}</span></div>'
        f'{creds}</div>'
    )


def render() -> str:
    chain = "".join(fire_button(b, e, True) for b, e in CHAIN)
    decoys = "".join(fire_button(b, e, False) for b, e in DECOYS)
    svc = "".join(service_card(n, u, p, b, user, pw) for n, u, p, b, user, pw in SERVICES)
    return f"""<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>SOC Range — Attack Console</title>
<link rel="icon" href="{FAVICON}">
<style>{CSS}{MAP_CSS}</style></head><body>
<header class=bar>
  <div class=brand id=wm><span class=b1>Bru</span><span class=b2>CON</span><span class=byear>2026</span></div>
  <div class=titles>
    <div class=eyebrow>SOC Range</div>
    <div class=title>Attack Console</div>
  </div>
  <div class=live><span class=dot></span>range armed</div>
</header>

<div class=shell>
<aside class=sidebar>
  <div class=side-head>
    <div class=eyebrow>Quick access</div>
    <h2 class=side-title>Where things live</h2>
    <p class=side-note>Open in Chrome, Edge or Firefox. Safari users: use the <code>:port</code> links. Click a credential to copy it.</p>
  </div>
  <div class=side-services>{svc}</div>
</aside>

<main>
  <section class="panel outpanel">
    <div class=phead><h2>Console</h2><p>Live output from the last action &mdash; what the attack actually did.</p></div>
    <pre id=out class=console>range armed. fire a button to begin.</pre>
  </section>

  <section class=panel>
    <div class=phead><h2>Kill chain <span class=tag>attacks</span></h2><p>Fire in order to build the incident.</p></div>
    <div class="rail">{chain}</div>
  </section>

  <section class=panel>
    <div class=phead><h2>Decoys <span class="tag ok">benign</span></h2><p>Same shape as an attack, harmless intent — the false positives the AI should dismiss.</p></div>
    <div class="grid">{decoys}</div>
  </section>

  <section class=panel>
    <div class=phead><h2>Activity log</h2><p>Every action you fire, recorded to <code>lab/logs/actions.log</code>. Newest at the bottom.</p></div>
    <div class=logwrap>
      <table class=logtable>
        <thead><tr><th>Time (UTC)</th><th>Type</th><th>Action</th><th>Rule</th><th>Source IP</th><th>Status</th></tr></thead>
        <tbody id=logbody></tbody>
      </table>
    </div>
  </section>

  {network_map_html(NETWORK, ATTACKER_IP)}

  {network_table_html(NETWORK)}
</main>
</div>

<div id=modal class=modal hidden onclick="if(event.target===this)resolveConfirm(false)">
  <div class=modal-card role=dialog aria-modal=true aria-labelledby=modal-title>
    <div class=modal-kicker id=modal-kicker>&#9888; Confirm attack</div>
    <div class=modal-title id=modal-title>Run this action?</div>
    <p class=modal-body id=modal-body>This runs an action against the bank site. Continue?</p>
    <div class=modal-actions>
      <button class=btn-ghost onclick="resolveConfirm(false)">Deny</button>
      <button class=btn-danger id=modal-go onclick="resolveConfirm(true)">Accept</button>
    </div>
  </div>
</div>

<script>
async function cp(e, text){{
  e.preventDefault(); e.stopPropagation();
  try {{
    await navigator.clipboard.writeText(text);
    const s = e.currentTarget.querySelector('.cpi'); const o = s.textContent;
    s.textContent = 'copied'; e.currentTarget.classList.add('ok');
    setTimeout(()=>{{ s.textContent = o; e.currentTarget.classList.remove('ok'); }}, 1000);
  }} catch (_) {{}}
}}
// --- confirm modal (accept / deny, every action) ---
let _confirmResolve = null;
function askConfirm(label, isAttack, pv){{
  const card = document.querySelector('#modal .modal-card');
  const go = document.getElementById('modal-go');
  card.classList.toggle('benign', !isAttack);
  go.classList.toggle('benign', !isAttack);
  document.getElementById('modal-kicker').innerHTML =
    isAttack ? '\\u26a0 Confirm attack' : 'Confirm action';
  document.getElementById('modal-title').textContent =
    'Run \\u201c' + label + (isAttack ? '\\u201d attack?' : '\\u201d?');
  let ipline = '';
  if (pv && pv.ip) {{
    const verb = pv.role === 'destination' ? 'will beacon out to' : 'will come from';
    ipline = ' This action ' + verb + ' ' + pv.ip + ' (flagged on AbuseIPDB).';
  }} else if (pv && pv.label) {{
    ipline = ' Source: ' + pv.label + '.';
  }}
  document.getElementById('modal-body').textContent = (isAttack
    ? 'This runs a real attack against the bank site and will raise a case in the SOC pipeline.'
    : 'This runs a benign action \\u2014 the harmless twin the AI should learn to dismiss.')
    + ipline + ' Continue?';
  go.textContent = isAttack ? 'Fire attack' : 'Run action';
  document.getElementById('modal').hidden = false;
  go.focus();
  return new Promise(res => {{ _confirmResolve = res; }});
}}
function resolveConfirm(v){{
  document.getElementById('modal').hidden = true;
  const r = _confirmResolve; _confirmResolve = null;
  if (r) r(v);
}}
document.addEventListener('keydown', e => {{
  if (e.key === 'Escape' && !document.getElementById('modal').hidden) resolveConfirm(false);
}});

// --- activity log: table built from the server record file (survives refresh) ---
async function loadLog(){{
  let text = '';
  try {{ const r = await fetch('/log'); text = await r.text(); }} catch (e) {{}}
  const body = document.getElementById('logbody');
  const lines = text.split('\\n').filter(l => l.trim());
  if (!lines.length) {{
    body.innerHTML = '<tr><td colspan=6 class=logempty>No actions recorded yet. Fire a button to begin.</td></tr>';
    return;
  }}
  const re = /^\\[(.+?)\\]\\s+(\\S+)\\s+(.+?)\\s+\\(rule\\s+(.+?)\\)\\s+\\[(.+?)\\]\\s+-\\s+(.+)$/;
  body.innerHTML = lines.map(l => {{
    const mm = l.match(re);
    if (!mm) return '<tr><td colspan=6>' + l + '</td></tr>';
    const kc = mm[2] === 'ATTACK' ? 'k-atk' : 'k-ben';
    return '<tr><td class=lt-time>' + mm[1] + '</td>'
      + '<td><span class="ktag ' + kc + '">' + mm[2] + '</span></td>'
      + '<td class=lt-act>' + mm[3] + '</td>'
      + '<td class=lt-rule>' + mm[4] + '</td>'
      + '<td class=lt-ip>' + mm[5] + '</td>'
      + '<td>' + mm[6] + '</td></tr>';
  }}).join('');
  const w = document.querySelector('.logwrap'); if (w) w.scrollTop = w.scrollHeight;
}}
window.addEventListener('DOMContentLoaded', loadLog);

// The action id and IP travel in the POST body, never the URL. Ad-blockers and privacy
// extensions match request URLs against filter lists (e.g. EasyPrivacy blocks anything
// containing "beacon"), and a blocked fetch surfaces as "TypeError: Failed to fetch"
// (net::ERR_BLOCKED_BY_CLIENT). Keeping ids like c2_beacon out of the URL dodges that.
const JSON_POST = body => ({{method:'POST', headers:{{'Content-Type':'application/json'}}, body: JSON.stringify(body)}});
async function fire(id, label, isAttack, el){{
  let pv = {{}};
  try {{ const r = await fetch('/preview', JSON_POST({{id}})); pv = await r.json(); }} catch (e) {{}}
  const ok = await askConfirm(label, isAttack, pv);
  if (!ok) return;
  el.classList.add('firing');
  const out = document.getElementById('out');
  out.textContent = 'running ' + label + '\\u2026';
  try {{
    const r = await fetch('/fire', JSON_POST({{id, ip: (pv && pv.ip) || ''}}));
    out.textContent = (await r.text()).trim() || '(no output)';
  }} catch (e) {{
    out.textContent = 'error: ' + e;
  }} finally {{
    el.classList.remove('firing');
    el.classList.add('fired');
    setTimeout(()=>el.classList.remove('fired'), 1200);
    loadLog();
  }}
}}
</script>
</body></html>"""


CSS = """
:root{
  --bg:#0a0e14; --surface:#111823; --surface2:#161f2e; --line:#25324a;
  --text:#cdd6e4; --muted:#7b8798; --amber:#f5a623; --atk:#ff4d4d; --ben:#2fd08a;
  --mono:ui-monospace,"SF Mono",SFMono-Regular,Menlo,Consolas,monospace;
}
*{box-sizing:border-box}
body{margin:0;background:
  radial-gradient(1200px 600px at 80% -10%, rgba(245,166,35,.06), transparent 60%),
  var(--bg);color:var(--text);font-family:var(--mono);line-height:1.5}
a{color:inherit;text-decoration:none}

.bar{display:flex;align-items:center;gap:22px;padding:16px 26px;
  border-bottom:1px solid var(--line);position:sticky;top:0;z-index:5;
  background:rgba(10,14,20,.9);backdrop-filter:blur(6px)}
.logo{height:44px;width:auto;display:block}
.brand{font-weight:800;font-size:22px;letter-spacing:-.5px;
  font-family:system-ui,-apple-system,"Helvetica Neue",Arial,sans-serif}
.brand .b1{color:var(--text)} .brand .b2{color:var(--amber)}
.brand .byear{color:var(--muted);font-weight:600;font-size:12px;margin-left:6px;vertical-align:super}
.titles{border-left:1px solid var(--line);padding-left:22px}
.eyebrow{color:var(--amber);font-size:11px;letter-spacing:3px;text-transform:uppercase}
.title{font-size:18px;font-weight:700;letter-spacing:.5px}
.live{margin-left:auto;color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:2px;
  display:flex;align-items:center;gap:8px}
.live .dot{width:8px;height:8px;border-radius:50%;background:var(--ben);
  box-shadow:0 0 0 0 rgba(47,208,138,.6);animation:pulse 2s infinite}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(47,208,138,.5)}70%{box-shadow:0 0 0 7px rgba(47,208,138,0)}100%{box-shadow:0 0 0 0 rgba(47,208,138,0)}}

/* two-column shell: sticky reference sidebar flush to the left, console beside it */
.shell{display:flex;align-items:flex-start}
.sidebar{flex:none;width:322px;align-self:stretch;background:var(--surface);
  border-right:1px solid var(--line);position:sticky;top:77px;
  max-height:calc(100vh - 77px);overflow-y:auto;overflow-x:hidden;padding:20px 18px;
  scrollbar-width:thin;scrollbar-color:var(--line) transparent}
.sidebar::-webkit-scrollbar{width:8px}
.sidebar::-webkit-scrollbar-track{background:transparent}
.sidebar::-webkit-scrollbar-thumb{background:var(--line);border-radius:8px}
.sidebar:hover::-webkit-scrollbar-thumb{background:var(--muted)}
.side-head{padding:0 2px 14px;border-bottom:1px solid var(--line);margin-bottom:16px}
.side-title{margin:6px 0 0;font-size:13px;letter-spacing:3px;text-transform:uppercase;color:var(--text)}
.side-note{margin:9px 0 0;color:var(--muted);font-size:11.5px;line-height:1.55}
.side-note code{color:var(--amber);font-size:11px}
.side-services{display:flex;flex-direction:column;gap:10px}

main{flex:1;min-width:0;max-width:1120px;padding:26px 28px 26px 44px;display:grid;gap:26px}
.panel{border:1px solid var(--line);border-radius:12px;background:var(--surface);overflow:hidden}
.phead{padding:16px 20px;border-bottom:1px solid var(--line);background:var(--surface2)}
.phead h2{margin:0;font-size:13px;letter-spacing:3px;text-transform:uppercase;color:var(--text)}
.phead p{margin:4px 0 0;color:var(--muted);font-size:12.5px}

/* kill-chain rail: connected stage nodes */
.rail{display:flex;flex-wrap:wrap;gap:0;padding:22px 20px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:14px;padding:20px}

.node{position:relative;text-align:left;cursor:pointer;color:var(--text);
  background:var(--surface2);border:1px solid var(--line);border-radius:10px;
  padding:14px 16px;display:flex;flex-direction:column;gap:6px;transition:.15s;font-family:var(--mono)}
.node:hover{transform:translateY(-2px)}
.node .rid{font-size:11px;color:var(--muted);letter-spacing:1px}
.node .lbl{font-size:15px;font-weight:700}
.node .blurb{font-size:12px;color:var(--muted);line-height:1.45}
.node:focus-visible{outline:2px solid var(--amber);outline-offset:2px}

/* rail nodes flow with connectors */
.rail .node{flex:1 1 300px;margin:8px}
.rail .node::after{content:"";position:absolute;right:-8px;top:50%;width:16px;height:2px;
  background:var(--line)}
.rail .node:last-child::after{display:none}

.node.atk{border-left:3px solid var(--atk)}
.node.atk:hover{border-color:var(--atk);box-shadow:0 8px 24px -12px rgba(255,77,77,.5)}
.node.atk .lbl{color:#ffd7d7}
.node.ben{border-left:3px solid var(--ben)}
.node.ben:hover{border-color:var(--ben);box-shadow:0 8px 24px -12px rgba(47,208,138,.4)}
.node.ben .lbl{color:#c9f5e2}
.node.firing{opacity:.6}
.node.fired{box-shadow:0 0 0 2px var(--amber) inset}

.console{margin:0;padding:18px 20px;background:#060a10;color:#9fe6c0;
  font-size:12.5px;white-space:pre-wrap;min-height:120px;max-height:280px;overflow:auto}

.svc{border:1px solid var(--line);border-radius:9px;padding:10px 12px;background:var(--surface2);
  display:flex;flex-direction:column;gap:4px;transition:border-color .15s}
.svc:hover{border-color:var(--amber)}
.svc-name{font-weight:700;font-size:13px;color:var(--text)}
.svc-url{color:var(--amber);font-size:12px}
.svc-port{color:var(--muted);font-size:11px}
.creds{display:flex;flex-wrap:wrap;gap:6px;margin-top:7px}
.chip{font-family:var(--mono);font-size:11.5px;background:#0d1420;border:1px solid var(--line);
  color:var(--text);border-radius:7px;padding:5px 8px;cursor:pointer;display:inline-flex;
  gap:7px;align-items:center}
.chip:hover{border-color:var(--amber)}
.chip.ok{border-color:var(--ben)}
.chip .cpi{color:var(--muted);font-size:9.5px;text-transform:uppercase;letter-spacing:1px}
.nocred{color:var(--muted);font-size:12px;font-style:italic}

/* confirm-attack modal */
.modal{position:fixed;inset:0;z-index:50;display:flex;align-items:center;justify-content:center;
  padding:20px;background:rgba(4,7,12,.72);backdrop-filter:blur(3px)}
.modal[hidden]{display:none}
.modal-card{width:min(430px,100%);background:var(--surface);border:1px solid var(--line);
  border-radius:14px;padding:22px 22px 18px;box-shadow:0 24px 60px -20px rgba(0,0,0,.75)}
.modal-kicker{color:var(--atk);font-size:11px;letter-spacing:2px;text-transform:uppercase;font-weight:700}
.modal-title{font-size:17px;font-weight:700;margin:9px 0 6px;color:var(--text)}
.modal-body{color:var(--muted);font-size:13px;line-height:1.55;margin:0 0 18px}
.modal-actions{display:flex;justify-content:flex-end;gap:10px}
.btn-ghost,.btn-danger{font-family:var(--mono);font-size:13px;border-radius:8px;
  padding:9px 16px;cursor:pointer;border:1px solid var(--line)}
.btn-ghost{background:transparent;color:var(--text)}
.btn-ghost:hover{border-color:var(--muted)}
.btn-danger{background:var(--atk);border-color:var(--atk);color:#2a0b0b;font-weight:700}
.btn-danger:hover{filter:brightness(1.08)}
.btn-danger:focus-visible,.btn-ghost:focus-visible{outline:2px solid var(--amber);outline-offset:2px}
.modal-card.benign .modal-kicker{color:var(--ben)}
.btn-danger.benign{background:var(--ben);border-color:var(--ben);color:#04140d}

/* activity-log table */
.logwrap{max-height:300px;overflow:auto;scrollbar-width:thin;scrollbar-color:var(--line) transparent}
.logwrap::-webkit-scrollbar{width:8px;height:8px}
.logwrap::-webkit-scrollbar-track{background:transparent}
.logwrap::-webkit-scrollbar-thumb{background:var(--line);border-radius:8px}
.logwrap:hover::-webkit-scrollbar-thumb{background:var(--muted)}
.logtable{width:100%;border-collapse:collapse;font-size:12.5px}
.logtable th,.logtable td{text-align:left;padding:9px 14px;border-bottom:1px solid var(--line);white-space:nowrap}
.logtable thead th{position:sticky;top:0;z-index:1;background:var(--surface2);color:var(--muted);
  font-size:10px;letter-spacing:1.5px;text-transform:uppercase;font-weight:600}
.logtable tbody tr:last-child td{border-bottom:0}
.logtable tbody tr:hover{background:var(--surface2)}
.lt-time{color:var(--muted);font-variant-numeric:tabular-nums}
.lt-act{color:var(--text);font-weight:600;white-space:normal}
.lt-rule{color:var(--muted)}
.lt-ip{color:var(--muted);font-variant-numeric:tabular-nums}
.logempty{color:var(--muted);font-style:italic;text-align:center;padding:22px}
.ktag{display:inline-block;font-size:10px;font-weight:700;letter-spacing:1px;padding:2px 8px;border-radius:20px}
.ktag.k-atk{background:rgba(255,77,77,.15);color:#ff9b9b}
.ktag.k-ben{background:rgba(47,208,138,.15);color:#8fe9c4}

/* source-IP identity cards */
.idwrap{display:grid;grid-template-columns:1fr 1fr;gap:14px;padding:20px}
@media (max-width:640px){.idwrap{grid-template-columns:1fr}}
.idcard{border:1px solid var(--line);border-left-width:3px;border-radius:8px;
  padding:10px 12px;background:var(--surface2);display:flex;flex-direction:column;gap:6px}
.idcard.atk{border-left-color:var(--atk)}
.idcard.ben{border-left-color:var(--ben)}
.idkind{font-size:10px;letter-spacing:1.5px;text-transform:uppercase;color:var(--muted)}
.idcard.atk .idkind{color:#ff9b9b}
.idcard.ben .idkind{color:#8fe9c4}
.chip.big{font-size:13px;font-weight:600;align-self:flex-start;padding:5px 10px}

/* top band: source IPs beside the live console */
.topband{display:grid;grid-template-columns:1fr 1fr;gap:26px;align-items:stretch}
@media (max-width:820px){.topband{grid-template-columns:1fr}}
.outpanel{display:flex;flex-direction:column}
.outpanel .console{flex:1;margin:0}
.idpanel .idwrap{padding:16px 20px 20px}

/* little badges in section headings */
.phead h2 .tag{font-size:10px;letter-spacing:2px;text-transform:uppercase;vertical-align:middle;
  margin-left:8px;padding:2px 8px;border-radius:20px;background:rgba(255,77,77,.15);color:#ff9b9b}
.phead h2 .tag.ok{background:rgba(47,208,138,.15);color:#8fe9c4}

@media (max-width:900px){
  .shell{flex-direction:column}
  .sidebar{position:static;width:auto;max-height:none;overflow:visible;
    border-right:0;border-bottom:1px solid var(--line)}
  .side-services{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr))}
  main{max-width:none}
}
@media (max-width:640px){.bar{flex-wrap:wrap;gap:12px}.titles{border:0;padding:0}.live{margin:0}}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
"""


@app.route("/")
def index() -> str:
    return render()


# The id and IP arrive in the JSON body, not the URL — an ad-blocker/privacy extension
# matches URLs against filter lists and blocks e.g. anything containing "beacon"
# (net::ERR_BLOCKED_BY_CLIENT), which the panel would report as "Failed to fetch".
def _body():
    return request.get_json(silent=True) or request.form or {}


@app.route("/preview", methods=["POST"])
def preview():
    button_id = _body().get("id", "")
    if button_id not in ALL:
        return Response("unknown button", status=404)
    if KIND.get(button_id) == "ATTACK":
        role = "destination" if button_id in OUTBOUND else "source"
        payload = {"ip": pick_malicious_ip(), "kind": "attacker", "role": role}
    else:
        payload = {"ip": "", "kind": "benign", "label": BENIGN_SOURCE.get(button_id, "clean source")}
    return Response(json.dumps(payload), mimetype="application/json")


@app.route("/fire", methods=["POST"])
def fire():
    body = _body()
    button_id = body.get("id", "")
    entry = ALL.get(button_id)
    if not entry:
        return Response(f"unknown button: {button_id}", status=404)
    label, rule, script, _blurb = entry
    path = os.path.join(SCRIPTS, script)
    env = {**os.environ, "TARGET_BASE_URL": TARGET}
    chosen_ip = body.get("ip", "")
    if chosen_ip and KIND.get(button_id) == "ATTACK":
        env["MALICIOUS_DEST_IP" if button_id in OUTBOUND else "ATTACKER_IP"] = chosen_ip
    try:
        proc = subprocess.run(["bash", path], env=env, capture_output=True, text=True, timeout=60)
    except subprocess.SubprocessError as exc:
        record_action(label, KIND.get(button_id, "?"), rule, "error", chosen_ip)
        return Response(f"error running {script}: {exc}", status=500)
    status = "ok" if proc.returncode == 0 else f"exit {proc.returncode}"
    record_action(label, KIND.get(button_id, "?"), rule, status, chosen_ip)
    if proc.returncode == 0:
        emit_breadcrumbs(button_id)
    return Response(proc.stdout + proc.stderr, mimetype="text/plain")


@app.route("/log")
def action_log():
    try:
        with open(ACTION_LOG, encoding="utf-8") as fh:
            return Response(fh.read(), mimetype="text/plain")
    except OSError:
        return Response("", mimetype="text/plain")


@app.route("/healthz")
def healthz():
    # Liveness probe for the container healthcheck.
    return "ok", 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)
