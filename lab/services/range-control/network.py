"""
The company network map for the panel. NETWORK is the single source of truth: each row is
one host. network_map_html() renders a left-to-right layout — Internet → Firewall → DMZ →
Core → Endpoints — as labelled columns of host cards with an amber SIEM tap bar. Hosts are
positioned by column/row index so adding a host is a one-line data edit. The map never
states whether a host is a container or authored telemetry.

Row: (hostname, ip, zone, role, log_source)
"""

from html import escape

# Column order for the left-to-right layout.
# "Internet" and "Firewall" are synthetic (not in NETWORK); they appear as diagram elements.
COLUMN_ORDER = ["DMZ", "Core servers", "Endpoints", "Security"]

NETWORK = [
    # DMZ column
    ("web-prod-01",          "10.20.0.10",  "DMZ",
     "Public bank website.", "web access and auth logs"),
    ("mail-gateway-01",      "10.20.0.20",  "DMZ",
     "Inbound and outbound mail gateway.", "mail gateway log"),
    ("vpn-corp-01",          "10.20.0.30",  "DMZ",
     "Remote-access VPN for staff working from home.", "VPN session log"),
    ("proxy-01",             "10.20.0.5",   "DMZ",
     "Forward web proxy — egress for all internal browsing.", "proxy egress log"),
    # Core servers column
    ("dc-01",                "10.20.10.10", "Core servers",
     "Active Directory domain controller and DNS.", "Windows security log"),
    ("database-01",          "10.20.10.20", "Core servers",
     "Core banking database (PostgreSQL).", "PostgreSQL log"),
    ("fileserver-01",        "10.20.10.30", "Core servers",
     "Corporate file server (SMB shares).", "SMB access log"),
    ("backup-01",            "10.20.10.40", "Core servers",
     "Backup storage server (Veeam).", "backup job log"),
    # Endpoints (rendered as one cluster node — five workstations)
    ("workstation-finance-01","10.20.20.11","Endpoints",
     "Finance workstation.", "endpoint log"),
    ("workstation-finance-02","10.20.20.12","Endpoints",
     "Finance workstation.", "endpoint log"),
    ("workstation-hr-01",    "10.20.20.31", "Endpoints",
     "HR workstation.", "endpoint log"),
    ("workstation-it-01",    "10.20.20.41", "Endpoints",
     "IT workstation.", "endpoint log"),
    ("workstation-sales-01", "10.20.20.51", "Endpoints",
     "Sales workstation.", "endpoint log"),
    # SIEM (amber tap bar across all segments)
    ("wazuh.manager",        "internal",    "Security",
     "The SIEM.", ""),
]

# ── Layout constants ─────────────────────────────────────────────────────────
# Fixed coordinate space; the wrapper scrolls horizontally on narrow screens.
_W  = 1060   # stage width
_H  = 480    # stage height

# Column x-centres (absolute left edge of each node band)
_COL_X = {
    "internet":     16,
    "firewall":    210,
    "dmz":         390,
    "core":        596,
    "endpoints":   812,
}

_NODE_W  = 160   # node width
_NODE_H  = 46    # node height per row
_DEV_H   = 44    # device pill height

# DMZ rows (top-to-bottom): web-prod-01, mail-gateway-01, vpn-corp-01, proxy-01
_DMZ_TOP = 30
_DMZ_GAP = 88

# Core rows: dc-01, database-01, fileserver-01, backup-01
_CORE_TOP = 30
_CORE_GAP = 88

# Attacker node centre-y
_ATK_Y = 210


def _node_top(col_top, row_gap, idx):
    return col_top + idx * row_gap


def _cx(col_key):
    """Left edge of node in col → right edge (connect point)."""
    return _COL_X[col_key] + _NODE_W


def _lx(col_key):
    """Left edge of node in col."""
    return _COL_X[col_key]


# ── SVG edges ────────────────────────────────────────────────────────────────

_FW_W = 150   # firewall pill width


def _build_svg(attacker_ip):  # noqa: ARG001  (ip not used in edge coords)
    """Return the SVG layer: vertical dashed dividers between the section columns plus the
    amber SIEM tap line. No node-to-node edges."""
    # One dashed divider centred in each gap between the five section columns.
    gaps = [
        (_COL_X["internet"] + _NODE_W + _COL_X["firewall"]) // 2,
        (_COL_X["firewall"] + _FW_W + _COL_X["dmz"]) // 2,
        (_COL_X["dmz"] + _NODE_W + _COL_X["core"]) // 2,
        (_COL_X["core"] + _NODE_W + _COL_X["endpoints"]) // 2,
    ]
    sep_top, sep_bot = 8, _H - 50
    seps = [
        f'<path d="M{x},{sep_top} L{x},{sep_bot}" '
        f'stroke="#25324a" stroke-width="1.4" stroke-dasharray="3 5" opacity=".65"/>'
        for x in gaps
    ]
    sep_svg = "\n    ".join(seps)

    siem_y   = _H - 38
    siem_x0  = _COL_X["dmz"]
    siem_x1  = _COL_X["endpoints"] + _NODE_W
    siem_svg = (
        f'<path d="M{siem_x0},{siem_y} L{siem_x1},{siem_y}" '
        f'stroke="#f5a623" stroke-width="1.4" stroke-dasharray="3 4" opacity=".8"/>'
    )
    return (
        f'<svg viewBox="0 0 {_W} {_H}" aria-hidden="true">'
        f'\n    {sep_svg}'
        f'\n    {siem_svg}'
        f'\n  </svg>'
    )


# ── Node / device helpers ────────────────────────────────────────────────────

def _node(hostname, ip, top, left, role, extra_cls=""):
    cls = f"n {extra_cls}".strip()
    style = f"left:{left}px;top:{top}px;width:{_NODE_W}px"
    return (
        f'<div class="{cls}" style="{style}" title="{escape(role)}">'
        f'<b>{escape(hostname)}</b>'
        f'<span>{escape(ip)}</span>'
        f'</div>'
    )


def _dev(label, top, left, width=150, height=_DEV_H, radius=10):
    style = f"left:{left}px;top:{top}px;width:{width}px;height:{height}px;border-radius:{radius}px"
    return f'<div class="dev" style="{style}"><b>{escape(label)}</b></div>'


def _cluster(hostnames, top, left, width=168, min_height=230):
    names_html = "<br>".join(escape(h) for h in hostnames)
    style = (
        f"left:{left}px;top:{top}px;"
        f"width:{width}px;min-height:{min_height}px"
    )
    return (
        f'<div class="n cluster" style="{style}" '
        f'title="Endpoint workstations on the 10.20.20.0/24 VLAN">'
        f'<b>endpoints</b>'
        f'<span>10.20.20.0/24<br>{names_html}</span>'
        f'</div>'
    )


# ── Public interface ─────────────────────────────────────────────────────────

def network_map_html(network, attacker_ip):
    """Render the company network as a left-to-right flow diagram."""
    rows_by_zone = {}
    for row in network:
        rows_by_zone.setdefault(row[2], []).append(row)

    dmz_rows  = rows_by_zone.get("DMZ", [])
    core_rows = rows_by_zone.get("Core servers", [])
    ep_rows   = rows_by_zone.get("Endpoints", [])

    nodes = []

    # Attacker node (synthetic)
    nodes.append(
        _node("attacker", escape(attacker_ip),
              top=_ATK_Y, left=_COL_X["internet"],
              role="Outside the perimeter. Every attack starts here.")
    )

    # Firewall device pill
    fw_top = _ATK_Y
    nodes.append(_dev("firewall", top=fw_top, left=_COL_X["firewall"]))

    # Column labels (absolutely positioned text above first node)
    col_labels = [
        ("Internet",  _COL_X["internet"]),
        ("Firewall",  _COL_X["firewall"]),
        ("DMZ",       _COL_X["dmz"]),
        ("Core",      _COL_X["core"]),
        ("Endpoints", _COL_X["endpoints"]),
    ]
    label_html = "".join(
        f'<div class="col-label" style="left:{lx}px;width:{_NODE_W}px">'
        f'{escape(lbl)}</div>'
        for lbl, lx in col_labels
    )

    # DMZ nodes
    for idx, row in enumerate(dmz_rows):
        hostname, ip, _zone, role, _src = row
        top = _node_top(_DMZ_TOP, _DMZ_GAP, idx)
        nodes.append(_node(hostname, ip, top=top, left=_COL_X["dmz"], role=role))

    # Core nodes
    for idx, row in enumerate(core_rows):
        hostname, ip, _zone, role, _src = row
        top = _node_top(_CORE_TOP, _CORE_GAP, idx)
        nodes.append(_node(hostname, ip, top=top, left=_COL_X["core"], role=role))

    # Endpoints cluster
    ep_names = [r[0] for r in ep_rows]
    nodes.append(_cluster(ep_names, top=30, left=_COL_X["endpoints"]))

    # SIEM amber bar (device pill spanning DMZ → Endpoints columns)
    siem_left  = _COL_X["dmz"]
    siem_width = _COL_X["endpoints"] + _NODE_W - siem_left
    siem_y     = _H - 38
    nodes.append(_dev("wazuh.manager · SIEM tap on every segment",
                      top=siem_y, left=siem_left,
                      width=siem_width, height=30, radius=8))

    svg = _build_svg(attacker_ip)
    nodes_html = "\n  ".join(nodes)

    stage = (
        f'<div class="stage" style="width:{_W}px;height:{_H}px">'
        f'\n  {svg}'
        f'\n  {label_html}'
        f'\n  {nodes_html}'
        f'\n</div>'
    )

    return (
        '<section class="panel netmap">'
        '<div class=phead>'
        '<h2>Company network <span class="tag ok">bank of wonderland</span></h2>'
        '</div>'
        '<div class="stage-wrap">'
        f'{stage}'
        '</div>'
        '</section>'
    )


def network_table_html(network):
    """Render the full host inventory as a table. Driven by NETWORK so it stays in sync
    with the map: hostname, IP, zone, role and the telemetry the host sends to the SIEM."""
    rows = []
    for hostname, ip, zone, role, log_source in network:
        telemetry = escape(log_source) if log_source else "&mdash;"
        rows.append(
            "<tr>"
            f"<td class=nt-host>{escape(hostname)}</td>"
            f"<td class=nt-ip>{escape(ip)}</td>"
            f"<td>{escape(zone)}</td>"
            f"<td class=nt-role>{escape(role)}</td>"
            f"<td class=nt-log>{telemetry}</td>"
            "</tr>"
        )
    body = "\n      ".join(rows)
    return (
        '<section class="panel">'
        '<div class=phead>'
        '<h2>Company network <span class="tag ok">host inventory</span></h2>'
        '<p>Every host on the bank of wonderland network, its zone and the telemetry '
        'it sends to the SIEM.</p>'
        '</div>'
        '<div class="nettable-wrap">'
        '<table class="nettable">'
        '<thead><tr><th>Host</th><th>IP address</th><th>Zone</th>'
        '<th>Role</th><th>Telemetry</th></tr></thead>'
        f'<tbody>\n      {body}\n    </tbody>'
        '</table>'
        '</div>'
        '</section>'
    )


MAP_CSS = """
/* ── network map: left-to-right flow diagram ── */
.netmap .stage-wrap{overflow-x:auto;padding:22px 20px 24px;scrollbar-width:thin;
  scrollbar-color:var(--line) transparent}
.netmap .stage-wrap::-webkit-scrollbar{height:9px}
.netmap .stage-wrap::-webkit-scrollbar-thumb{background:var(--line);border-radius:9px}
.netmap .stage{position:relative;margin:0 auto}
.netmap .stage svg{position:absolute;inset:0;width:100%;height:100%;
  pointer-events:none;overflow:visible}
/* column header labels */
.netmap .col-label{position:absolute;top:-22px;font-size:10px;letter-spacing:2px;
  text-transform:uppercase;color:var(--muted);text-align:center}
/* host nodes */
.netmap .n{position:absolute;border:1px solid var(--line);
  border-left:3px solid var(--line);border-radius:8px;background:var(--surface2);
  padding:7px 10px;display:flex;flex-direction:column;justify-content:center;
  gap:2px;z-index:2}
.netmap .n b{font-size:12px;font-weight:700;color:var(--text);letter-spacing:.2px}
.netmap .n span{font-size:9.5px;color:var(--muted);font-variant-numeric:tabular-nums;
  line-height:1.5}
/* SIEM node */
.netmap .n.siem{border-left-color:var(--amber)}
.netmap .n.siem b{color:#ffdfa6}
/* cluster */
.netmap .n.cluster{width:auto}
/* device pills: firewall / core switch / SIEM bar */
.netmap .dev{position:absolute;border:1px solid var(--amber);border-radius:20px;
  background:rgba(245,166,35,.08);display:flex;align-items:center;
  justify-content:center;gap:8px;z-index:2}
.netmap .dev b{font-size:11px;font-weight:700;color:var(--amber);letter-spacing:1.5px;
  text-transform:uppercase}

/* ── company network host-inventory table ── */
.nettable-wrap{overflow-x:auto;scrollbar-width:thin;scrollbar-color:var(--line) transparent}
.nettable-wrap::-webkit-scrollbar{height:8px}
.nettable-wrap::-webkit-scrollbar-thumb{background:var(--line);border-radius:8px}
.nettable{width:100%;border-collapse:collapse;font-size:12.5px}
.nettable th,.nettable td{text-align:left;padding:9px 14px;
  border-bottom:1px solid var(--line);vertical-align:top}
.nettable thead th{background:var(--surface2);color:var(--muted);font-size:10px;
  letter-spacing:1.5px;text-transform:uppercase;font-weight:600}
.nettable tbody tr:last-child td{border-bottom:0}
.nettable tbody tr:hover{background:var(--surface2)}
.nettable .nt-host{color:var(--text);font-weight:700;white-space:nowrap}
.nettable .nt-ip{color:var(--amber);font-variant-numeric:tabular-nums;white-space:nowrap}
.nettable .nt-role{color:var(--text)}
.nettable .nt-log{color:var(--muted)}
"""
