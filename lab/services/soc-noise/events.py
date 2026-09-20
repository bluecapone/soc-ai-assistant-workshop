"""
Pure document builders for the paper-host telemetry soc-noise writes into the indexer.

Standard library only, so these can be unit-tested without requests. gen.py imports
build_doc and the host builders, supplies the random users and addresses, and writes
the documents through its existing _bulk path. Every id here is in the 1002xx band and
is deliberately absent from the integrator forward list, so nothing here becomes a case.
"""

HOST_RULE_IDS = ["100201", "100202", "100203", "100204",
                 "100205", "100206", "100207", "100208"]

# Internal staff whose activity fills the internal hosts. Service accounts drive the
# app-to-database and backup traffic.
STAFF = ["sarah.mitchell", "james.okonkwo", "priya.nair", "david.chen",
         "laura.gomez", "marco.rossi", "aisha.khan", "thomas.mueller"]
SERVICE_ACCOUNTS = ["svc_webapp", "svc_backup", "svc_report"]
WORKSTATIONS = [("workstation-finance-01", "10.20.20.11"),
                ("workstation-finance-02", "10.20.20.12"),
                ("workstation-hr-01", "10.20.20.31"),
                ("workstation-it-01", "10.20.20.41"),
                ("workstation-sales-01", "10.20.20.51")]


def build_doc(iso, rule_id, level, desc, groups, decoder, location, data, full_log):
    """One Wazuh-shaped alert document, same field set soc-noise's web events use."""
    import time
    return {
        "timestamp": iso,
        "@timestamp": iso,
        "agent": {"name": "wazuh.manager", "id": "000"},
        "manager": {"name": "wazuh.manager"},
        "rule": {"id": rule_id, "level": level, "description": desc,
                 "groups": groups, "firedtimes": 1, "mail": False},
        "decoder": {"name": decoder},
        "location": location,
        "data": data,
        "full_log": full_log,
        "id": f"{time.time():.6f}",
    }


def dc_logon(iso, user, wks, wks_ip):
    full = (f"AuthNSvc: EventID=4624 LogonType=3 TargetUserName={user} "
            f"TargetDomain=WONDERLAND IpAddress={wks_ip} Workstation={wks} Status=success")
    return build_doc(iso, "100201", 3, f"Domain logon for {user} from {wks}",
                     ["windows", "authentication_success", "ambient"],
                     "windows-security", "/var/log/host/dc-01/security.log",
                     {"host": "dc-01", "win_event": "4624", "user": user,
                      "logon_type": "3", "src_ip": wks_ip, "workstation": wks,
                      "status": "success"}, full)


def db_query(iso, db_user, statement_kind, rows, src_ip):
    full = (f"postgres[{rows % 9000 + 1000}]: LOG: connection authorized user={db_user} "
            f"database=corebank ; statement: {statement_kind} ... rows={rows}")
    return build_doc(iso, "100202", 3, f"Database {statement_kind} by {db_user}",
                     ["database", "ambient"],
                     "postgresql", "/var/log/host/database-01/postgresql.log",
                     {"host": "database-01", "db_user": db_user, "database": "corebank",
                      "statement_kind": statement_kind, "rows": str(rows), "src_ip": src_ip}, full)


def fs_access(iso, user, share, path, op, src_ip):
    full = f"smbd: user={user} share={share} path={path} op={op} result=ok src={src_ip}"
    return build_doc(iso, "100203", 3, f"File {op} on {share} by {user}",
                     ["fileshare", "ambient"],
                     "samba", "/var/log/host/fileserver-01/smbd.log",
                     {"host": "fileserver-01", "user": user, "share": share,
                      "path": path, "op": op, "src_ip": src_ip}, full)


def mail_flow(iso, mail_from, mail_to, src_ip):
    full = (f"mail-gateway-01 mailscan: from={mail_from} ip={src_ip} to={mail_to} "
            f"verdict=clean action=delivered")
    return build_doc(iso, "100204", 3, f"Mail delivered to {mail_to}",
                     ["email", "ambient"],
                     "mailscan", "/var/log/host/mail-gateway-01/maillog",
                     {"host": "mail-gateway-01", "mail_from": mail_from, "mail_to": mail_to,
                      "verdict": "clean", "src_ip": src_ip}, full)


def proxy_browse(iso, src_ip, dst_host, cat, nbytes):
    full = (f"proxy-01 proxy: src={src_ip} dst_host={dst_host} method=CONNECT "
            f"bytes={nbytes} cat={cat} action=allowed")
    return build_doc(iso, "100205", 3, f"Allowed browsing to {dst_host}",
                     ["network", "ambient"],
                     "proxy", "/var/log/host/proxy-01/proxy.log",
                     {"host": "proxy-01", "src_ip": src_ip, "dst_host": dst_host,
                      "cat": cat, "bytes": str(nbytes)}, full)


def vpn_session(iso, user, home_ip, event):
    full = f"openvpn: user={user} ip={home_ip} event={event} proto=udp port=1194"
    return build_doc(iso, "100206", 3, f"VPN {event} for {user}",
                     ["vpn", "authentication_success", "ambient"],
                     "openvpn", "/var/log/host/vpn-corp-01/openvpn.log",
                     {"host": "vpn-corp-01", "user": user, "src_ip": home_ip,
                      "event": event}, full)


def edr_event(iso, wks, user, kind, detail):
    full = f"edr: host={wks} user={user} event={kind} detail=\"{detail}\""
    return build_doc(iso, "100207", 3, f"Endpoint {kind} on {wks}",
                     ["endpoint", "ambient"],
                     "edr", f"/var/log/host/{wks}/edr.log",
                     {"host": wks, "user": user, "event": kind, "detail": detail}, full)


def backup_job(iso, job, status, nbytes):
    full = f"veeam: job=\"{job}\" status={status} bytes={nbytes} result=completed"
    return build_doc(iso, "100208", 3, f"Backup job {job} {status}",
                     ["backup", "ambient"],
                     "veeam", "/var/log/host/backup-01/veeam.log",
                     {"host": "backup-01", "job": job, "status": status,
                      "bytes": str(nbytes)}, full)
