# Wazuh config

Detection and TheHive-forwarding config for the lab's single-node Wazuh. See the attack-to-detection map in the button set of [`../../../../docs/workshop/lab-build-spec.md`](../../../../docs/workshop/lab-build-spec.md).

## Files

| File | Mounted at | Purpose |
|---|---|---|
| `local_decoder.xml` | `/var/ossec/etc/decoders/local_decoder.xml` | parse the target's access.log and auth.log |
| `local_rules.xml` | `/var/ossec/etc/rules/local_rules.xml` | rules 1001xx, one per attack + benign twin |
| `ossec.conf` | `/wazuh-config-mount/etc/ossec.conf` | localfile, FIM, and the TheHive integration |
| `integrations/custom-w2thive` | `/var/ossec/integrations/custom-w2thive` | integrator wrapper (runs the Python) |
| `integrations/custom-w2thive.py` | `/var/ossec/integrations/custom-w2thive.py` | builds and POSTs the TheHive alert |
| `certs/config.yml` | cert generator input | single-node SSL certs |

## Setup on first boot

1. **The integrator's TheHive API key is auto-minted at startup.** `start.sh` renews the key for `integrator@soclab.local` (an organisation user with `manageCase/create` profile, not the platform admin) via `curl` POST to `$TH/api/v1/user/integrator@soclab.local/key/renew`, seds it into the host-side `ossec.runtime.conf` file, and copies that updated config into the already-running `wazuh.manager` container via `docker compose exec`. The committed template `ossec.conf` is key-free; only `ossec.runtime.conf` (gitignored, regenerated fresh on every run) ever contains the live key. No manual configuration of `.env` or `.conf` files is required.

   Verified end to end 2026-09-13: with the key in place and `wazuh-integratord` running, firing panel attacks opened TheHive **cases** for rules 100110, 100121, 100130, 100140, and 100150, each with the source IP, URL, and beacon domain attached as observables. `custom-w2thive` creates a case (`POST /api/v1/case`) then attaches each observable (`POST /api/v1/case/{id}/observable`). The whole chain (attack → target log → manager → analysisd → integratord → TheHive case) works under emulation on arm64.
2. **Make the integrator executable.** `custom-w2thive` and `custom-w2thive.py` must be mode 750 and owned by `wazuh:wazuh` inside the container; `chmod 750` both if you mount them by hand.
3. **Set `vm.max_map_count`.** The indexer needs `sysctl -w vm.max_map_count=262144` on the Docker host (recorded as a boot hazard in [`../../../../docs/workshop/lab-build-spec.md`](../../../../docs/workshop/lab-build-spec.md)).

## Verify on a live manager (this is the load-bearing seam)

- `wazuh-logtest` against a sample access.log line confirms the decoder extracts `srcip`, `url`, `id`, `user_agent`, then that a rule in the 1001xx band fires.
- Click a button on the range control panel, then confirm the alert appears in the Wazuh dashboard, and that `custom-w2thive` posted a matching alert into TheHive (check `/var/ossec/logs/integrations.log` and `ossec.log` for the integrator's stderr on failure).
- Tune levels and the frequency thresholds (recon, brute force, crawler) against real timing. The thresholds in `local_rules.xml` are a starting point, not measured.

## Verified findings (2026-09-13, arm64 Docker)

- **Wazuh images are amd64-only.** `wazuh/wazuh-manager`, `wazuh-indexer`, and `wazuh-dashboard` (checked at 4.9.2 and later tags) publish a single amd64 manifest. On Apple Silicon they run under emulation. TheHive and n8n are native arm64, so Wazuh is the one emulated piece. This is ADR-0006 open question 1.
- **The cert generator needs Wazuh's dotted node names.** Single-label names like `wazuh-indexer` are rejected (`Invalid IP or DNS`). The compose services and `certs/config.yml` use `wazuh.indexer`, `wazuh.manager`, `wazuh.dashboard`; with those, the generator produces the indexer, filebeat, and dashboard certs cleanly under emulation. Keep the compose hostnames and the cert names identical or TLS SAN validation fails.

## Full config is wired and boots (verified 2026-09-13, arm64 under emulation)

All three Wazuh containers come up and the detection pipeline runs end to end: a panel attack writes the target log, the manager tails it, analysisd fires the 1001xx rules, filebeat ships to the indexer, and the alerts are queryable in `wazuh-alerts-*`. Config in `config/wazuh_indexer/` and `config/wazuh_dashboard/` is taken from Wazuh's official single-node compose (v4.9.2); the per-file cert mounts and demo creds are in `../docker-compose.yml`.

Four fixes were needed to get there, all worth knowing:

1. **Deliver custom config through `/wazuh-config-mount/`, not `/var/ossec/etc/`.** Bind-mounting `local_rules.xml` straight into `/var/ossec/etc/rules/` makes the manager's first-boot think the config volume is already populated, so it skips the default etc tree (`etc/shared/ar.conf` and friends) and analysisd crashes. The entrypoint copies everything under `/wazuh-config-mount/` in after laying down defaults, which is the correct path.
2. **`url` is a Wazuh static field.** Rules matching the request path must use the dedicated `<url>` tag, not `<field name="url">` (that fails to load with "Field 'url' is static"). `user_agent`, `authresult`, and `file` are dynamic and stay as `<field name=...>`.
3. **Cert files must be readable by the container.** The generated keys come out mode 0600 owned by the build user; the indexer runs as another uid, so they need to be readable (0644 here). OpenSearch logs a benign "insecure file permissions" warning at 0644, which is fine for the lab.
4. **Demo passwords must match `internal_users.yml`.** `admin`/`brucon2026`, `wazuh-wui`/`MyS3cr37P450r.*-`, `kibanaserver`/`kibanaserver` correspond to the bcrypt hashes shipped in that file; change the hashes and the passwords together.

Memory note: on a 7.7 GB Docker VM the three emulated Wazuh JVMs plus TheHive fit with headroom (indexer ~1.5 GiB, embedded TheHive ~1.4 GiB). A 16 GB+ laptop is still the right target, but it is not as tight as first feared.

## Reconcile `ossec.conf`

The mounted `ossec.conf` overlays the image default. Diff it against the ossec.conf shipped in `wazuh/wazuh-manager:4.9.2` before trusting it. The workshop-added blocks (localfile, syscheck, integration) are marked; the surrounding blocks are a minimal single-node shape and may need modules from the image default added back.
