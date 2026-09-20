#!/usr/bin/env bash
# Live-reload dev mode: bind-mount source + gunicorn --reload, so code edits to the
# Flask apps show up on the next request with no image rebuild. Brings the whole stack
# up; only the code services (bank-web, range-control, soc-noise) get the dev treatment.
#
#   ./scripts/dev.sh                 # bring the stack up in dev mode
#   ./scripts/dev.sh bank-web        # just (re)create one service in dev mode
#
# After this, editing services/*/app.py is live. soc-noise needs a one-liner to re-run:
#   docker compose -f docker-compose.yml -f docker-compose.dev.yml restart soc-noise
set -euo pipefail
# Work from the lab root, whether this lives in lab/ or lab/scripts/.
cd "$(dirname "$0")"; [ -f docker-compose.yml ] || cd ..
exec docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d "$@"
