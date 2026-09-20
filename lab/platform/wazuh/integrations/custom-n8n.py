#!/usr/bin/env python3
"""
Wazuh -> n8n webhook integrator.
Posts a Wazuh alert to an n8n workflow webhook. The n8n workflow handles
triage, enrichment, and LLM-based verdict generation.

Called by the `n8n-webhook` wrapper with:
argv[1] = alert JSON file, argv[2] = api_key (unused), argv[3] = webhook_url
"""

import json
import sys
import urllib.request
import urllib.error


def main() -> int:
    if len(sys.argv) < 4:
        sys.stderr.write("n8n-webhook: usage: n8n-webhook <alert-file> <api_key> <webhook_url>\n")
        return 1

    alert_file = sys.argv[1]
    # api_key = sys.argv[2]  # unused for webhook integration
    webhook_url = sys.argv[3]

    try:
        with open(alert_file) as f:
            alert = json.load(f)
    except Exception as exc:
        sys.stderr.write(f"n8n-webhook: cannot read alert: {exc}\n")
        return 1

    try:
        # POST the alert JSON to the n8n webhook
        body = json.dumps(alert).encode("utf-8")
        req = urllib.request.Request(
            webhook_url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            response_body = resp.read().decode("utf-8")
            # Log the response for debugging
            sys.stderr.write(f"n8n-webhook: posted alert to {webhook_url}, status {resp.status}\n")

    except urllib.error.HTTPError as exc:
        sys.stderr.write(f"n8n-webhook: HTTP {exc.code}: {exc.read()[:300]!r}\n")
        return 1
    except urllib.error.URLError as exc:
        sys.stderr.write(f"n8n-webhook: cannot reach webhook: {exc}\n")
        return 1
    except Exception as exc:
        sys.stderr.write(f"n8n-webhook: error posting to webhook: {exc}\n")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
