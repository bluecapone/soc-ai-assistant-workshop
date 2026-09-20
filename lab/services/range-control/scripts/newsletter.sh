#!/usr/bin/env bash
# Decoy (rule 100171): a legitimate statement/newsletter email to the same finance user from the
# benign IP. Gateway verdict=clean, a plain attachment with no malicious hash, an on-domain https
# link. The benign twin of the phishing email; every signal is clean.
set -euo pipefail
source "$(dirname "$0")/_lib.sh"

from_user="$(pick statements newsletter no-reply notifications updates account-services rewards)"
rcpt="$(pick "${MAIL_RECIPIENTS[@]}")@${MAIL_DOMAIN}"
path="$(pick statements/september newsletter/2026 account/summary offers/autumn help/tips rewards/balance)"
subj="$(pick 'Your September statement is ready' 'Bank of Wonderland monthly newsletter' 'Your account summary' 'Autumn savings tips' 'Important service update' 'Your rewards balance this month')"
base="$(pick september-statement account-summary newsletter-2026 terms-update rate-notice rewards-summary)"
att="${base}_$(rtok).pdf"

echo "Newsletter email from ${BENIGN_IP} -> ${rcpt} (att=${att})"
mail_line clean "${from_user}@${MAIL_DOMAIN}" "$BENIGN_IP" "$rcpt" \
  "https://${MAIL_DOMAIN}/${path}" "$subj" "$att" none
