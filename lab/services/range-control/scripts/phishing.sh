#!/usr/bin/env bash
# Attack (rule 100170): a credential-harvesting email the gateway flagged as suspicious.
# The tells are real: a live-malicious attachment hash (MalwareBazaar family) and a link on a
# real flagged domain (URLhaus). The gateway does NOT label it "phishing"; the analyst/AI must
# confirm from the hash and the link reputation. Sender, recipient, subject vary per run.
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
ip="$(rand_attacker_ip)"

IFS='|' read -r sha fam _src <<<"$(pick_ioc malware sha256)"
: "${sha:=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}"
: "${fam:=AgentTesla}"
IFS='|' read -r link _l _s <<<"$(pick_ioc phishing url)"
IFS='|' read -r pdom _pl _ps <<<"$(pick_ioc phishing domain)"
: "${pdom:=secure-docs-verify.top}"
: "${link:=http://${pdom}/login}"

from_user="$(pick accounts-payable billing invoices no-reply security payroll hr-notify it-support docusign finance)"
rcpt="$(pick "${MAIL_RECIPIENTS[@]}")@${MAIL_DOMAIN}"
subj="$(pick 'Overdue invoice - immediate payment required' 'Your account will be suspended' 'You have a new secure document to review' 'Payment remittance advice' 'Action required: verify your mailbox' 'A file has been shared with you')"
base="$(pick invoice remittance statement purchase_order scan payment-advice document receipt payslip)"
ext="$(pick pdf docx xlsm zip)"
att="${base}_$(rtok).${ext}"

echo "Phishing email from ${ip} -> ${rcpt} (att=${att}, ${fam})"
mail_line suspicious "${from_user}@${pdom}" "$ip" "$rcpt" "$link" "$subj" "$att" "$sha"
