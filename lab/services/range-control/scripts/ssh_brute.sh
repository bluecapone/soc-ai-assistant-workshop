#!/usr/bin/env bash
# Attack (rules 100160 + 100161): a full SSH intrusion. A sustained password spray — dozens of
# failed logins for common accounts from the attacker IP — that finally breaks through to a
# successful login. The failures trip Wazuh's SSH brute-force composite (5763 -> 100160); the
# success at the end is the compromise (5715 -> 100161). Both carry the same attacker IP, so the
# analyst/AI correlates the two into one host takeover. Accounts tried, count and the breached
# account vary per run.
set -euo pipefail
source "$(dirname "$0")/_lib.sh"
ip="$(rand_attacker_ip)"
users=(root admin deploy postgres oracle test ubuntu ec2-user git jenkins www-data pi mysql svc
       administrator backup nagios ftp user1 support tomcat hadoop redis vagrant devops ansible)
attempts="$(rint 60 95)"
echo "SSH brute force from ${ip}: password spray in progress (${attempts} attempts)..."
for ((i=1; i<=attempts; i++)); do
  ssh_line Failed "$(pick "${users[@]}")" "$ip"
done
# The breakthrough: after the spray, one account gives way and the attacker is in.
breached="$(pick root deploy ubuntu ec2-user)"
ssh_line Accepted "$breached" "$ip"
echo "  ${attempts} failures then a SUCCESS as ${breached} from ${ip} — host compromised"
