#!/usr/bin/env bash
set -euo pipefail
iptables-restore < /root/iptables-before-ai.rules
echo "Règles iptables précédentes restaurées."
