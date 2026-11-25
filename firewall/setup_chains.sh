#!/usr/bin/env bash
set -euo pipefail

# À exécuter uniquement depuis la console de la VM de laboratoire.
# Sauvegarder les règles avant exécution.
iptables-save > /root/iptables-before-ai.rules
ipset create AI_BLOCKED hash:ip family inet timeout 3600 -exist

iptables -N AI_INPUT 2>/dev/null || true
iptables -N AI_FORWARD 2>/dev/null || true

iptables -C INPUT -j AI_INPUT 2>/dev/null || iptables -I INPUT 1 -j AI_INPUT
iptables -C FORWARD -j AI_FORWARD 2>/dev/null || iptables -I FORWARD 1 -j AI_FORWARD

iptables -C AI_INPUT -m set --match-set AI_BLOCKED src -j DROP 2>/dev/null || \
  iptables -A AI_INPUT -m set --match-set AI_BLOCKED src -j DROP
iptables -C AI_FORWARD -m set --match-set AI_BLOCKED src -j DROP 2>/dev/null || \
  iptables -A AI_FORWARD -m set --match-set AI_BLOCKED src -j DROP

iptables -A AI_INPUT -j RETURN
iptables -A AI_FORWARD -j RETURN

echo "Chaînes IA installées. Vérifier: iptables -S; ipset list AI_BLOCKED"
