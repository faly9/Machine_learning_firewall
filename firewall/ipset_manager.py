import ipaddress
import subprocess

from config import PROTECTED_IPS, BLOCK_SECONDS, MAX_BLOCK_SECONDS

SET_NAME = "AI_BLOCKED"

IPTABLES_MATCH = [
    "-m", "set",
    "--match-set", SET_NAME, "src",
    "-j", "DROP"
]

# CORRECTION : on pose la regle sur INPUT ET FORWARD.
# - FORWARD : cas ou cette machine est une gateway / un pare-feu
#   en coupure entre l'attaquant et la cible.
# - INPUT : cas ou cette machine EST la cible directe du trafic
#   (setup de lab le plus courant : Kali attaque l'IP de la
#   machine qui fait tourner main.py). Sans la regle INPUT,
#   l'IP est bien ajoutee dans l'ipset mais rien n'est jamais
#   droppe pour du trafic destine a cette machine.
CHAINS = ["INPUT", "FORWARD"]


def run(args):
    return subprocess.run(
        args,
        check=True,
        text=True,
        capture_output=True
    )


def _rule_exists(chain):
    check = subprocess.run(
        ["iptables", "-C", chain] + IPTABLES_MATCH,
        text=True,
        capture_output=True
    )
    return check.returncode == 0


def ensure_set():
    # 1. Créer l'ensemble IPset s'il n'existe pas
    run([
        "ipset", "create", SET_NAME,
        "hash:ip",
        "family", "inet",
        "timeout", str(MAX_BLOCK_SECONDS),
        "-exist"
    ])

    # 2. Ajouter la règle DROP sur chaque chaîne pertinente,
    #    uniquement si elle n'existe pas déjà (idempotent).
    for chain in CHAINS:
        if not _rule_exists(chain):
            run([
                "iptables", "-I", chain, "1"
            ] + IPTABLES_MATCH)


def block_ip(ip, seconds=None):
    addr = ipaddress.ip_address(ip)

    if addr.version != 4:
        raise ValueError("Ce prototype ne bloque que IPv4")

    if str(addr) in PROTECTED_IPS:
        raise ValueError("Adresse protégée : blocage interdit")

    duration = min(
        max(60, int(seconds or BLOCK_SECONDS)),
        MAX_BLOCK_SECONDS
    )

    ensure_set()

    run([
        "ipset", "add", SET_NAME,
        str(addr),
        "timeout", str(duration),
        "-exist"
    ])


def unblock_ip(ip):
    addr = ipaddress.ip_address(ip)

    run([
        "ipset", "del", SET_NAME, str(addr)
    ])


def is_private_or_protected(ip):
    addr = ipaddress.ip_address(ip)

    return (
        str(addr) in PROTECTED_IPS
        or addr.is_loopback
        or addr.is_multicast
        or addr.is_unspecified
        or addr.is_link_local
    )
