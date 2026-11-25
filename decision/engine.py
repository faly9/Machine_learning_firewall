
from config import ANOMALY_THRESHOLD, AUTO_BLOCK

from firewall.ipset_manager import (
    block_ip,
    is_private_or_protected
)

from storage.db import (
    add_event,
    update_event_risk
)

from learning.risk_scoring import calculate_ip_risk


# ============================================================
# CONFIGURATION DES LABELS
# ============================================================

BENIGN_LABELS = {
    "BENIGN",
    "NORMAL",
    "0"
}

UNKNOWN_LABELS = {
    "UNKNOWN",
    ""
}


# Correspondance entre les alertes comportementales
# et les catégories d'attaques enregistrées.

BEHAVIOR_LABELS = {
    "PORTSCAN_BEHAVIOR": "PORTSCAN",

    "SSH_CONNECTION_BURST_BEHAVIOR": "SSH_BRUTE_FORCE",

    "FTP_CONNECTION_BURST_BEHAVIOR": "FTP_BRUTE_FORCE",

    "HTTP_CONNECTION_BURST_BEHAVIOR": "WEB_ATTACK",

    "SYN_FLOOD_BEHAVIOR": "DOS",

    "DOS_BEHAVIOR": "DOS",

    "DDOS_BEHAVIOR": "DDOS",
}


# ============================================================
# BLOCAGE AUTOMATIQUE
# ============================================================

def _apply_risk_block(src_ip, risk):

    if not risk["should_block"]:
        return "Seuil de risque non atteint"

    if not AUTO_BLOCK:
        return "Blocage désactivé (mode observation)"

    if not src_ip or src_ip == "MULTIPLE":
        return "Blocage individuel impossible"

    if is_private_or_protected(src_ip):
        return "Blocage ignoré : adresse protégée"

    try:
        block_ip(src_ip)

        return "IP bloquée après analyse du risque"

    except Exception as exc:
        return f"Échec du blocage : {exc}"


# ============================================================
# CALCUL DU RISQUE ET BLOCAGE
# ============================================================

def _calculate_risk_and_block(src_ip, event_id):

    risk = calculate_ip_risk(src_ip)

    risk_reason = "; ".join(risk["reasons"])

    update_event_risk(
        event_id,
        risk["risk_score"],
        risk_reason
    )

    block_detail = _apply_risk_block(
        src_ip,
        risk
    )

    return risk, block_detail


# ============================================================
# DÉTECTION PAR MACHINE LEARNING
# ============================================================

def evaluate(src_ip, features, detectors):

    # Classification Random Forest
    rf_label = detectors.classify(features)

    normalized_label = str(rf_label).strip().upper()

    # Détection d'anomalies Half-Space Trees
    anomaly_score = detectors.anomaly_score(features)

    is_anomaly = anomaly_score >= ANOMALY_THRESHOLD

    is_attack = (
        normalized_label not in BENIGN_LABELS
        and normalized_label not in UNKNOWN_LABELS
    )

    # Décision finale
    if normalized_label in UNKNOWN_LABELS:

        decision = "SUSPECT" if is_anomaly else "UNKNOWN"

    elif is_attack and is_anomaly:

        decision = "MALICIOUS"

    elif is_attack or is_anomaly:

        decision = "SUSPECT"

    else:

        decision = "NORMAL"

    # Enregistrement de l'événement
    event_id = add_event(
        src_ip=src_ip,
        decision=decision,
        rf_label=normalized_label,
        anomaly_score=anomaly_score,
        features=features,
        detail="Détection par Random Forest et Half-Space Trees",
        detection_type="ML"
    )

    # Calcul du risque après insertion de l'événement
    risk, block_detail = _calculate_risk_and_block(
        src_ip,
        event_id
    )

    return {
        "event_id": event_id,
        "src_ip": src_ip,
        "decision": decision,
        "rf_label": normalized_label,
        "anomaly_score": anomaly_score,
        "risk_score": risk["risk_score"],
        "risk_threshold": risk["threshold"],
        "risk_reasons": risk["reasons"],
        "detail": block_detail
    }


# ============================================================
# DÉTECTION COMPORTEMENTALE
# ============================================================

def evaluate_behavior(alert):

    src_ip = alert.get("src_ip", "UNKNOWN")

    detection = str(
        alert.get("detection", "UNKNOWN")
    ).strip().upper()

    rf_label = BEHAVIOR_LABELS.get(
        detection,
        "UNKNOWN"
    )

    decision = str(
        alert.get("decision", "SUSPECT")
    ).strip().upper()

    if decision not in {"MALICIOUS", "SUSPECT"}:
        decision = "SUSPECT"

    dst_ip = alert.get("dst_ip")

    detail = alert.get(
        "detail",
        f"Détection comportementale : {detection}"
    )

    # Informations complémentaires
    if alert.get("attempts") is not None:
        detail += f" | Tentatives : {alert['attempts']}"

    if alert.get("unique_ports") is not None:
        detail += f" | Ports distincts : {alert['unique_ports']}"

    if alert.get("packet_count") is not None:
        detail += f" | Paquets : {alert['packet_count']}"

    # Enregistrement de l'événement
    event_id = add_event(
        src_ip=src_ip,
        decision=decision,
        rf_label=rf_label,
        anomaly_score=None,
        features=alert.get("features", {}),
        detail=detail,
        detection_type="BEHAVIORAL",
        dst_ip=dst_ip
    )

    # --------------------------------------------------------
    # CAS PARTICULIER : DDOS
    # --------------------------------------------------------
    # Une alerte DDoS peut regrouper plusieurs IP sources.
    # Il ne faut donc pas calculer le risque ou bloquer
    # une fausse adresse IP appelée "MULTIPLE".

    if alert.get("blockable", True) is False or src_ip == "MULTIPLE":

        return {
            "event_id": event_id,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "decision": decision,
            "detection": detection,
            "rf_label": rf_label,
            "risk_score": None,
            "risk_threshold": None,
            "risk_reasons": [
                "Attaque collective : plusieurs sources détectées"
            ],
            "detail": detail,
            "block_detail": (
                "Aucun blocage individuel : "
                "alerte collective nécessitant une analyse spécifique"
            )
        }

    # --------------------------------------------------------
    # CAS NORMAL : UNE IP SOURCE
    # --------------------------------------------------------

    risk, block_detail = _calculate_risk_and_block(
        src_ip,
        event_id
    )

    return {
        "event_id": event_id,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "decision": decision,
        "detection": detection,
        "rf_label": rf_label,
        "risk_score": risk["risk_score"],
        "risk_threshold": risk["threshold"],
        "risk_reasons": risk["reasons"],
        "detail": detail,
        "block_detail": block_detail
    }


# ============================================================
# COMPATIBILITÉ AVEC L'ANCIENNE FONCTION
# ============================================================

def evaluate_portscan(alert):

    return evaluate_behavior(alert)
