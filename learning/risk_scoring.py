
from storage.db import get_ip_history


RISK_WINDOW_MINUTES = 5
RISK_THRESHOLD = 80
MAX_RISK_SCORE = 100

EVENT_WEIGHTS = {
    "NORMAL": 0,
    "UNKNOWN": 0,
    "SUSPECT": 10,
    "MALICIOUS": 30,
}


def calculate_ip_risk(src_ip):
    """
    Calcule le risque d'une IP à partir de ses événements récents.
    Ce module réalise un apprentissage comportemental,
    pas un réentraînement du Random Forest.
    """

    events = get_ip_history(
        src_ip,
        minutes=RISK_WINDOW_MINUTES,
    )

    score = 0
    reasons = []

    for event in events:
        decision = (event.get("decision") or "UNKNOWN").upper()
        weight = EVENT_WEIGHTS.get(decision, 0)

        if weight:
            score += weight
            reasons.append(
                f'{decision} ({weight} points, événement {event["id"]})'
            )

    score = min(score, MAX_RISK_SCORE)

    return {
        "src_ip": src_ip,
        "risk_score": score,
        "threshold": RISK_THRESHOLD,
        "should_block": score >= RISK_THRESHOLD,
        "event_count": len(events),
        "reasons": reasons,
    }
