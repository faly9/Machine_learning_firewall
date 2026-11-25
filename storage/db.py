
import json
import sqlite3
from pathlib import Path

from config import DB_PATH


# Les classes reconnues par le Random Forest
VALID_LABELS = {
    "BENIGN",
    "BOTNET",
    "DDOS",
    "DOS",
    "FTP_BRUTE_FORCE",
    "INFILTRATION",
    "PORTSCAN",
    "SSH_BRUTE_FORCE",
    "WEB_ATTACK",
    "PORTSCAN_BEHAVIOR",
}


def connect():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)

    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row

    con.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts DATETIME DEFAULT CURRENT_TIMESTAMP,
            src_ip TEXT NOT NULL,
            duration REAL,
            packets REAL,
            bytes REAL,
            protocol_tcp REAL,
            protocol_udp REAL,
            protocol_icmp REAL,
            syn_packets REAL,
            unique_dst_ports REAL,
            failed_estimate REAL,
            true_label TEXT,
            decision TEXT NOT NULL,
            rf_label TEXT,
            anomaly_score REAL,
            detail TEXT
        )
    """)

    # Ajouter les nouvelles colonnes sans supprimer les anciennes données.
    existing = {
        row["name"]
        for row in con.execute("PRAGMA table_info(events)")
    }

    migrations = {
        "features_json": "TEXT",
        "detection_type": "TEXT DEFAULT 'ML'",
        "dst_ip": "TEXT",
        "risk_score": "REAL",
        "risk_reason": "TEXT",
    }

    for column, sql_type in migrations.items():
        if column not in existing:
            con.execute(
                f"ALTER TABLE events ADD COLUMN {column} {sql_type}"
            )

    # Les validations humaines sont séparées des prédictions automatiques.
    con.execute("""
        CREATE TABLE IF NOT EXISTS event_feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER NOT NULL UNIQUE,
            validated_label TEXT NOT NULL,
            comment TEXT,
            validated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(event_id) REFERENCES events(id)
        )
    """)

    con.execute("""
        CREATE INDEX IF NOT EXISTS idx_events_src_ip_ts
        ON events(src_ip, ts)
    """)

    con.commit()
    return con


def add_event(
    src_ip,
    decision,
    rf_label,
    anomaly_score,
    features=None,
    detail="",
    detection_type="ML",
    dst_ip=None,
    risk_score=None,
    risk_reason=None,
):
    features = features or {}

    # Les 23 caractéristiques sont conservées intégralement en JSON.
    features_json = json.dumps(
        features,
        ensure_ascii=False,
        allow_nan=False,
    )

    # Compatibilité avec les anciennes colonnes de la base.
    legacy_values = {
        "duration": features.get("Flow Duration"),
        "packets": (
            (features.get("Total Fwd Packets") or 0)
            + (features.get("Total Backward Packets") or 0)
        ),
        "bytes": (
            (features.get("Total Length of Fwd Packets") or 0)
            + (features.get("Total Length of Bwd Packets") or 0)
        ),
        "syn_packets": features.get("SYN Flag Count"),
    }

    con = connect()

    columns = {
        row["name"]
        for row in con.execute("PRAGMA table_info(events)")
    }

    values = {
        "src_ip": src_ip,
        "decision": decision,
        "rf_label": rf_label,
        "anomaly_score": anomaly_score,
        "detail": detail,
        "features_json": features_json,
        "detection_type": detection_type,
        "dst_ip": dst_ip,
        "risk_score": risk_score,
        "risk_reason": risk_reason,
        **legacy_values,
    }

    selected = [
        (name, value)
        for name, value in values.items()
        if name in columns
    ]

    names = ", ".join(name for name, _ in selected)
    placeholders = ", ".join("?" for _ in selected)

    con.execute(
        f"INSERT INTO events ({names}) VALUES ({placeholders})",
        [value for _, value in selected],
    )

    event_id = con.execute(
        "SELECT last_insert_rowid()"
    ).fetchone()[0]

    con.commit()
    con.close()

    return event_id


def add_feedback(event_id, label, comment=""):
    label = label.strip().upper()

    if label not in VALID_LABELS:
        raise ValueError(f"Classe invalide : {label}")

    con = connect()

    exists = con.execute(
        "SELECT id FROM events WHERE id = ?",
        (event_id,),
    ).fetchone()

    if not exists:
        con.close()
        raise ValueError(f"Événement {event_id} introuvable")

    con.execute("""
        INSERT INTO event_feedback (
            event_id, validated_label, comment
        )
        VALUES (?, ?, ?)
        ON CONFLICT(event_id) DO UPDATE SET
            validated_label = excluded.validated_label,
            comment = excluded.comment,
            validated_at = CURRENT_TIMESTAMP
    """, (event_id, label, comment))

    con.commit()
    con.close()


def recent_events(limit=100):
    con = connect()

    rows = con.execute("""
        SELECT
            e.*,
            f.validated_label,
            f.comment AS validation_comment
        FROM events e
        LEFT JOIN event_feedback f ON f.event_id = e.id
        ORDER BY e.id DESC
        LIMIT ?
    """, (limit,)).fetchall()

    con.close()
    return [dict(row) for row in rows]


def get_ip_history(src_ip, minutes=5):
    con = connect()

    rows = con.execute("""
        SELECT id, ts, decision, rf_label, detection_type
        FROM events
        WHERE src_ip = ?
          AND ts >= datetime('now', ?)
        ORDER BY id DESC
    """, (src_ip, f"-{int(minutes)} minutes")).fetchall()

    con.close()
    return [dict(row) for row in rows]

def update_event_risk(event_id, risk_score, risk_reason):
    con = connect()

    try:
        con.execute("""
            UPDATE events
            SET risk_score = ?,
                risk_reason = ?
            WHERE id = ?
        """, (
            risk_score,
            risk_reason,
            event_id
        ))

        con.commit()

    finally:
        con.close()
