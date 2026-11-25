
import os
from dotenv import load_dotenv

load_dotenv()


def csv_set(name, default=""):
    return {
        x.strip()
        for x in os.getenv(name, default).split(",")
        if x.strip()
    }


# Capture réseau
INTERFACE = os.getenv("INTERFACE", "enp0s3")
CAPTURE_FILTER = os.getenv(
    "CAPTURE_FILTER",
    "host 10.228.52.132"
)

# Agrégation des flux
WINDOW_SECONDS = int(os.getenv("WINDOW_SECONDS", "10"))
MIN_PACKETS = int(os.getenv("MIN_PACKETS", "3"))

# Détection comportementale des scans TCP
PORTSCAN_WINDOW_SECONDS = int(
    os.getenv("PORTSCAN_WINDOW_SECONDS", "10")
)
PORTSCAN_THRESHOLD = int(
    os.getenv("PORTSCAN_THRESHOLD", "15")
)
PORTSCAN_ALERT_COOLDOWN = int(
    os.getenv("PORTSCAN_ALERT_COOLDOWN", "10")
)

# Machine Learning
MODEL_PATH = os.getenv(
    "MODEL_PATH",
    "models/random_forest_firewall.joblib"
)

# Base de données
DB_PATH = os.getenv("DB_PATH", "data/firewall.db")

# Sécurité et décisions
AUTO_BLOCK = os.getenv(
    "AUTO_BLOCK", "true"
).strip().lower() in ("1", "true", "yes", "on")

ANOMALY_THRESHOLD = float(
    os.getenv("ANOMALY_THRESHOLD", "0.85")
)

BLOCK_SECONDS = int(os.getenv("BLOCK_SECONDS", "900"))
MAX_BLOCK_SECONDS = int(os.getenv("MAX_BLOCK_SECONDS", "3600"))

PROTECTED_IPS = csv_set("PROTECTED_IPS")

MANAGEMENT_PORTS = {
    int(x) for x in csv_set("MANAGEMENT_PORTS")
}
