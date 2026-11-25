
from pathlib import Path
import math

import joblib
import pandas as pd
from river import anomaly


# ============================================================
# CONFIGURATION DU MODELE RANDOM FOREST
# ============================================================

PROJECT_DIR = Path(__file__).resolve().parent.parent

MODEL_PATH = (
    PROJECT_DIR
    / "models"
    / "random_forest_firewall.joblib"
)


# Les 23 caractéristiques utilisées pendant l'entraînement.
EXPECTED_FEATURES = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "SYN Flag Count",
    "ACK Flag Count",
    "RST Flag Count",
    "FIN Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Packet Length Mean",
    "Fwd Packet Length Max",
    "Bwd Packet Length Max",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward"
]


# ============================================================
# NORMALISATION POUR HALFSAPCETREES
# ============================================================

CAPS = {
    "Destination Port": 65535.0,
    "Flow Duration": 120_000_000.0,
    "Total Fwd Packets": 10000.0,
    "Total Backward Packets": 10000.0,
    "Total Length of Fwd Packets": 10_000_000.0,
    "Total Length of Bwd Packets": 10_000_000.0,
    "Flow Bytes/s": 1_000_000_000.0,
    "Flow Packets/s": 1_000_000.0,
    "SYN Flag Count": 10000.0,
    "ACK Flag Count": 10000.0,
    "RST Flag Count": 10000.0,
    "FIN Flag Count": 10000.0,
    "Down/Up Ratio": 100.0,
    "Average Packet Size": 65535.0,
    "Packet Length Mean": 65535.0,
    "Fwd Packet Length Max": 65535.0,
    "Bwd Packet Length Max": 65535.0,
    "Flow IAT Mean": 120_000_000.0,
    "Flow IAT Std": 120_000_000.0,
    "Init_Win_bytes_forward": 65535.0,
    "Init_Win_bytes_backward": 65535.0,
    "act_data_pkt_fwd": 10000.0,
    "min_seg_size_forward": 1500.0
}


NEGATIVE_SENTINEL_FEATURES = {
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward"
}


# ============================================================
# DETECTEURS
# ============================================================

class Detectors:

    def __init__(self):

        # Vérifier la présence du nouveau modèle
        if not MODEL_PATH.exists():
            raise FileNotFoundError(
                f"Nouveau modèle introuvable : {MODEL_PATH}"
            )

        # Charger le dictionnaire enregistré avec joblib
        model_data = joblib.load(MODEL_PATH)

        if not isinstance(model_data, dict):
            raise ValueError(
                "Format incorrect : le modèle doit être un dictionnaire."
            )

        # Récupérer le modèle et ses informations
        self.rf = model_data["model"]
        self.features = list(model_data["features"])
        self.classes = list(model_data["classes"])

        # Vérifier les caractéristiques
        if self.features != EXPECTED_FEATURES:
            raise ValueError(
                "Les caractéristiques du modèle ne correspondent "
                "pas aux 23 caractéristiques attendues."
            )

        if len(self.features) != 23:
            raise ValueError(
                f"Nombre incorrect de caractéristiques : {len(self.features)}"
            )

        # Vérifier le nombre de caractéristiques du Random Forest
        if getattr(self.rf, "n_features_in_", None) != len(self.features):
            raise ValueError(
                "Le nombre de caractéristiques du modèle Random Forest "
                "est incorrect."
            )

        # Vérifier les noms si scikit-learn les a enregistrés
        model_features = list(
            getattr(self.rf, "feature_names_in_", [])
        )

        if model_features and model_features != self.features:
            raise ValueError(
                "L'ordre des caractéristiques du modèle est incorrect."
            )

        print("=" * 55)
        print("NOUVEAU RANDOM FOREST CHARGE")
        print("=" * 55)

        print(f"Modèle : {MODEL_PATH.name}")
        print(f"Caractéristiques : {len(self.features)}")
        print(f"Nombre de classes : {len(self.classes)}")
        print(f"Accuracy enregistrée : {model_data.get('accuracy')}")

        print("\nClasses reconnues :")

        for classe in self.classes:
            print(f" - {classe}")

        # Détecteur d'anomalies non supervisé
        self.hst = anomaly.HalfSpaceTrees(
            n_trees=25,
            height=8,
            window_size=250,
            seed=42
        )

        self.hst_seen = 0

    # ========================================================
    # PREPARATION DES 23 CARACTERISTIQUES
    # ========================================================

    def prepare_features(self, features):

        missing = [
            name for name in self.features
            if name not in features
        ]

        if missing:
            raise ValueError(
                f"Caractéristiques manquantes : {missing}"
            )

        result = {}

        for name in self.features:

            try:
                value = float(features[name])

            except (TypeError, ValueError):
                raise ValueError(
                    f"Valeur non numérique pour {name}: {features[name]}"
                )

            if not math.isfinite(value):
                raise ValueError(
                    f"Valeur invalide pour {name}: {value}"
                )

            if value < 0:

                if (
                    name in NEGATIVE_SENTINEL_FEATURES
                    and value == -1
                ):
                    pass

                else:
                    raise ValueError(
                        f"Valeur négative interdite pour {name}: {value}"
                    )

            result[name] = value

        return result

    # ========================================================
    # CLASSIFICATION RANDOM FOREST
    # ========================================================

    def classify(self, features):

        clean = self.prepare_features(features)

        # Respecter exactement l'ordre du modèle entraîné
        x = pd.DataFrame(
            [[clean[name] for name in self.features]],
            columns=self.features
        )

        prediction = self.rf.predict(x)[0]

        return str(prediction)

    # ========================================================
    # NORMALISATION POUR LE DETECTEUR D'ANOMALIES
    # ========================================================

    def normalize(self, features):

        clean = self.prepare_features(features)

        normalized = {}

        for name in self.features:

            value = clean[name]

            if value == -1:
                normalized[name] = 0.0
                continue

            normalized[name] = min(
                1.0,
                value / CAPS[name]
            )

        return normalized

    # ========================================================
    # DETECTION D'ANOMALIES HALFSAPCETREES
    # ========================================================

    def anomaly_score(self, features):

        x = self.normalize(features)

        # Evaluer avant l'apprentissage
        score = float(self.hst.score_one(x))

        # Apprentissage progressif
        self.hst.learn_one(x)

        self.hst_seen += 1

        return score
