
import sys
from pathlib import Path

import pandas as pd
import joblib

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score
)


FEATURES = [
    "duration",
    "packets",
    "bytes",
    "protocol_tcp",
    "protocol_udp",
    "protocol_icmp",
    "syn_packets",
    "unique_dst_ports",
    "failed_estimate"
]


MODEL_PATH = Path("models/random_forest.joblib")


def main(csv_path):

    print("[1] Chargement du dataset...")

    df = pd.read_csv(csv_path)

    required = FEATURES + ["Label"]

    missing = [
        column for column in required
        if column not in df.columns
    ]

    if missing:
        raise SystemExit(
            "Colonnes absentes : " + ", ".join(missing)
        )

    df = df[required].copy()

    # Conversion des caractéristiques en valeurs numériques
    for column in FEATURES:
        df[column] = pd.to_numeric(
            df[column],
            errors="coerce"
        )

    df["Label"] = df["Label"].astype("string").str.strip()

    # Suppression des valeurs invalides
    df = df.replace(
        [float("inf"), -float("inf")],
        float("nan")
    )

    df = df.dropna()

    # Suppression des valeurs négatives
    df = df[(df[FEATURES] >= 0).all(axis=1)]

    if df.empty:
        raise SystemExit("Dataset vide après nettoyage.")

    print("\n[2] Répartition des classes :")
    print(df["Label"].value_counts())

    if df["Label"].nunique() < 2:
        raise SystemExit(
            "Il faut au moins deux classes pour entraîner le modèle."
        )

    if df["Label"].value_counts().min() < 2:
        raise SystemExit(
            "Chaque classe doit contenir au moins deux exemples."
        )

    X = df[FEATURES].astype(float)

    y = df["Label"].astype(str)

    print("\n[3] Séparation entraînement / test...")

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y
    )

    print("Exemples entraînement :", len(X_train))
    print("Exemples test :", len(X_test))

    print("\n[4] Entraînement Random Forest...")

    model = RandomForestClassifier(
        n_estimators=200,
        class_weight="balanced_subsample",
        random_state=42,
        n_jobs=-1
    )

    model.fit(X_train, y_train)

    print("\n[5] Évaluation du modèle...")

    predictions = model.predict(X_test)

    print(
        "\nAccuracy :",
        accuracy_score(y_test, predictions)
    )

    print("\nRapport de classification :")

    print(
        classification_report(
            y_test,
            predictions,
            zero_division=0
        )
    )

    print("\nMatrice de confusion :")

    print(
        confusion_matrix(
            y_test,
            predictions,
            labels=model.classes_
        )
    )

    print("\n[6] Sauvegarde du modèle...")

    MODEL_PATH.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    joblib.dump(model, MODEL_PATH)

    print("Modèle enregistré :", MODEL_PATH)

    print("\nEntraînement terminé avec succès.")


if __name__ == "__main__":

    if len(sys.argv) != 2:

        raise SystemExit(
            "Usage: python train.py dataset_prepare.csv"
        )

    main(sys.argv[1])
