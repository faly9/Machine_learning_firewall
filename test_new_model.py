import joblib

MODEL_PATH = "models/random_forest_firewall.joblib"

print("=" * 60)
print("VERIFICATION DU NOUVEAU RANDOM FOREST")
print("=" * 60)

data = joblib.load(MODEL_PATH)

model = data["model"]
features = data["features"]
classes = data["classes"]

print("\n[OK] Modèle chargé")
print("Nombre de caractéristiques :", len(features))
print("Nombre de classes :", len(classes))

print("\nCARACTERISTIQUES :")
for i, feature in enumerate(features, start=1):
    print(f"{i:02d}. {feature}")

print("\nCLASSES :")
for classe in classes:
    print("-", classe)

print("\nAccuracy enregistrée :", data.get("accuracy"))

print("\n[OK] Vérification terminée")
