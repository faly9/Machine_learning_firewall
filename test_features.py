from capture.flows import WindowAggregator, FEATURES

aggregator = WindowAggregator()

# Vérifier la construction du dictionnaire
flow = aggregator._new_flow(
    "192.168.1.10",
    "192.168.1.20",
    50000,
    22,
    6
)

flow["fwd_packets"] = 2
flow["bwd_packets"] = 2

flow["fwd_bytes"] = 120
flow["bwd_bytes"] = 180

flow["fwd_lengths"] = [60, 60]
flow["bwd_lengths"] = [90, 90]

flow["timestamps"] = [
    1000.0,
    1000.1,
    1000.2,
    1000.3
]

flow["syn"] = 1
flow["ack"] = 3

flow["init_win_fwd"] = 64240
flow["init_win_bwd"] = 65160

flow["act_data_pkt_fwd"] = 1
flow["min_seg_size_forward"] = 20

features = aggregator._build_features(flow)

print("Nombre de caractéristiques :", len(features))

print("\nCaractéristiques calculées :")

for i, name in enumerate(FEATURES, 1):
    print(f"{i:02d}. {name} = {features[name]}")

assert len(features) == 23
assert list(features.keys()) == FEATURES

print("\n[OK] Les 23 caractéristiques sont présentes.")
