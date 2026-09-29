import json
import joblib
import pandas as pd
from pathlib import Path

from detection.detector import ZyderMLDetector

# --------------------------------------------------
# CONFIG
# --------------------------------------------------

CSV_PATH = "Dataset/archivecicd/Wednesday-workingHours.pcap_ISCX.csv"

# Use a real GoldenEye flow
df = pd.read_csv(CSV_PATH)

# Clean column names exactly like your CICIDS preprocessor
df.columns = df.columns.str.strip()

# Select real DoS GoldenEye flow
attack_rows = df[
    df["Label"].astype(str).str.strip() == "DoS GoldenEye"
]

if attack_rows.empty:
    raise RuntimeError("No DoS GoldenEye flows found.")

# Select first real flow
row = attack_rows.iloc[0]

print("=" * 70)
print("REAL CICIDS2017 GOLDENEYE TEST")
print("=" * 70)

print("Dataset label :", row["Label"])
print("Destination Port:", row["Destination Port"])

# --------------------------------------------------
# LOAD THE SAME FEATURES USED BY ZYDER
# --------------------------------------------------

preprocess = joblib.load("models/preprocessing_cicids.pkl")

feature_names = preprocess["feature_names"]

# Build flow using exactly the 71 CICIDS features
flow = {}

for feature in feature_names:
    value = row.get(feature, 0)

    if pd.isna(value):
        value = 0

    flow[feature] = float(value)

# Metadata for reporting
flow["dst_port"] = int(row["Destination Port"])
flow["protocol"] = 6

# --------------------------------------------------
# RUN ZYDER ML
# --------------------------------------------------

detector = ZyderMLDetector(
    model_dir="models",
    dataset="cicids",
    threshold=0.75
)

detector.load()

result = detector.predict(flow)

print()
print("ZYDER ML RESULT")
print("-" * 70)
print("Prediction       :", result.prediction)
print("Attack probability:", result.attack_probability)
print("Threshold         :", result.threshold)
print("Intrusion         :", result.is_intrusion)

print()
print("Expected ground truth: ATTACK")
print("Expected signature    : BENIGN")
print("Reason: destination port is", row["Destination Port"],
      "while the current Suricata rule monitors TCP/445.")

print()
print("Full flow:")
print(json.dumps(flow, indent=2))

print("=" * 70)
