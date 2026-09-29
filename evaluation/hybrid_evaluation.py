import argparse
import json
import subprocess
import tempfile
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pandas as pd
import yaml

from detection.pcap_pipeline import extract_cicids_flows
from detection.detector import ZyderMLDetector
from detection.suricata_detector import SuricataDetector


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def load_config():
    with open(PROJECT_ROOT / "config/config.yaml", "r") as f:
        return yaml.safe_load(f)


def get_threshold(config):
    value = config.get("detection", {}).get("threshold", 0.5)

    if isinstance(value, dict):
        return float(value.get("cicids", 0.75))

    return float(value)


def run_suricata(pcap):
    output_dir = Path(
        tempfile.mkdtemp(prefix="zyder-hybrid-eval-")
    )

    config = "/opt/homebrew/etc/suricata/suricata.yaml"
    rules = "/opt/homebrew/etc/suricata/rules/zyder.rules"

    print(f"Running Suricata on: {pcap}")

    subprocess.run(
        [
            "suricata",
            "-r",
            str(pcap),
            "-c",
            config,
            "-S",
            rules,
            "-l",
            str(output_dir),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    eve = output_dir / "eve.json"

    if not eve.exists():
        raise RuntimeError(
            f"Suricata did not create EVE log: {eve}"
        )

    return eve


def evaluate_metrics(y_true, y_pred):
    tp = int(((y_true == 1) & (y_pred == 1)).sum())
    tn = int(((y_true == 0) & (y_pred == 0)).sum())
    fp = int(((y_true == 0) & (y_pred == 1)).sum())
    fn = int(((y_true == 1) & (y_pred == 0)).sum())

    total = len(y_true)

    accuracy = (tp + tn) / total if total else 0

    precision = (
        tp / (tp + fp)
        if (tp + fp)
        else 0
    )

    recall = (
        tp / (tp + fn)
        if (tp + fn)
        else 0
    )

    f1 = (
        2 * precision * recall /
        (precision + recall)
        if (precision + recall)
        else 0
    )

    fpr = (
        fp / (fp + tn)
        if (fp + tn)
        else 0
    )

    return {
        "TP": tp,
        "TN": tn,
        "FP": fp,
        "FN": fn,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
    }


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--pcap",
        required=True,
        help="PCAP file to evaluate",
    )

    parser.add_argument(
        "--ground-truth",
        required=True,
        choices=["benign", "attack"],
        help="Ground-truth label for this PCAP",
    )

    args = parser.parse_args()

    pcap = Path(args.pcap)

    if not pcap.exists():
        raise FileNotFoundError(pcap)

    config = load_config()
    threshold = get_threshold(config)

    print("=" * 70)
    print("ZYDER MULTI-FLOW HYBRID EVALUATION")
    print("=" * 70)

    print(f"PCAP        : {pcap}")
    print(f"Ground truth: {args.ground_truth.upper()}")
    print(f"Threshold   : {threshold}")

    # ---------------------------------------------------------
    # 1. Extract flows
    # ---------------------------------------------------------

    print("\n[1/4] Extracting flows...")

    flows = extract_cicids_flows(str(pcap))

    print(f"Extracted flows: {len(flows)}")

    if not flows:
        raise RuntimeError("No flows extracted.")

    # ---------------------------------------------------------
    # 2. Load ML detector
    # ---------------------------------------------------------

    print("\n[2/4] Loading ML detector...")

    detector = ZyderMLDetector(
        model_dir=config["paths"]["models_dir"],
        dataset="cicids",
        threshold=threshold,
        base_dir=PROJECT_ROOT,
    )

    detector.load()

    # ---------------------------------------------------------
    # 3. Run Suricata
    # ---------------------------------------------------------

    print("\n[3/4] Running Suricata...")

    eve_log = run_suricata(pcap)

    signature_detector = SuricataDetector(
        str(eve_log)
    )

    # ---------------------------------------------------------
    # 4. Evaluate every flow
    # ---------------------------------------------------------

    print("\n[4/4] Evaluating every flow...")

    rows = []

    for i, flow in enumerate(flows, start=1):

        # -------------------------
        # ML
        # -------------------------

        ml_result = detector.predict(flow)

        ml_probability = float(
            ml_result.attack_probability
        )

        ml_attack = (
            ml_probability >= threshold
        )

        # -------------------------
        # Signature
        # -------------------------

        sig_result = signature_detector.detect(flow)

        signature_attack = bool(
            sig_result.is_intrusion
        )

        # -------------------------
        # Hybrid OR fusion
        # -------------------------

        hybrid_attack = (
            ml_attack or signature_attack
        )

        if ml_attack and signature_attack:
            trigger = "BOTH"

        elif ml_attack:
            trigger = "ML"

        elif signature_attack:
            trigger = "SIGNATURE"

        else:
            trigger = "NONE"

        # -------------------------
        # Ground truth
        # -------------------------

        ground_truth = (
            1 if args.ground_truth == "attack"
            else 0
        )

        # -------------------------
        # Store
        # -------------------------

        rows.append({
            "flow_id": i,

            "ground_truth":
                "ATTACK"
                if ground_truth
                else "BENIGN",

            "ml_probability":
                ml_probability,

            "ml_verdict":
                "ATTACK"
                if ml_attack
                else "BENIGN",

            "signature_verdict":
                "ATTACK"
                if signature_attack
                else "BENIGN",

            "signature_rules":
                "; ".join(
                    sig_result.matched_rules
                ),

            "hybrid_verdict":
                "ATTACK"
                if hybrid_attack
                else "BENIGN",

            "hybrid_trigger":
                trigger,

            "src_ip":
                flow.get("src_ip", ""),

            "dst_ip":
                flow.get("dst_ip", ""),

            "src_port":
                flow.get("src_port", ""),

            "dst_port":
                flow.get("dst_port", ""),

            "protocol":
                flow.get("protocol", ""),

            "timestamp":
                flow.get("timestamp", ""),
        })

        if i % 100 == 0:
            print(
                f"Processed {i}/{len(flows)} flows..."
            )

    df = pd.DataFrame(rows)

    # ---------------------------------------------------------
    # Metrics
    # ---------------------------------------------------------

    y_true = (
        df["ground_truth"]
        .eq("ATTACK")
        .astype(int)
        .to_numpy()
    )

    ml_pred = (
        df["ml_verdict"]
        .eq("ATTACK")
        .astype(int)
        .to_numpy()
    )

    sig_pred = (
        df["signature_verdict"]
        .eq("ATTACK")
        .astype(int)
        .to_numpy()
    )

    hybrid_pred = (
        df["hybrid_verdict"]
        .eq("ATTACK")
        .astype(int)
        .to_numpy()
    )

    ml_metrics = evaluate_metrics(
        y_true,
        ml_pred
    )

    sig_metrics = evaluate_metrics(
        y_true,
        sig_pred
    )

    hybrid_metrics = evaluate_metrics(
        y_true,
        hybrid_pred
    )

    # ---------------------------------------------------------
    # Component counts
    # ---------------------------------------------------------

    ml_only = int(
        (
            (ml_pred == 1) &
            (sig_pred == 0)
        ).sum()
    )

    signature_only = int(
        (
            (ml_pred == 0) &
            (sig_pred == 1)
        ).sum()
    )

    both = int(
        (
            (ml_pred == 1) &
            (sig_pred == 1)
        ).sum()
    )

    neither = int(
        (
            (ml_pred == 0) &
            (sig_pred == 0)
        ).sum()
    )

    # ---------------------------------------------------------
    # Save
    # ---------------------------------------------------------

    output_dir = PROJECT_ROOT / "outputs"
    output_dir.mkdir(exist_ok=True)

    csv_path = (
        output_dir /
        f"hybrid_{pcap.stem}_flows.csv"
    )

    json_path = (
        output_dir /
        f"hybrid_{pcap.stem}_results.json"
    )

    df.to_csv(
        csv_path,
        index=False
    )

    results = {
        "pcap": str(pcap),
        "ground_truth": args.ground_truth,
        "total_flows": len(df),
        "threshold": threshold,

        "component_counts": {
            "ml_only": ml_only,
            "signature_only": signature_only,
            "both": both,
            "neither": neither,
        },

        "ml_metrics": ml_metrics,
        "signature_metrics": sig_metrics,
        "hybrid_metrics": hybrid_metrics,
    }

    with open(json_path, "w") as f:
        json.dump(
            results,
            f,
            indent=2
        )

    # ---------------------------------------------------------
    # Print final results
    # ---------------------------------------------------------

    print("\n")
    print("=" * 70)
    print("ZYDER HYBRID EVALUATION RESULTS")
    print("=" * 70)

    print(f"Total flows: {len(df)}")

    print("\nML:")
    print(json.dumps(
        ml_metrics,
        indent=2
    ))

    print("\nSIGNATURE:")
    print(json.dumps(
        sig_metrics,
        indent=2
    ))

    print("\nHYBRID:")
    print(json.dumps(
        hybrid_metrics,
        indent=2
    ))

    print("\nComponent Complementarity:")
    print(f"ML only       : {ml_only}")
    print(f"Signature only: {signature_only}")
    print(f"Both          : {both}")
    print(f"Neither       : {neither}")

    print("\nSaved:")
    print(csv_path)
    print(json_path)


if __name__ == "__main__":
    main()
