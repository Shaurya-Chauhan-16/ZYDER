"""
ZYDER — ML-Based Network Intrusion Detection System
=====================================================
Main CLI entry point.

Commands:
    python main.py train     --dataset unsw|cicids   Train XGBoost model
    python main.py evaluate  --dataset unsw|cicids   Evaluate saved model
    python main.py predict   --flow <json>           Single flow prediction
    python main.py explain   --flow <json>           Predict + SHAP explanation
    python main.py demo                              Run demo with sample flows
"""

from __future__ import annotations

import subprocess
import tempfile
import argparse
import json
import logging
import sys
from pathlib import Path

import yaml

# Ensure project root is in path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))


def load_config(config_path: str = "config/config.yaml") -> dict:
    """Load YAML configuration."""
    path = PROJECT_ROOT / config_path
    if not path.exists():
        print(f"ERROR: Config file not found: {path}")
        sys.exit(1)
    with open(path) as f:
        return yaml.safe_load(f)


def cmd_train(args: argparse.Namespace) -> None:
    """Train XGBoost model."""
    from training.train import train
    train(
        dataset=args.dataset,
        config_path=args.config,
        mode=args.mode,
    )

def get_detection_threshold(config: dict, dataset: str) -> float:
    """Get the detection threshold for the selected dataset."""
    detection_cfg = config.get("detection", {})
    threshold_cfg = detection_cfg.get("threshold", 0.5)

    if isinstance(threshold_cfg, dict):
        return float(threshold_cfg.get(dataset, 0.5))

    return float(threshold_cfg)

def cmd_evaluate(args: argparse.Namespace) -> None:
    """Evaluate a saved model on test data."""
    from training.train import (
        load_config as load_train_config,
        setup_logging,
        get_preprocessor,
        split_data,
        remove_near_duplicates,
    )
    from training.evaluate import ZyderEvaluator
    from xgboost import XGBClassifier

    config = load_train_config(PROJECT_ROOT / args.config)
    setup_logging(config, PROJECT_ROOT)
    logger = logging.getLogger("zyder.evaluate")

    logger.info("Loading saved model and preprocessing data...")

    # Load model
    model_dir = PROJECT_ROOT / config["paths"]["models_dir"]
    model_path = model_dir / f"zyder_xgboost_{args.dataset}.json"
    if not model_path.exists():
        logger.error(f"Model not found: {model_path}. Train first.")
        sys.exit(1)

    model = XGBClassifier()
    model.load_model(str(model_path))

    # Preprocess data
    preprocessor = get_preprocessor(args.dataset, config, PROJECT_ROOT)
    X, y = preprocessor.preprocess(mode=args.mode)
    X, y = remove_near_duplicates(X, y)
    _, _, X_test, _, _, y_test = split_data(X, y, config)

    # Evaluate
    output_dir = PROJECT_ROOT / config["paths"]["outputs_dir"]
    evaluator = ZyderEvaluator(
        model=model,
        feature_names=preprocessor.feature_names,
        output_dir=output_dir,
        dataset_name=args.dataset,
    )

    threshold = get_detection_threshold(config, args.dataset)
    evaluator.evaluate(X_test, y_test, threshold=threshold)


def cmd_predict(args: argparse.Namespace) -> None:
    """Predict on a single flow."""
    from detection.detector import ZyderMLDetector
    from detection.pcap_pipeline import extract_cicids_flows

    config = load_config(args.config)
    threshold = get_detection_threshold(config, args.dataset)

    detector = ZyderMLDetector(
        model_dir=config["paths"]["models_dir"],
        dataset=args.dataset,
        threshold=threshold,
        base_dir=PROJECT_ROOT,
    )
    detector.load()

    # Get flow from JSON or PCAP
    if args.pcap:
        if args.dataset != "cicids":
            print("ERROR: --pcap is currently supported only for --dataset cicids.")
            sys.exit(1)

        print(f"\n   Reading PCAP: {args.pcap}")

        try:
            flows = extract_cicids_flows(args.pcap)
        except Exception as e:
            print(f"ERROR: PCAP processing failed: {e}")
            sys.exit(1)

        if not flows:
            print("ERROR: No network flows were extracted from the PCAP.")
            sys.exit(1)

        print(f"   Extracted {len(flows)} flow(s).")
        flow = flows[0]
    elif args.flow:
        try:
            flow = json.loads(args.flow)
        except json.JSONDecodeError as e:
            print(f"ERROR: Invalid JSON: {e}")
            sys.exit(1)
    else:
        print("ERROR: Provide either --flow or --pcap.")
        sys.exit(1)

    result = detector.predict(flow)
    print(result)
    print(f"\nJSON:\n{json.dumps(result.to_dict(), indent=2)}")


def cmd_explain(args: argparse.Namespace) -> None:
    """Predict + SHAP explanation for a single flow."""
    from detection.detector import ZyderMLDetector
    from detection.pcap_pipeline import extract_cicids_flows
    from explainability.shap_explainer import ZyderSHAPExplainer

    config = load_config(args.config)
    threshold = get_detection_threshold(config, args.dataset)

    detector = ZyderMLDetector(
        model_dir=config["paths"]["models_dir"],
        dataset=args.dataset,
        threshold=threshold,
        base_dir=PROJECT_ROOT,
    )
    detector.load()

    if args.pcap:
        if args.dataset != "cicids":
            print("ERROR: --pcap is currently supported only for --dataset cicids.")
            sys.exit(1)

        print(f"\n   Reading PCAP: {args.pcap}")

        try:
            flows = extract_cicids_flows(args.pcap)
        except Exception as e:
            print(f"ERROR: PCAP processing failed: {e}")
            sys.exit(1)

        if not flows:
            print("ERROR: No network flows were extracted from the PCAP.")
            sys.exit(1)

        flow = flows[0]
    elif args.flow:
        try:
            flow = json.loads(args.flow)
        except json.JSONDecodeError as e:
            print(f"ERROR: Invalid JSON: {e}")
            sys.exit(1)
    else:
        print("ERROR: Provide either --flow or --pcap.")
        sys.exit(1)

    # Prepare features
    features = detector._prepare_features(flow)

    # SHAP explanation
    explainer = ZyderSHAPExplainer(
        model=detector.get_model(),
        feature_names=detector.get_feature_names(),
    )
    explanation = explainer.explain_single(features, threshold=threshold)
    print(explanation)

    # Save waterfall plot
    output_dir = PROJECT_ROOT / config["paths"]["outputs_dir"]
    output_dir.mkdir(parents=True, exist_ok=True)
    explainer.plot_waterfall(features, save_path=output_dir / "waterfall_single.png")


def cmd_demo(args: argparse.Namespace) -> None:
    """Run a demo with sample flows showing the full pipeline."""
    from detection.detector import ZyderMLDetector
    from detection.hybrid_detector import HybridDetector, RuleBasedSignatureDetector
    from detection.suricata_detector import SuricataDetector
    from explainability.shap_explainer import ZyderSHAPExplainer
    from reporting.gemini_reporter import GeminiReporter, IncidentReport

    config = load_config(args.config)
    threshold = get_detection_threshold(config, args.dataset)

    print("\n" + "=" * 60)
    print("  ZYDER — Hybrid IDS Demo")
    print("=" * 60)

    # Check if model exists
    model_dir = PROJECT_ROOT / config["paths"]["models_dir"]
    model_path = model_dir / f"zyder_xgboost_{args.dataset}.json"
    if not model_path.exists():
        print(f"\n[!]  No trained model found for '{args.dataset}'.")
        print(f"   Train first: python main.py train --dataset {args.dataset}")
        sys.exit(1)

    # Initialize components
    print("\n1. Initializing ML Detector...")
    ml_detector = ZyderMLDetector(
        model_dir=config["paths"]["models_dir"],
        dataset=args.dataset,
        threshold=threshold,
        base_dir=PROJECT_ROOT,
    )
    ml_detector.load()

    print("2. Initializing Signature Detector (ZYDER Rules)...")
    eve_log = config["paths"]["suricata_eve_log"]
    sig_detector = SuricataDetector(eve_log)

    print("3. Initializing Hybrid Detector...")
    hybrid_detector = HybridDetector(ml_detector, sig_detector)

    print("4. Initializing SHAP Explainer...")
    explainer = ZyderSHAPExplainer(
        model=ml_detector.get_model(),
        feature_names=ml_detector.get_feature_names(),
    )

    print("5. Initializing Gemini Reporter...")
    gemini_key = config.get("gemini", {}).get("api_key", "")
    reporter = GeminiReporter(api_key=gemini_key)

    # Sample flows for demo
    feature_names = ml_detector.get_feature_names()
    # Create a benign-looking flow (low values, common port)
    benign_flow = {feat: 0 for feat in feature_names}
    benign_flow.update({
        "src_ip": "192.168.1.100",
        "dst_ip": "8.8.8.8",
        "src_port": 52341,
        "dst_port": 53,
        "protocol": 17,  # UDP
        "flow_duration": 0.01,
        "fwd_packet_count": 1,
        "bwd_packet_count": 1,
        "fwd_bytes": 64,
        "bwd_bytes": 128,
    })

    # Create a suspicious flow (unusual port, high rate)
    suspicious_flow = {feat: 0 for feat in feature_names}
    suspicious_flow.update({
        "src_ip": "10.0.0.55",
        "dst_ip": "192.168.1.1",
        "src_port": 4444,
        "dst_port": 445,
        "protocol": 6,  # TCP
        "flow_duration": 0.001,
        "fwd_packet_count": 500,
        "bwd_packet_count": 0,
        "fwd_bytes": 50000,
        "bwd_bytes": 0,
        "packet_rate": 500000,
        "byte_rate": 50000000,
    })

    # Demo flow 1: Benign
    print("\n" + "-" * 60)
    print("  Demo Flow 1: Normal DNS Query")
    print("-" * 60)
    result1 = hybrid_detector.detect(benign_flow)
    print(result1)

    # Demo flow 2: Suspicious
    print("\n" + "-" * 60)
    print("  Demo Flow 2: Suspicious Traffic")
    print("-" * 60)
    result2 = hybrid_detector.detect(suspicious_flow)
    print(result2)

    # SHAP explanation for the suspicious flow
    if result2.is_intrusion:
        print("\n  Generating SHAP explanation...")
        features = ml_detector._prepare_features(suspicious_flow)
        explanation = explainer.explain_single(features, threshold=threshold)
        print(explanation)

        # Generate incident report
        print("\n  Generating Incident Report...")
        incident = IncidentReport.from_hybrid_result(
            result2, suspicious_flow,
            shap_features=explanation.top_features,
        )
        report = reporter.generate_report(incident)
        print(report)

    print("\n" + "=" * 60)
    print("  Demo Complete!")
    print("=" * 60)

def cmd_hybrid(args: argparse.Namespace) -> None:
    """Run hybrid detection on one or more network flows."""
    from detection.detector import ZyderMLDetector
    from detection.hybrid_detector import HybridDetector
    from detection.pcap_pipeline import extract_cicids_flows
    from detection.suricata_detector import SuricataDetector
    from explainability.shap_explainer import ZyderSHAPExplainer
    from reporting.gemini_reporter import GeminiReporter, IncidentReport

    config = load_config(args.config)
    threshold = get_detection_threshold(config, args.dataset)

    flows: list[dict] = []

    # Parse flow JSON or load from PCAP
    if args.pcap:
        if args.dataset != "cicids":
            print("ERROR: --pcap is currently supported only for --dataset cicids.")
            sys.exit(1)

        print(f"\n   Reading PCAP: {args.pcap}")
        try:
            flows = extract_cicids_flows(args.pcap)
        except Exception as e:
            print(f"ERROR: PCAP processing failed: {e}")
            sys.exit(1)

        if not flows:
            print("ERROR: No network flows were extracted from the PCAP.")
            sys.exit(1)

        print(f"   Extracted {len(flows)} flow(s).")
    else:
        if not args.flow:
            print("ERROR: Provide either --flow or --pcap.")
            sys.exit(1)

        try:
            flows = [json.loads(args.flow)]
        except json.JSONDecodeError as e:
            print(f"ERROR: Invalid JSON: {e}")
            sys.exit(1)

    # Initialize ML detector
    print("\n1. Initializing ML Detector...")
    ml_detector = ZyderMLDetector(
        model_dir=config["paths"]["models_dir"],
        dataset=args.dataset,
        threshold=threshold,
        base_dir=PROJECT_ROOT,
    )
    ml_detector.load()

    # Initialize signature detector
    print("\n2. Initializing Signature Detector (Suricata)...")
    if args.pcap:
        suricata_output = Path(tempfile.mkdtemp(prefix="zyder-pcap-suricata-"))
        suricata_config = "/opt/homebrew/etc/suricata/suricata.yaml"
        zyder_rules = "/opt/homebrew/etc/suricata/rules/zyder.rules"

        print("\n   Running Suricata on PCAP...")
        try:
            subprocess.run(
                [
                    "suricata",
                    "-r",
                    args.pcap,
                    "-c",
                    suricata_config,
                    "-S",
                    zyder_rules,
                    "-l",
                    str(suricata_output),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError as e:
            print("ERROR: Suricata processing failed.")
            if e.stderr:
                print(e.stderr)
            sys.exit(1)

        eve_log = suricata_output / "eve.json"
        if not eve_log.exists():
            print(f"ERROR: Suricata did not produce EVE log: {eve_log}")
            sys.exit(1)

        print(f"   Suricata EVE: {eve_log}")
        sig_detector = SuricataDetector(str(eve_log))
    else:
        sig_detector = SuricataDetector("/tmp/zyder-smb-suricata/eve.json")

    # Initialize hybrid detector
    print("\n3. Initializing Hybrid Detector...")
    hybrid_detector = HybridDetector(ml_detector, sig_detector)

    # Run hybrid detection
    print("\n4. Running Hybrid Detection...")

    results = []
    for i, current_flow in enumerate(flows, start=1):
        print("\n" + "=" * 70)
        print(f"FLOW {i}/{len(flows)}")
        print("=" * 70)

        result = hybrid_detector.detect(current_flow)
        results.append((current_flow, result))
        print(result)

        if result.is_intrusion:
            print("\n5. Generating SHAP explanation...")

            explainer = ZyderSHAPExplainer(
                model=ml_detector.get_model(),
                feature_names=ml_detector.get_feature_names(),
            )

            features = ml_detector._prepare_features(current_flow)
            explanation = explainer.explain_single(features, threshold=threshold)
            print(explanation)

            print("\n6. Generating Incident Report...")

            gemini_key = config.get("gemini", {}).get("api_key", "")
            reporter = GeminiReporter(api_key=gemini_key)

            incident = IncidentReport.from_hybrid_result(
                result,
                current_flow,
                shap_features=explanation.top_features,
            )

            report = reporter.generate_report(incident)
            print(report)

    print("\n" + "=" * 70)
    print("ZYDER DETECTION SUMMARY")
    print("=" * 70)

    total_flows = len(results)
    intrusion_flows = sum(1 for _, r in results if r.is_intrusion)
    ml_attacks = sum(1 for _, r in results if r.ml_result.is_intrusion)
    signature_alerts = sum(1 for _, r in results if r.signature_result and r.signature_result.is_intrusion)
    both_detections = sum(
        1 for _, r in results if r.ml_result.is_intrusion and r.signature_result and r.signature_result.is_intrusion
    )

    print(f"PCAP:             {args.pcap or 'n/a'}")
    print(f"Total Flows:      {total_flows}")
    print(f"Intrusion Flows:  {intrusion_flows}")
    print(f"ML Attacks:       {ml_attacks}")
    print(f"Signature Alerts: {signature_alerts}")
    print(f"Both ML + SIG:    {both_detections}")

    if intrusion_flows > 0:
        print("\nFINAL VERDICT: INTRUSION")
    else:
        print("\nFINAL VERDICT: BENIGN")


def main() -> None:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="ZYDER — ML-Based Network Intrusion Detection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py train --dataset unsw
  python main.py train --dataset cicids --mode zyder
  python main.py evaluate --dataset unsw
  python main.py predict --dataset unsw --flow '{"dst_port": 445, "protocol": 6}'
  python main.py explain --dataset unsw --flow '{"dst_port": 445, "protocol": 6}'
  python main.py demo --dataset unsw
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # ---- train ----
    p_train = subparsers.add_parser("train", help="Train XGBoost model")
    p_train.add_argument("--dataset", required=True, choices=["unsw", "cicids"])
    p_train.add_argument("--config", default="config/config.yaml")
    p_train.add_argument("--mode", default="native", choices=["native", "zyder"])

    # ---- evaluate ----
    p_eval = subparsers.add_parser("evaluate", help="Evaluate saved model")
    p_eval.add_argument("--dataset", required=True, choices=["unsw", "cicids"])
    p_eval.add_argument("--config", default="config/config.yaml")
    p_eval.add_argument("--mode", default="native", choices=["native", "zyder"])

    # ---- predict ----
    p_pred = subparsers.add_parser("predict", help="Single flow prediction")
    p_pred.add_argument("--dataset", default="unsw", choices=["unsw", "cicids"])
    p_pred.add_argument("--config", default="config/config.yaml")
    p_pred.add_argument("--flow", help="Flow data as JSON string")
    p_pred.add_argument("--pcap", help="PCAP file for real traffic analysis")

    # ---- explain ----
    p_explain = subparsers.add_parser("explain", help="Predict + SHAP explanation")
    p_explain.add_argument("--dataset", default="unsw", choices=["unsw", "cicids"])
    p_explain.add_argument("--config", default="config/config.yaml")
    p_explain.add_argument("--flow", help="Flow data as JSON string")
    p_explain.add_argument("--pcap", help="PCAP file for real traffic analysis")

    # ---- hybrid ----
    p_hybrid = subparsers.add_parser("hybrid", help="Run hybrid ML + signature detection")
    p_hybrid.add_argument("--dataset", default="unsw", choices=["unsw", "cicids"])
    p_hybrid.add_argument("--config", default="config/config.yaml")
    p_hybrid.add_argument("--flow", help="Flow data as JSON string")
    p_hybrid.add_argument("--pcap", help="PCAP file for real traffic analysis")

    # ---- demo ----
    p_demo = subparsers.add_parser("demo", help="Run full pipeline demo")
    p_demo.add_argument("--dataset", default="unsw", choices=["unsw", "cicids"])
    p_demo.add_argument("--config", default="config/config.yaml")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(0)

    commands = {
    "train": cmd_train,
    "evaluate": cmd_evaluate,
    "predict": cmd_predict,
    "explain": cmd_explain,
    "hybrid": cmd_hybrid,
    "demo": cmd_demo,
}

    commands[args.command](args)


if __name__ == "__main__":
    main()
