import os
from reporting.gemini_reporter import GeminiReporter, IncidentReport


def run_test(name, incident):
    print("\n" + "=" * 70)
    print(name)
    print("=" * 70)

    reporter = GeminiReporter(
        api_key=os.getenv("GEMINI_API_KEY"),
        model="gemini-3.5-flash",
    )

    report = reporter.generate_report(incident)

    print(report)


# G1 — ML + Signature
g1 = IncidentReport(
    timestamp="2026-08-12T08:00:00Z",
    src_ip="10.0.0.20",
    dst_ip="192.168.1.10",
    src_port=49152,
    dst_port=80,
    protocol="TCP",
    ml_prediction="ATTACK",
    ml_confidence=0.97,
    signature_result=(
        "Engine: Suricata, "
        "Intrusion: True, "
        "Rules: HTTP_ATTACK_RULE, "
        "Severity: HIGH"
    ),
    top_shap_features=[
        {
            "name": "Flow Duration",
            "shap_value": 0.31,
            "value": 5000,
            "direction": "attack",
        },
        {
            "name": "Packet Rate",
            "shap_value": 0.24,
            "value": 850,
            "direction": "attack",
        },
    ],
    feature_values={
        "flow_duration": 5000,
        "packet_rate": 850,
    },
    severity="CRITICAL",
    triggered_by="BOTH",
)


# G3 — ML only
g3 = IncidentReport(
    timestamp="2026-08-12T08:05:00Z",
    src_ip="10.0.0.30",
    dst_ip="192.168.1.20",
    src_port=4444,
    dst_port=8080,
    protocol="TCP",
    ml_prediction="ATTACK",
    ml_confidence=0.93,
    signature_result=None,
    top_shap_features=[
        {
            "name": "Flow Packets/s",
            "shap_value": 0.42,
            "value": 1200,
            "direction": "attack",
        },
        {
            "name": "Total Fwd Packets",
            "shap_value": 0.27,
            "value": 900,
            "direction": "attack",
        },
    ],
    feature_values={
        "flow_packets_per_second": 1200,
        "total_fwd_packets": 900,
    },
    severity="HIGH",
    triggered_by="ML",
)


# G4 — Benign
g4 = IncidentReport(
    timestamp="2026-08-12T08:10:00Z",
    src_ip="192.168.1.100",
    dst_ip="8.8.8.8",
    src_port=52341,
    dst_port=53,
    protocol="UDP",
    ml_prediction="BENIGN",
    ml_confidence=0.001,
    signature_result=None,
    top_shap_features=[
        {
            "name": "Destination Port",
            "shap_value": -0.21,
            "value": 53,
            "direction": "benign",
        }
    ],
    feature_values={
        "destination_port": 53,
    },
    severity="LOW",
    triggered_by="NONE",
)


# G5 — Weak / incomplete evidence
g5 = IncidentReport(
    timestamp="2026-08-12T08:15:00Z",
    src_ip="10.0.0.50",
    dst_ip="192.168.1.50",
    src_port=50000,
    dst_port=443,
    protocol="TCP",
    ml_prediction="BENIGN",
    ml_confidence=0.51,
    signature_result=None,
    top_shap_features=[],
    feature_values={},
    severity="LOW",
    triggered_by="NONE",
)


run_test("G1 — ML + SIGNATURE", g1)
run_test("G3 — ML ONLY", g3)
run_test("G4 — BENIGN", g4)
run_test("G5 — WEAK / INCOMPLETE EVIDENCE", g5)
