"""
ZYDER Gemini Incident Reporter
==============================
Prepares structured incident data from ZYDER detections and
generates SOC-style reports using Google Gemini.

Gemini is used as the analyst/interpretation layer.
Detection decisions remain with ZYDER's ML + signature + hybrid engines.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional

from google import genai


logger = logging.getLogger("zyder.reporting")


@dataclass
class IncidentReport:
    """Structured incident data for ZYDER detection events."""

    timestamp: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    ml_prediction: str
    ml_confidence: float
    signature_result: Optional[str]
    top_shap_features: List[Dict[str, Any]]
    feature_values: Dict[str, Any]
    severity: str
    triggered_by: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, default=str)

    @classmethod
    def from_hybrid_result(
        cls,
        hybrid_result: Any,
        flow: Dict[str, Any],
        shap_features: Optional[List[Dict[str, Any]]] = None,
    ) -> "IncidentReport":

        confidence = hybrid_result.ml_result.attack_probability

        severity_levels = {
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4,
        }

        # ML severity
        if confidence >= 0.95:
            ml_severity = "CRITICAL"
        elif confidence >= 0.85:
            ml_severity = "HIGH"
        elif confidence >= 0.70:
            ml_severity = "MEDIUM"
        else:
            ml_severity = "LOW"

        # Signature severity
        sig_severity = "LOW"

        if hybrid_result.signature_result:
            sig_severity = hybrid_result.signature_result.severity.upper()

        # Highest severity wins
        if severity_levels.get(sig_severity, 1) > severity_levels.get(
            ml_severity, 1
        ):
            severity = sig_severity
        else:
            severity = ml_severity

        sig_result_str = None

        if hybrid_result.signature_result:
            sig = hybrid_result.signature_result

            sig_result_str = (
                f"Engine: {sig.engine}, "
                f"Intrusion: {sig.is_intrusion}, "
                f"Rules: {sig.matched_rules}, "
                f"Severity: {sig.severity}"
            )

        return cls(
            timestamp=hybrid_result.timestamp,
            src_ip=flow.get(
                "src_ip",
                flow.get("source_ip", "unknown"),
            ),
            dst_ip=flow.get(
                "dst_ip",
                flow.get("destination_ip", "unknown"),
            ),
            src_port=int(
                flow.get(
                    "src_port",
                    flow.get("source_port", 0),
                )
            ),
            dst_port=int(
                flow.get(
                    "dst_port",
                    flow.get("destination_port", 0),
                )
            ),
            protocol=str(
                flow.get(
                    "protocol",
                    flow.get("proto", "unknown"),
                )
            ),
            ml_prediction=hybrid_result.ml_result.prediction,
            ml_confidence=hybrid_result.ml_result.attack_probability,
            signature_result=sig_result_str,
            top_shap_features=shap_features or [],
            feature_values={
                k: v
                for k, v in flow.items()
                if k not in (
                    "src_ip",
                    "dst_ip",
                    "source_ip",
                    "destination_ip",
                )
            },
            severity=severity,
            triggered_by=hybrid_result.triggered_by,
        )


class GeminiReporter:

    def generate_pcap_report(self, summary_data: dict) -> str:
        """Generate a full PCAP analysis report."""
        if not self.api_key:
            return self._generate_local_pcap_report(summary_data)

        try:
            return self._generate_gemini_pcap_report(summary_data)
        except Exception as e:
            logger.error(f"Gemini API call failed for PCAP report: {e}")
            return self._generate_local_pcap_report(summary_data)

    def _generate_gemini_pcap_report(self, summary_data: dict) -> str:
        if self._client is None:
            self._client = genai.Client(api_key=self.api_key)

        total = summary_data.get('flow_count', 0)
        intrusions = summary_data.get('total_intrusions', 0)
        benign = total - intrusions
        
        prompt = f"""
You are a Security Operations Center (SOC) analyst.
Generate a comprehensive ZYDER SECURITY ANALYSIS REPORT for a recently analyzed PCAP file.

DETECTION SUMMARY:
Total flows analyzed: {total}
Benign flows: {benign}
Malicious/Suspicious (Intrusions): {intrusions}

Detection Sources for Intrusions:
- ML Only: {summary_data.get('ml_only', 0)}
- Signature Only: {summary_data.get('sig_only', 0)}
- Hybrid: {summary_data.get('hybrid', 0)}

Generate the report using exactly this structure:
# ZYDER SECURITY ANALYSIS REPORT
1. Executive Summary
2. Traffic/Flow Summary
3. Detection Results
4. Security Findings
5. Final Verdict
6. Conclusion

CRITICAL RULES:
- If there are zero intrusions (Malicious/Suspicious = 0), the Final Verdict MUST be BENIGN.
- If benign, explicitly state: "Based on the analyzed network flows and the configured ML and signature-based detection engines, no malicious activity was detected in this PCAP."
- Do NOT claim the network is "completely safe." Instead, use "no malicious activity was detected."
- Do NOT fabricate fake IP addresses, protocols, or attack names. Stick to the statistical summary provided above.
- If there are intrusions, state that malicious activity was found.
"""
        logger.info("Generating Gemini PCAP report...")
        response = self._client.models.generate_content(
            model=self.model_name,
            contents=prompt,
        )
        return response.text

    def _generate_local_pcap_report(self, summary_data: dict) -> str:
        total = summary_data.get('flow_count', 0)
        intrusions = summary_data.get('total_intrusions', 0)
        benign = total - intrusions
        verdict = "BENIGN" if intrusions == 0 else "MALICIOUS"
        
        lines = [
            "ZYDER SECURITY ANALYSIS REPORT",
            "=" * 40,
            f"Final Verdict: {verdict}",
            "",
            "1. Executive Summary",
            "-" * 40,
        ]
        
        if intrusions == 0:
            lines.append("Based on the analyzed network flows and the configured ML and signature-based detection engines, no malicious activity was detected in this PCAP.")
        else:
            lines.append(f"Malicious activity detected. Found {intrusions} intrusive flows.")
            
        lines.extend([
            "",
            "2. Traffic/Flow Summary",
            "-" * 40,
            f"Total Flows: {total}",
            f"Benign Flows: {benign}",
            f"Intrusions: {intrusions}",
            "",
            "3. Detection Sources",
            "-" * 40,
            f"ML Only: {summary_data.get('ml_only', 0)}",
            f"Signature Only: {summary_data.get('sig_only', 0)}",
            f"Hybrid: {summary_data.get('hybrid', 0)}",
            "",
            "4. Conclusion",
            "-" * 40,
            "End of automated local report."
        ])
        
        return "\n".join(lines)

    """
    SOC-style incident report generator using Google Gemini.

    Gemini receives evidence already generated by ZYDER.
    It does not make the primary intrusion-detection decision.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "gemini-3.5-flash",
    ) -> None:

        self.api_key = (
            api_key.strip()
            if api_key and api_key.strip()
            else os.getenv("GEMINI_API_KEY")
        )

        self.model_name = model
        self._client = None

        if self.api_key:
            self._client = genai.Client(api_key=self.api_key)

            logger.info(
                "Gemini reporter initialized "
                f"(model={self.model_name})"
            )
        else:
            logger.info(
                "Gemini reporter initialized — NO API key. "
                "Using local report generation only."
            )

    def generate_report(self, incident: IncidentReport) -> str:
        """
        Generate a SOC-style incident report.

        Uses Gemini when an API key is available.
        Falls back to local reporting if Gemini fails.
        """

        if not self.api_key:
            return self._generate_local_report(incident)

        try:
            return self._generate_gemini_report(incident)

        except Exception as e:
            logger.error(
                f"Gemini API call failed: {e}. "
                "Falling back to local report."
            )

            return self._generate_local_report(incident)

    def _generate_gemini_report(
        self,
        incident: IncidentReport,
    ) -> str:
        """Generate a SOC-style report using Gemini."""

        if self._client is None:
            self._client = genai.Client(
                api_key=self.api_key
            )

        prompt = self._build_prompt(incident)

        logger.info("Generating Gemini incident report...")

        response = self._client.models.generate_content(
            model=self.model_name,
            contents=prompt,
        )

        if not response.text:
            raise RuntimeError(
                "Gemini returned an empty response."
            )

        logger.info(
            "Gemini report generated successfully"
        )

        return response.text

    def _build_prompt(
        self,
        incident: IncidentReport,
    ) -> str:
        """Build the SOC analyst prompt."""

        shap_section = ""

        if incident.top_shap_features:

            features_str = "\n".join(
                f"  - {f['name']}: "
                f"SHAP={f.get('shap_value', 'N/A')}, "
                f"Value={f.get('value', 'N/A')}, "
                f"Direction={f.get('direction', 'N/A')}"
                for f in incident.top_shap_features[:5]
            )

            shap_section = (
                "\nTop SHAP Feature Contributions:\n"
                f"{features_str}"
            )

        prompt = f"""
You are a Security Operations Center (SOC) analyst.

Generate a concise and professional incident report
for the following intrusion detection alert generated
by the ZYDER Network Intrusion Detection System.

IMPORTANT:
- ZYDER has already performed the detection.
- Do not override or invent the detection result.
- Explain the evidence provided.
- Do not speculate beyond the available data.
- Treat SHAP values as model-attribution evidence,
  not absolute proof of causality.

DETECTION DATA:

Timestamp:
{incident.timestamp}

Source IP:
{incident.src_ip}

Destination IP:
{incident.dst_ip}

Source Port:
{incident.src_port}

Destination Port:
{incident.dst_port}

Protocol:
{incident.protocol}

ML Prediction:
{incident.ml_prediction}

ML Confidence:
{incident.ml_confidence:.4f}
({incident.ml_confidence:.1%})

Severity:
{incident.severity}

Triggered By:
{incident.triggered_by}

Signature Detection:
{incident.signature_result or "N/A"}

{shap_section}

Generate the report with these sections:

1. INCIDENT SUMMARY
Brief description of the detected activity.

2. INDICATORS OF COMPROMISE
Key suspicious indicators present in the supplied data.

3. ML ANALYSIS
Explain why the ML model classified the traffic this way,
referencing the provided SHAP features.

4. RISK ASSESSMENT
Explain the assigned severity using only the available
detection evidence.

5. RECOMMENDED ACTIONS
Provide practical SOC response actions appropriate to the
detected activity.

Keep the report under 300 words.

Use professional cybersecurity terminology.

Do not fabricate information.
"""

        return prompt

    def _generate_local_report(
        self,
        incident: IncidentReport,
    ) -> str:
        """Generate a report without Gemini."""

        lines = [
            "=" * 65,
            "  ZYDER INTRUSION DETECTION SYSTEM — INCIDENT REPORT",
            "=" * 65,
            "",
            "INCIDENT SUMMARY",
            "-" * 40,
            f"  Timestamp:     {incident.timestamp}",
            f"  Severity:      {incident.severity}",
            f"  Triggered By:  {incident.triggered_by}",
            "",
            "NETWORK FLOW",
            "-" * 40,
            f"  Source:        {incident.src_ip}:{incident.src_port}",
            f"  Destination:   {incident.dst_ip}:{incident.dst_port}",
            f"  Protocol:      {incident.protocol}",
            "",
            "ML DETECTION",
            "-" * 40,
            f"  Prediction:    {incident.ml_prediction}",
            f"  Confidence:    {incident.ml_confidence:.4f} "
            f"({incident.ml_confidence:.1%})",
            "",
        ]

        if incident.signature_result:

            lines.extend(
                [
                    "SIGNATURE DETECTION",
                    "-" * 40,
                    f"  {incident.signature_result}",
                    "",
                ]
            )

        if incident.top_shap_features:

            lines.extend(
                [
                    "KEY INDICATORS (SHAP Analysis)",
                    "-" * 40,
                ]
            )

            for i, feat in enumerate(
                incident.top_shap_features[:5],
                1,
            ):

                direction = (
                    "-> ATTACK"
                    if feat.get("direction") == "attack"
                    else "-> BENIGN"
                )

                lines.append(
                    f"  {i}. {feat['name']:<30} "
                    f"SHAP: "
                    f"{feat.get('shap_value', 0):+.4f} "
                    f"{direction}"
                )

            lines.append("")

        lines.extend(
            [
                "END OF REPORT",
                "=" * 65,
            ]
        )

        return "\n".join(lines)