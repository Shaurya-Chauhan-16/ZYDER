"""
ZYDER Hybrid Detector
======================
Implements the paper's hybrid detection fusion:

    D(X) = Ds(X) OR Dm(X)

Where:
    Ds(X) = Signature-based detection (Snort/Suricata)
    Dm(X) = XGBoost ML detection

If EITHER detector flags an intrusion, the final verdict is INTRUSION.

The signature detector is defined as an abstract interface (ABC) so
that a real Snort/Suricata integration can be plugged in later.
A StubSignatureDetector is provided for testing.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Dict, List, Optional

from detection.detector import DetectionResult, ZyderMLDetector

logger = logging.getLogger("zyder.detection.hybrid")


# ============================================================
# Signature Detection Interface
# ============================================================

@dataclass
class SignatureResult:
    """Result from a signature-based detector."""
    is_intrusion: bool          # True if signature matched
    matched_rules: List[str]    # List of matched rule IDs/names
    severity: str               # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    engine: str                 # "snort", "suricata", "stub", etc.
    details: str = ""           # Human-readable match details

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class SignatureDetector(ABC):
    """
    Abstract interface for signature-based intrusion detection.

    To integrate a real engine (Snort, Suricata, etc.), create a
    subclass that implements the detect() method. The detect() method
    receives a flow dict and returns a SignatureResult.

    Example future integration:
        class SnortDetector(SignatureDetector):
            def detect(self, flow: dict) -> SignatureResult:
                # Send flow to Snort via Unix socket / API
                # Parse alert output
                # Return SignatureResult
    """

    @abstractmethod
    def detect(self, flow: Dict[str, Any]) -> SignatureResult:
        """
        Analyze a network flow against known attack signatures.

        Args:
            flow: Network flow data (IPs, ports, protocol, payload, etc.)

        Returns:
            SignatureResult indicating whether any signatures matched.
        """
        ...

class RuleBasedSignatureDetector(SignatureDetector):
    """
    Lightweight rule-based signature detector.

    This is a development/testing implementation that mimics
    signature-based detection using simple network-flow rules.

    It is NOT a replacement for Snort or Suricata.
    """

    def detect(self, flow: Dict[str, Any]) -> SignatureResult:
        matched_rules: List[str] = []
        rule_severities: List[str] = []

        dst_port = flow.get("dst_port", flow.get("destination_port", 0))
        src_port = flow.get("src_port", flow.get("source_port", 0))
        protocol = flow.get("protocol", 0)

        # Rule 1: SMB
        if dst_port == 445 or src_port == 445:
            matched_rules.append("SIG-SMB-445")
            rule_severities.append("HIGH")

        # Rule 2: Telnet
        if dst_port == 23 or src_port == 23:
            matched_rules.append("SIG-TELNET-23")
            rule_severities.append("MEDIUM")

        # Rule 3: FTP
        if dst_port == 21 or src_port == 21:
            matched_rules.append("SIG-FTP-21")
            rule_severities.append("MEDIUM")

        # Rule 4: High-volume TCP
        packet_count = flow.get("fwd_packet_count", flow.get("total_fwd_packets", 0))
        if protocol == 6 and packet_count >= 500:
            matched_rules.append("SIG-HIGH-VOLUME-TCP")
            rule_severities.append("HIGH")

        if matched_rules:
            severity_order = {
                "LOW": 1,
                "MEDIUM": 2,
                "HIGH": 3,
                "CRITICAL": 4,
            }
            severity = max(rule_severities, key=lambda s: severity_order[s])

            return SignatureResult(
                is_intrusion=True,
                matched_rules=matched_rules,
                severity=severity,
                engine="zyder-rules",
                details="One or more ZYDER signature rules matched.",
            )

        return SignatureResult(
            is_intrusion=False,
            matched_rules=[],
            severity="NONE",
            engine="zyder-rules",
            details="No ZYDER signature rules matched.",
        )

class StubSignatureDetector(SignatureDetector):
    """
    Stub signature detector for testing and development.

    Always returns BENIGN. This is NOT a real detection engine —
    it is a placeholder that will be replaced with Snort/Suricata
    integration in the future.

    DO NOT use this for production intrusion detection.
    """

    def detect(self, flow: Dict[str, Any]) -> SignatureResult:
        """Stub: always returns no intrusion."""
        return SignatureResult(
            is_intrusion=False,
            matched_rules=[],
            severity="NONE",
            engine="stub",
            details="Stub detector — no signature analysis performed. "
                    "Replace with Snort/Suricata for real detection.",
        )


# ============================================================
# Hybrid Detection (Fusion)
# ============================================================

@dataclass
class HybridResult:
    """Combined result from both detectors."""
    final_verdict: str              # "INTRUSION" or "BENIGN"
    is_intrusion: bool
    triggered_by: str               # "ML", "SIGNATURE", "BOTH", "NONE"
    ml_result: DetectionResult
    signature_result: Optional[SignatureResult]
    timestamp: str = ""
    flow_metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.utcnow().isoformat() + "Z"

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "final_verdict": self.final_verdict,
            "is_intrusion": self.is_intrusion,
            "triggered_by": self.triggered_by,
            "timestamp": self.timestamp,
            "ml_result": self.ml_result.to_dict(),
            "flow_metadata": self.flow_metadata,
        }
        if self.signature_result:
            d["signature_result"] = self.signature_result.to_dict()
        return d

    def __str__(self) -> str:
        icon = "[!]" if self.is_intrusion else "[OK]"
        lines = [
            f"\n{'=' * 55}",
            f"  {icon} ZYDER HYBRID DETECTION: {self.final_verdict}",
            f"{'=' * 55}",
            f"  Triggered by:       {self.triggered_by}",
            f"  Timestamp:          {self.timestamp}",
            f"",
            f"  ML Detection:",
            f"    Prediction:       {self.ml_result.prediction}",
            f"    Attack Prob:      {self.ml_result.attack_probability:.4f}",
            f"    Threshold:        {self.ml_result.threshold:.2f}",
        ]

        if self.signature_result:
            lines.extend([
                f"",
                f"  Signature Detection ({self.signature_result.engine}):",
                f"    Intrusion:        {self.signature_result.is_intrusion}",
                f"    Rules matched:    {len(self.signature_result.matched_rules)}",
                f"    Severity:         {self.signature_result.severity}",
            ])
            if self.signature_result.matched_rules:
                for rule in self.signature_result.matched_rules[:5]:
                    lines.append(f"      - {rule}")

        lines.append("=" * 55)
        return "\n".join(lines)


class HybridDetector:
    """
    Implements ZYDER hybrid detection:  D(X) = Ds(X) OR Dm(X)

    Combines ML-based (XGBoost) and signature-based detection.
    If either detector identifies an intrusion, the final result
    is INTRUSION.
    """

    def __init__(
        self,
        ml_detector: ZyderMLDetector,
        signature_detector: Optional[SignatureDetector] = None,
    ) -> None:
        """
        Args:
            ml_detector: Loaded ZyderMLDetector instance.
            signature_detector: Optional signature detector.
                If None, only ML detection is used.
        """
        self.ml_detector = ml_detector
        self.signature_detector = signature_detector

        if signature_detector is None:
            logger.info("HybridDetector initialized — ML only (no signature engine)")
        else:
            logger.info(
                f"HybridDetector initialized — ML + "
                f"{type(signature_detector).__name__}"
            )

    def detect(self, flow: Dict[str, Any]) -> HybridResult:
        """
        Run hybrid detection on a single network flow.

        Implements:  D(X) = Ds(X) OR Dm(X)

        Args:
            flow: Network flow data dict.

        Returns:
            HybridResult with combined verdict.
        """
        # ---- ML Detection: Dm(X) ----
        ml_result = self.ml_detector.predict(flow)

        # ---- Signature Detection: Ds(X) ----
        sig_result = None
        if self.signature_detector is not None:
            sig_result = self.signature_detector.detect(flow)

        # ---- Decision Fusion: D(X) = Ds(X) OR Dm(X) ----
        ml_intrusion = ml_result.is_intrusion
        sig_intrusion = sig_result.is_intrusion if sig_result else False

        is_intrusion = ml_intrusion or sig_intrusion

        # Determine trigger source
        if ml_intrusion and sig_intrusion:
            triggered_by = "BOTH"
        elif ml_intrusion:
            triggered_by = "ML"
        elif sig_intrusion:
            triggered_by = "SIGNATURE"
        else:
            triggered_by = "NONE"

        final_verdict = "INTRUSION" if is_intrusion else "BENIGN"

        # Extract flow metadata for incident reporting
        metadata_keys = [
            "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
            "source_ip", "destination_ip", "source_port", "destination_port",
        ]
        flow_metadata = {k: flow.get(k) for k in metadata_keys if k in flow}

        result = HybridResult(
            final_verdict=final_verdict,
            is_intrusion=is_intrusion,
            triggered_by=triggered_by,
            ml_result=ml_result,
            signature_result=sig_result,
            flow_metadata=flow_metadata,
        )

        if is_intrusion:
            logger.warning(f"HYBRID DETECTION: {final_verdict} (by {triggered_by})")
        else:
            logger.debug(f"HYBRID DETECTION: {final_verdict}")

        return result
