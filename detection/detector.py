"""
ZYDER ML Detector
==================
XGBoost-based intrusion detection for single network flows.
Loads saved model + preprocessing config and provides a clean
prediction interface.

Usage:
    detector = ZyderMLDetector(model_dir="models", dataset="unsw")
    detector.load()
    result = detector.predict(flow)
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd
import joblib
from xgboost import XGBClassifier

from preprocessing.feature_schema import LABEL_MAPPING

logger = logging.getLogger("zyder.detection")


@dataclass
class DetectionResult:
    """Structured result from the ML detector."""
    prediction: str                 # "ATTACK" or "BENIGN"
    attack_probability: float       # 0.0 to 1.0
    threshold: float                # Classification threshold used
    is_intrusion: bool              # True if prediction == "ATTACK"
    top_features: List[Dict[str, Any]] = field(default_factory=list)
    # top_features populated by SHAP when enabled

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def __str__(self) -> str:
        status = "[!] INTRUSION DETECTED" if self.is_intrusion else "[OK] BENIGN"
        lines = [
            f"\n{'=' * 50}",
            f"  {status}",
            f"{'=' * 50}",
            f"  Prediction:        {self.prediction}",
            f"  Attack Probability: {self.attack_probability:.4f} ({self.attack_probability:.1%})",
            f"  Threshold:         {self.threshold:.2f}",
        ]
        if self.top_features:
            lines.append(f"\n  Top Contributing Features:")
            for i, feat in enumerate(self.top_features[:5], 1):
                direction = "-> ATTACK" if feat.get("direction") == "attack" else "-> BENIGN"
                lines.append(
                    f"    {i}. {feat['name']:.<30s} "
                    f"{feat.get('shap_value', 0):+.4f} {direction}"
                )
        lines.append("=" * 50)
        return "\n".join(lines)


class ZyderMLDetector:
    """
    XGBoost ML detector for single-flow intrusion detection.

    Loads a trained model and preprocessing configuration,
    then provides predict() for individual flows.
    """

    def __init__(
        self,
        model_dir: str = "models",
        dataset: str = "unsw",
        threshold: Optional[float] = None,
        base_dir: Optional[Path] = None,
    ) -> None:
        """
        Args:
            model_dir: Directory containing saved model files.
            dataset: Which dataset's model to load ("unsw" or "cicids").
            threshold: Classification threshold (configurable).
            base_dir: Project root. Defaults to parent of this file's directory.
        """
        self.base_dir = base_dir or Path(__file__).resolve().parent.parent
        self.model_dir = self.base_dir / model_dir
        self.dataset = dataset

        if threshold is None:
            self.threshold = 0.50
        else:
            self.threshold = threshold

        self.model: Optional[XGBClassifier] = None
        self.feature_names: List[str] = []
        self.label_encoders: Dict = {}
        self.imputation_values: Dict[str, float] = {}
        self._loaded = False

    def load(self) -> None:
        """Load the saved model and preprocessing configuration."""
        # Load XGBoost model
        model_path = self.model_dir / f"zyder_xgboost_{self.dataset}.json"
        if not model_path.exists():
            raise FileNotFoundError(
                f"Model file not found: {model_path}. "
                "Train the model first with: python main.py train --dataset "
                f"{self.dataset}"
            )

        self.model = XGBClassifier()
        self.model.load_model(str(model_path))
        logger.info(f"Loaded XGBoost model from {model_path}")

        # Load preprocessing config
        pkl_path = self.model_dir / f"preprocessing_{self.dataset}.pkl"
        if pkl_path.exists():
            saved = joblib.load(pkl_path)
            self.label_encoders = saved.get("label_encoders", {})
            self.imputation_values = saved.get("imputation_values", {})
            self.feature_names = saved.get("feature_names", [])
            logger.info(f"Loaded preprocessing config ({len(self.feature_names)} features)")
        else:
            # Fallback: load from feature_schema.json
            schema_path = self.model_dir / "feature_schema.json"
            if schema_path.exists():
                with open(schema_path) as f:
                    schema = json.load(f)
                self.feature_names = schema.get("feature_names", [])
                logger.info(f"Loaded feature schema ({len(self.feature_names)} features)")
            else:
                raise FileNotFoundError(
                    f"No preprocessing config found in {self.model_dir}. "
                    "Retrain the model."
                )

        self._loaded = True
        logger.info(f"ZYDER ML Detector ready (dataset={self.dataset}, "
                     f"threshold={self.threshold})")

    def predict(self, flow: Dict[str, Any]) -> DetectionResult:
        """
        Predict whether a single network flow is malicious.

        Args:
            flow: Dictionary mapping feature names to values.
                  Example: {"flow_duration": 0.5, "dst_port": 80, ...}

        Returns:
            DetectionResult with prediction, probability, and threshold.
        """
        if not self._loaded:
            raise RuntimeError("Detector not loaded. Call .load() first.")

        # Build feature vector matching training order
        features = self._prepare_features(flow)

        # Predict
        prob = self.model.predict_proba(features)[:, 1][0]
        is_attack = bool(prob >= self.threshold)
        prediction = "ATTACK" if is_attack else "BENIGN"

        result = DetectionResult(
            prediction=prediction,
            attack_probability=float(round(prob, 6)),
            threshold=self.threshold,
            is_intrusion=is_attack,
        )

        if is_attack:
            logger.warning(f"INTRUSION DETECTED — P(attack)={prob:.4f}")
        else:
            logger.debug(f"BENIGN — P(attack)={prob:.4f}")

        return result

    def predict_batch(
        self, flows: List[Dict[str, Any]]
    ) -> List[DetectionResult]:
        """Predict on multiple flows."""
        if not self._loaded:
            raise RuntimeError("Detector not loaded. Call .load() first.")

        # Build feature matrix
        rows = []
        for flow in flows:
            row = self._build_feature_row(flow)
            rows.append(row)

        df = pd.DataFrame(rows, columns=self.feature_names)
        df = df.apply(pd.to_numeric, errors="coerce").fillna(0)

        probs = self.model.predict_proba(df)[:, 1]

        results = []
        for prob in probs:
            is_attack = prob >= self.threshold
            results.append(DetectionResult(
                prediction="ATTACK" if is_attack else "BENIGN",
                attack_probability=float(round(prob, 6)),
                threshold=self.threshold,
                is_intrusion=is_attack,
            ))

        return results

    def _prepare_features(self, flow: Dict[str, Any]) -> pd.DataFrame:
        """Convert a flow dict into a single-row DataFrame matching training schema."""
        row = self._build_feature_row(flow)
        df = pd.DataFrame([row], columns=self.feature_names)
        df = df.apply(pd.to_numeric, errors="coerce").fillna(0)
        return df

    def _build_feature_row(self, flow: Dict[str, Any]) -> Dict[str, Any]:
        """Build a feature row dict from a flow, applying label encoding."""
        row = {}
        for feat in self.feature_names:
            val = flow.get(feat, 0)

            # Apply label encoding for categorical features
            if feat in self.label_encoders:
                le = self.label_encoders[feat]
                val_str = str(val)
                if val_str in le.classes_:
                    val = int(le.transform([val_str])[0])
                else:
                    val = 0  # Unknown category

            row[feat] = val
        return row

    def get_model(self) -> XGBClassifier:
        """Return the loaded XGBoost model (for SHAP etc.)."""
        if not self._loaded:
            raise RuntimeError("Detector not loaded. Call .load() first.")
        return self.model

    def get_feature_names(self) -> List[str]:
        """Return the feature names used by this model."""
        return self.feature_names.copy()
