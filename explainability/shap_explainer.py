"""
ZYDER SHAP Explainability Module
==================================
Integrates SHAP (SHapley Additive exPlanations) with the trained
XGBoost model to provide interpretable intrusion detection.

Uses TreeExplainer (optimized for tree-based models like XGBoost)
for both global and per-flow explanations.

Features:
- Global feature importance (mean absolute SHAP values)
- Single-flow explanation with top contributing features
- Waterfall plots for individual predictions
- Summary plots for dataset-wide analysis
- Direction indicators (BENIGN vs ATTACK contribution)

Note: SHAP computation adds overhead. For maximum inference
throughput, disable SHAP via config.detection.shap_enabled = false.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

logger = logging.getLogger("zyder.explainability")


@dataclass
class FlowExplanation:
    """SHAP explanation for a single network flow."""
    prediction: str                     # "ATTACK" or "BENIGN"
    attack_probability: float
    base_value: float                   # Expected model output
    shap_values: Optional[np.ndarray] = None  # Full SHAP vector
    top_features: List[Dict[str, Any]] = field(default_factory=list)

    def __str__(self) -> str:
        status = "[!] INTRUSION DETECTED" if self.prediction == "ATTACK" else "[OK] BENIGN"
        lines = [
            f"\n{'=' * 55}",
            f"  {status}",
            f"{'=' * 55}",
            f"  Probability:  {self.attack_probability:.4f} ({self.attack_probability:.1%})",
            f"  Base value:   {self.base_value:.4f}",
            f"",
            f"  Top Contributing Features:",
        ]

        for i, feat in enumerate(self.top_features[:10], 1):
            direction_icon = "↑ ATTACK" if feat["direction"] == "attack" else "↓ BENIGN"
            lines.append(
                f"    {i:>2d}. {feat['name']:.<32s} "
                f"SHAP: {feat['shap_value']:+.4f}  "
                f"Val: {feat['value']:.4g}  "
                f"{direction_icon}"
            )

        lines.append("=" * 55)
        return "\n".join(lines)


class ZyderSHAPExplainer:
    """
    SHAP integration for ZYDER XGBoost model.

    Uses TreeExplainer for efficient explanation of tree-based models.
    """

    def __init__(
        self,
        model: Any,
        feature_names: List[str],
    ) -> None:
        """
        Args:
            model: Trained XGBClassifier.
            feature_names: List of feature names matching model input order.
        """
        self.model = model
        self.feature_names = feature_names
        self._explainer = None

    def _get_explainer(self) -> Any:
        """Lazy-load SHAP TreeExplainer (imported on demand to avoid startup cost)."""
        if self._explainer is None:
            import shap
            logger.info("Initializing SHAP TreeExplainer...")
            self._explainer = shap.TreeExplainer(self.model)
            logger.info("SHAP TreeExplainer ready")
        return self._explainer

    def explain_single(
        self,
        flow_features: np.ndarray | pd.DataFrame,
        threshold: float = 0.5,
    ) -> FlowExplanation:
        """
        Explain a single flow prediction with SHAP values.

        Args:
            flow_features: 1-row array/DataFrame of features.
            threshold: Classification threshold.

        Returns:
            FlowExplanation with ranked contributing features.
        """
        explainer = self._get_explainer()

        # Ensure 2D
        if isinstance(flow_features, pd.DataFrame):
            X = flow_features.values
        else:
            X = np.atleast_2d(flow_features)

        # Get SHAP values
        shap_values = explainer.shap_values(X)

        # For binary classification, shap_values may be a list of 2 arrays
        # or a single array. Handle both cases.
        if isinstance(shap_values, list):
            # shap_values[1] = contributions toward class 1 (ATTACK)
            sv = shap_values[1][0]
        else:
            sv = shap_values[0]

        # Get prediction
        prob = self.model.predict_proba(X)[:, 1][0]
        prediction = "ATTACK" if prob >= threshold else "BENIGN"
        base_value = float(explainer.expected_value[1] if isinstance(
            explainer.expected_value, (list, np.ndarray)
        ) else explainer.expected_value)

        # Rank features by absolute SHAP contribution
        abs_shap = np.abs(sv)
        sorted_indices = np.argsort(abs_shap)[::-1]

        top_features = []
        for idx in sorted_indices[:15]:  # Top 15
            shap_val = float(sv[idx])
            feature_val = float(X[0, idx])
            top_features.append({
                "name": self.feature_names[idx],
                "shap_value": round(shap_val, 6),
                "value": round(feature_val, 6),
                "direction": "attack" if shap_val > 0 else "benign",
                "abs_contribution": round(abs_shap[idx], 6),
            })

        return FlowExplanation(
            prediction=prediction,
            attack_probability=float(round(prob, 6)),
            base_value=base_value,
            shap_values=sv,
            top_features=top_features,
        )

    def global_importance(
        self, X: np.ndarray | pd.DataFrame, max_samples: int = 1000
    ) -> Dict[str, float]:
        """
        Compute global feature importance using mean absolute SHAP values.

        Args:
            X: Feature matrix (a sample is used if X is large).
            max_samples: Max rows to use for computation.

        Returns:
            Dict of {feature_name: mean_abs_shap_value}, sorted descending.
        """
        explainer = self._get_explainer()

        if isinstance(X, pd.DataFrame):
            X = X.values

        # Sample if large
        if len(X) > max_samples:
            indices = np.random.RandomState(42).choice(
                len(X), max_samples, replace=False
            )
            X_sample = X[indices]
        else:
            X_sample = X

        logger.info(f"Computing global SHAP importance ({len(X_sample)} samples)...")
        shap_values = explainer.shap_values(X_sample)

        if isinstance(shap_values, list):
            sv = shap_values[1]
        else:
            sv = shap_values

        mean_abs = np.mean(np.abs(sv), axis=0)

        importance = {}
        for i, name in enumerate(self.feature_names):
            importance[name] = float(round(mean_abs[i], 6))

        # Sort by importance
        importance = dict(sorted(
            importance.items(), key=lambda x: x[1], reverse=True
        ))

        logger.info("Global SHAP Feature Importance:")
        for i, (name, val) in enumerate(list(importance.items())[:10], 1):
            logger.info(f"  {i:>2d}. {name:.<35s} {val:.6f}")

        return importance

    def plot_waterfall(
        self,
        flow_features: np.ndarray | pd.DataFrame,
        save_path: Optional[str | Path] = None,
    ) -> None:
        """
        Generate SHAP waterfall plot for a single flow.

        Args:
            flow_features: 1-row feature array/DataFrame.
            save_path: Path to save the plot. If None, shows interactively.
        """
        import shap

        explainer = self._get_explainer()

        if isinstance(flow_features, pd.DataFrame):
            X = flow_features.values
        else:
            X = np.atleast_2d(flow_features)

        shap_explanation = explainer(X)

        # For binary: select class 1 (ATTACK)
        if len(shap_explanation.shape) == 3:
            explanation = shap_explanation[:, :, 1]
        else:
            explanation = shap_explanation

        explanation.feature_names = self.feature_names

        fig = plt.figure(figsize=(12, 8))
        shap.plots.waterfall(explanation[0], show=False, max_display=15)
        plt.title("ZYDER — SHAP Waterfall Plot", fontsize=14, fontweight="bold")
        plt.tight_layout()

        if save_path:
            plt.savefig(str(save_path), dpi=150, bbox_inches="tight")
            logger.info(f"Saved waterfall plot -> {save_path}")
        plt.close(fig)

    def plot_summary(
        self,
        X: np.ndarray | pd.DataFrame,
        save_path: Optional[str | Path] = None,
        max_samples: int = 500,
    ) -> None:
        """
        Generate SHAP summary (beeswarm) plot.

        Args:
            X: Feature matrix.
            save_path: Path to save the plot.
            max_samples: Max samples for computation.
        """
        import shap

        explainer = self._get_explainer()

        if isinstance(X, pd.DataFrame):
            X_np = X.values
            feature_names = list(X.columns)
        else:
            X_np = X
            feature_names = self.feature_names

        if len(X_np) > max_samples:
            indices = np.random.RandomState(42).choice(
                len(X_np), max_samples, replace=False
            )
            X_sample = X_np[indices]
        else:
            X_sample = X_np

        logger.info(f"Computing SHAP summary plot ({len(X_sample)} samples)...")
        shap_values = explainer.shap_values(X_sample)

        if isinstance(shap_values, list):
            sv = shap_values[1]
        else:
            sv = shap_values

        fig = plt.figure(figsize=(12, 10))
        shap.summary_plot(
            sv, X_sample,
            feature_names=feature_names,
            show=False,
            max_display=20,
        )
        plt.title("ZYDER — SHAP Summary Plot", fontsize=14, fontweight="bold")
        plt.tight_layout()

        if save_path:
            plt.savefig(str(save_path), dpi=150, bbox_inches="tight")
            logger.info(f"Saved summary plot -> {save_path}")
        plt.close(fig)

    def plot_global_importance(
        self,
        X: np.ndarray | pd.DataFrame,
        save_path: Optional[str | Path] = None,
        max_samples: int = 500,
    ) -> None:
        """
        Generate SHAP bar plot of global feature importance
        (mean |SHAP value|).
        """
        import shap

        explainer = self._get_explainer()

        if isinstance(X, pd.DataFrame):
            X_np = X.values
        else:
            X_np = X

        if len(X_np) > max_samples:
            indices = np.random.RandomState(42).choice(
                len(X_np), max_samples, replace=False
            )
            X_sample = X_np[indices]
        else:
            X_sample = X_np

        logger.info(f"Computing SHAP global importance ({len(X_sample)} samples)...")
        shap_values = explainer.shap_values(X_sample)

        if isinstance(shap_values, list):
            sv = shap_values[1]
        else:
            sv = shap_values

        mean_abs = np.mean(np.abs(sv), axis=0)
        n_features = min(20, len(self.feature_names))
        top_indices = np.argsort(mean_abs)[-n_features:]
        top_names = [self.feature_names[i] for i in top_indices]
        top_vals = mean_abs[top_indices]

        fig, ax = plt.subplots(figsize=(10, max(6, n_features * 0.4)))
        colors = plt.cm.magma(np.linspace(0.2, 0.8, n_features))
        ax.barh(range(n_features), top_vals, color=colors, edgecolor="white")
        ax.set_yticks(range(n_features))
        ax.set_yticklabels(top_names, fontsize=10)
        ax.set_xlabel("Mean |SHAP Value|", fontsize=12)
        ax.set_title(
            "ZYDER — Global Feature Importance (SHAP)",
            fontsize=14, fontweight="bold",
        )
        ax.grid(True, alpha=0.3, axis="x")
        plt.tight_layout()

        if save_path:
            plt.savefig(str(save_path), dpi=150, bbox_inches="tight")
            logger.info(f"Saved global importance plot -> {save_path}")
        plt.close(fig)
