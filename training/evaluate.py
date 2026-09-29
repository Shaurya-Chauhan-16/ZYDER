"""
ZYDER Evaluation Module
========================
Comprehensive model evaluation with metrics, visualizations,
and threshold analysis for the XGBoost IDS classifier.

Generates:
- Accuracy, Precision, Recall, F1, FPR, ROC-AUC
- Confusion Matrix
- Classification Report
- ROC Curve
- Precision-Recall Curve
- Feature Importance Chart
- Threshold Sweep Analysis
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import matplotlib
matplotlib.use("Agg")  # Non-interactive backend for saving plots
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.metrics import (
    accuracy_score,
    auc,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from xgboost import XGBClassifier

logger = logging.getLogger("zyder.evaluation")


class ZyderEvaluator:
    """Evaluates a trained XGBoost model on a test set."""

    def __init__(
        self,
        model: XGBClassifier,
        feature_names: List[str],
        output_dir: Path,
        dataset_name: str = "",
    ) -> None:
        self.model = model
        self.feature_names = feature_names
        self.output_dir = output_dir
        self.dataset_name = dataset_name
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def evaluate(
        self,
        X_test: np.ndarray | pd.DataFrame,
        y_test: np.ndarray | pd.Series,
        threshold: float = 0.5,
    ) -> Dict[str, Any]:
        """
        Run full evaluation and generate all metrics + visualizations.

        Args:
            X_test: Test feature matrix.
            y_test: True labels.
            threshold: Classification threshold (default 0.5).

        Returns:
            Dictionary with all computed metrics.
        """
        logger.info("=" * 60)
        logger.info("ZYDER Model Evaluation")
        logger.info("=" * 60)

        y_test = np.asarray(y_test)
        y_prob = self.model.predict_proba(X_test)[:, 1]
        y_pred = (y_prob >= threshold).astype(int)

        # ---- Core Metrics ----
        metrics = self._compute_metrics(y_test, y_pred, y_prob, threshold)
        self._log_metrics(metrics)

        # ---- Classification Report ----
        report = classification_report(
            y_test, y_pred,
            target_names=["BENIGN", "ATTACK"],
            output_dict=True,
        )
        report_str = classification_report(
            y_test, y_pred,
            target_names=["BENIGN", "ATTACK"],
        )
        logger.info(f"\nClassification Report:\n{report_str}")

        # ---- Visualizations ----
        self._plot_confusion_matrix(y_test, y_pred)
        self._plot_roc_curve(y_test, y_prob)
        self._plot_precision_recall_curve(y_test, y_prob)
        self._plot_feature_importance()

        # ---- Threshold Analysis ----
        threshold_analysis = self._threshold_sweep(y_test, y_prob)

        # ---- Save Results ----
        results = {
            "dataset": self.dataset_name,
            "threshold": threshold,
            "metrics": metrics,
            "classification_report": report,
            "threshold_analysis": threshold_analysis,
        }

        results_path = self.output_dir / f"evaluation_results_{self.dataset_name}.json"
        with open(results_path, "w") as f:
            json.dump(results, f, indent=2, default=str)
        logger.info(f"Saved evaluation results to {results_path}")

        return results

    def _compute_metrics(
        self,
        y_true: np.ndarray,
        y_pred: np.ndarray,
        y_prob: np.ndarray,
        threshold: float,
    ) -> Dict[str, float]:
        """Compute all evaluation metrics."""
        tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()

        metrics = {
            "accuracy": float(accuracy_score(y_true, y_pred)),
            "precision": float(precision_score(y_true, y_pred, zero_division=0)),
            "recall": float(recall_score(y_true, y_pred, zero_division=0)),
            "f1_score": float(f1_score(y_true, y_pred, zero_division=0)),
            "roc_auc": float(roc_auc_score(y_true, y_prob)),
            "false_positive_rate": float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0,
            "true_positive_rate": float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0,
            "true_negatives": int(tn),
            "false_positives": int(fp),
            "false_negatives": int(fn),
            "true_positives": int(tp),
            "threshold": threshold,
            "total_samples": int(len(y_true)),
        }
        return metrics

    def _log_metrics(self, metrics: Dict[str, float]) -> None:
        """Log metrics in a formatted table."""
        logger.info("\n" + "=" * 40)
        logger.info("       EVALUATION METRICS")
        logger.info("=" * 40)
        logger.info(f"  Accuracy:            {metrics['accuracy']:.4f}")
        logger.info(f"  Precision:           {metrics['precision']:.4f}")
        logger.info(f"  Recall:              {metrics['recall']:.4f}")
        logger.info(f"  F1 Score:            {metrics['f1_score']:.4f}")
        logger.info(f"  ROC-AUC:             {metrics['roc_auc']:.4f}")
        logger.info(f"  False Positive Rate: {metrics['false_positive_rate']:.4f}")
        logger.info(f"  Threshold:           {metrics['threshold']:.2f}")
        logger.info("=" * 40)
        logger.info(f"  TP: {metrics['true_positives']:>8d}  |  FP: {metrics['false_positives']:>8d}")
        logger.info(f"  FN: {metrics['false_negatives']:>8d}  |  TN: {metrics['true_negatives']:>8d}")
        logger.info("=" * 40)

    def _plot_confusion_matrix(self, y_true: np.ndarray, y_pred: np.ndarray) -> None:
        """Generate and save confusion matrix heatmap."""
        cm = confusion_matrix(y_true, y_pred)
        fig, ax = plt.subplots(figsize=(8, 6))

        sns.heatmap(
            cm, annot=True, fmt="d", cmap="Blues",
            xticklabels=["BENIGN", "ATTACK"],
            yticklabels=["BENIGN", "ATTACK"],
            ax=ax, linewidths=0.5,
            annot_kws={"size": 14},
        )
        ax.set_xlabel("Predicted", fontsize=12)
        ax.set_ylabel("Actual", fontsize=12)
        ax.set_title(
            f"ZYDER Confusion Matrix — {self.dataset_name.upper()}",
            fontsize=14, fontweight="bold",
        )

        path = self.output_dir / f"confusion_matrix_{self.dataset_name}.png"
        fig.tight_layout()
        fig.savefig(path, dpi=150)
        plt.close(fig)
        logger.info(f"  Saved confusion matrix -> {path}")

    def _plot_roc_curve(self, y_true: np.ndarray, y_prob: np.ndarray) -> None:
        """Generate and save ROC curve."""
        fpr, tpr, _ = roc_curve(y_true, y_prob)
        roc_auc = auc(fpr, tpr)

        fig, ax = plt.subplots(figsize=(8, 6))
        ax.plot(fpr, tpr, color="#2563eb", lw=2.5,
                label=f"ROC Curve (AUC = {roc_auc:.4f})")
        ax.plot([0, 1], [0, 1], color="#94a3b8", lw=1.5, linestyle="--",
                label="Random Classifier")
        ax.fill_between(fpr, tpr, alpha=0.15, color="#2563eb")
        ax.set_xlim([0.0, 1.0])
        ax.set_ylim([0.0, 1.05])
        ax.set_xlabel("False Positive Rate", fontsize=12)
        ax.set_ylabel("True Positive Rate", fontsize=12)
        ax.set_title(
            f"ZYDER ROC Curve — {self.dataset_name.upper()}",
            fontsize=14, fontweight="bold",
        )
        ax.legend(loc="lower right", fontsize=11)
        ax.grid(True, alpha=0.3)

        path = self.output_dir / f"roc_curve_{self.dataset_name}.png"
        fig.tight_layout()
        fig.savefig(path, dpi=150)
        plt.close(fig)
        logger.info(f"  Saved ROC curve -> {path}")

    def _plot_precision_recall_curve(
        self, y_true: np.ndarray, y_prob: np.ndarray
    ) -> None:
        """Generate and save Precision-Recall curve."""
        precision, recall, _ = precision_recall_curve(y_true, y_prob)
        pr_auc = auc(recall, precision)

        fig, ax = plt.subplots(figsize=(8, 6))
        ax.plot(recall, precision, color="#059669", lw=2.5,
                label=f"PR Curve (AUC = {pr_auc:.4f})")
        ax.fill_between(recall, precision, alpha=0.15, color="#059669")
        ax.set_xlim([0.0, 1.0])
        ax.set_ylim([0.0, 1.05])
        ax.set_xlabel("Recall", fontsize=12)
        ax.set_ylabel("Precision", fontsize=12)
        ax.set_title(
            f"ZYDER Precision-Recall Curve — {self.dataset_name.upper()}",
            fontsize=14, fontweight="bold",
        )
        ax.legend(loc="lower left", fontsize=11)
        ax.grid(True, alpha=0.3)

        path = self.output_dir / f"pr_curve_{self.dataset_name}.png"
        fig.tight_layout()
        fig.savefig(path, dpi=150)
        plt.close(fig)
        logger.info(f"  Saved Precision-Recall curve -> {path}")

    def _plot_feature_importance(self) -> None:
        """Generate and save XGBoost feature importance chart."""
        importance = self.model.feature_importances_
        n_features = min(25, len(self.feature_names))

        # Sort by importance
        indices = np.argsort(importance)[-n_features:]
        top_names = [self.feature_names[i] for i in indices]
        top_values = importance[indices]

        fig, ax = plt.subplots(figsize=(10, max(6, n_features * 0.35)))
        colors = plt.cm.viridis(np.linspace(0.3, 0.9, n_features))

        ax.barh(range(n_features), top_values, color=colors, edgecolor="white", height=0.7)
        ax.set_yticks(range(n_features))
        ax.set_yticklabels(top_names, fontsize=10)
        ax.set_xlabel("Feature Importance (Gain)", fontsize=12)
        ax.set_title(
            f"ZYDER Top {n_features} Features — {self.dataset_name.upper()}",
            fontsize=14, fontweight="bold",
        )
        ax.grid(True, alpha=0.3, axis="x")

        path = self.output_dir / f"feature_importance_{self.dataset_name}.png"
        fig.tight_layout()
        fig.savefig(path, dpi=150)
        plt.close(fig)
        logger.info(f"  Saved feature importance chart -> {path}")

    def _threshold_sweep(
        self, y_true: np.ndarray, y_prob: np.ndarray
    ) -> Dict[str, Any]:
        """
        Sweep classification thresholds and find optimal values
        for different objectives.
        """
        thresholds = np.arange(0.1, 0.95, 0.05)
        results = []

        for t in thresholds:
            y_pred_t = (y_prob >= t).astype(int)
            tn, fp, fn, tp = confusion_matrix(y_true, y_pred_t).ravel()

            results.append({
                "threshold": round(float(t), 2),
                "accuracy": float(accuracy_score(y_true, y_pred_t)),
                "precision": float(precision_score(y_true, y_pred_t, zero_division=0)),
                "recall": float(recall_score(y_true, y_pred_t, zero_division=0)),
                "f1": float(f1_score(y_true, y_pred_t, zero_division=0)),
                "fpr": float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0,
            })

        # Find optimal thresholds
        best_f1 = max(results, key=lambda x: x["f1"])
        best_recall = max(results, key=lambda x: x["recall"])
        best_low_fpr = min(results, key=lambda x: x["fpr"])

        analysis = {
            "sweep_results": results,
            "best_f1_threshold": best_f1,
            "best_recall_threshold": best_recall,
            "lowest_fpr_threshold": best_low_fpr,
        }

        logger.info("\nThreshold Analysis:")
        logger.info(f"  Best F1:     threshold={best_f1['threshold']:.2f}, "
                     f"F1={best_f1['f1']:.4f}")
        logger.info(f"  Best Recall: threshold={best_recall['threshold']:.2f}, "
                     f"Recall={best_recall['recall']:.4f}")
        logger.info(f"  Lowest FPR:  threshold={best_low_fpr['threshold']:.2f}, "
                     f"FPR={best_low_fpr['fpr']:.4f}")

        return analysis
