"""
ZYDER Unified Training Module
================================
Trains the XGBoost classifier for binary intrusion detection.

Supports both UNSW-NB15 and CICIDS2017 datasets with:
- Stratified train/val/test splitting
- Optional time-aware splitting (CICIDS2017)
- Near-duplicate detection before splitting
- Class imbalance handling via scale_pos_weight
- Early stopping on validation set
- Full evaluation pipeline
- Model and config persistence
"""

from __future__ import annotations

import hashlib
import json
import logging
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import numpy as np
import pandas as pd
import yaml
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

from preprocessing.unsw_preprocessor import UNSWPreprocessor
from preprocessing.cicids_preprocessor import CICIDSPreprocessor
from preprocessing.base_preprocessor import BasePreprocessor
from training.evaluate import ZyderEvaluator

logger = logging.getLogger("zyder.training")


def setup_logging(config: Dict[str, Any], base_dir: Path) -> None:
    """Configure logging from config."""
    log_cfg = config.get("logging", {})
    log_level = getattr(logging, log_cfg.get("level", "INFO"))
    log_file = base_dir / log_cfg.get("log_file", "outputs/zyder.log")
    log_file.parent.mkdir(parents=True, exist_ok=True)

    import io
    # Use UTF-8 wrapper on stdout to prevent Windows cp1252 encoding errors
    utf8_stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
        handlers=[
            logging.StreamHandler(utf8_stdout),
            logging.FileHandler(str(log_file), mode="w", encoding="utf-8"),
        ],
    )


def load_config(config_path: Path) -> Dict[str, Any]:
    """Load YAML configuration file."""
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")
    with open(config_path, "r") as f:
        return yaml.safe_load(f)


def get_preprocessor(
    dataset: str, config: Dict[str, Any], base_dir: Path
) -> BasePreprocessor:
    """Factory: return the appropriate preprocessor for the dataset."""
    if dataset == "unsw":
        return UNSWPreprocessor(config, base_dir)
    elif dataset == "cicids":
        return CICIDSPreprocessor(config, base_dir)
    else:
        raise ValueError(f"Unknown dataset: {dataset}. Use 'unsw' or 'cicids'.")


def remove_near_duplicates(
    X: pd.DataFrame, y: pd.Series, sample_frac: float = 1.0
) -> Tuple[pd.DataFrame, pd.Series]:
    """
    Remove near-duplicate rows by rounding feature values.
    This prevents data leakage when the same flow appears
    multiple times with minor float variations.
    """
    logger.info("Checking for near-duplicate flows...")

    n_before = len(X)

    # Round numeric columns to reduce float noise
    X_rounded = X.round(4)

    # Pandas duplicated is much faster than hashing rows
    mask = ~X_rounded.duplicated(keep="first")
    
    X = X[mask].reset_index(drop=True)
    y = y[mask].reset_index(drop=True)
    n_removed = n_before - len(X)

    if n_removed > 0:
        logger.info(f"  Removed {n_removed} near-duplicate flows")
    else:
        logger.info("  No near-duplicates found")

    return X, y


def split_data(
    X: pd.DataFrame,
    y: pd.Series,
    config: Dict[str, Any],
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.Series, pd.Series, pd.Series]:
    """
    Split data into train/val/test sets.

    Uses stratified splitting to maintain class distribution.
    """
    split_cfg = config.get("splitting", {})
    train_ratio = split_cfg.get("train_ratio", 0.70)
    val_ratio = split_cfg.get("val_ratio", 0.15)
    test_ratio = split_cfg.get("test_ratio", 0.15)
    random_state = split_cfg.get("random_state", 42)
    use_stratify = split_cfg.get("stratify", True)

    # Validate ratios
    total = train_ratio + val_ratio + test_ratio
    if abs(total - 1.0) > 0.01:
        logger.warning(f"Split ratios sum to {total:.2f}, not 1.0. Normalizing.")
        train_ratio /= total
        val_ratio /= total
        test_ratio /= total

    stratify_arg = y if use_stratify else None

    # First split: train vs (val+test)
    val_test_ratio = val_ratio + test_ratio
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y,
        test_size=val_test_ratio,
        random_state=random_state,
        stratify=stratify_arg,
    )

    # Second split: val vs test
    test_fraction = test_ratio / val_test_ratio
    stratify_temp = y_temp if use_stratify else None
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp,
        test_size=test_fraction,
        random_state=random_state,
        stratify=stratify_temp,
    )

    logger.info(f"\nData Split Summary:")
    logger.info(f"  Training:   {len(X_train):>8d} samples ({train_ratio:.0%})")
    logger.info(f"  Validation: {len(X_val):>8d} samples ({val_ratio:.0%})")
    logger.info(f"  Test:       {len(X_test):>8d} samples ({test_ratio:.0%})")
    logger.info(f"  Stratified: {use_stratify}")

    # Log class distribution per split
    for name, ys in [("Train", y_train), ("Val", y_val), ("Test", y_test)]:
        benign = (ys == 0).sum()
        attack = (ys == 1).sum()
        logger.info(f"  {name:>5s} — BENIGN: {benign:>7d}, ATTACK: {attack:>7d} "
                     f"(ratio: {attack / max(benign, 1):.3f})")

    return X_train, X_val, X_test, y_train, y_val, y_test


def build_xgboost(config: Dict[str, Any], y_train: pd.Series) -> XGBClassifier:
    """
    Build XGBClassifier with configured hyperparameters.
    Computes scale_pos_weight from training class distribution if not specified.
    """
    xgb_cfg = config.get("xgboost", {})

    # Auto-compute scale_pos_weight if null
    scale_pos_weight = xgb_cfg.get("scale_pos_weight")
    if scale_pos_weight is None:
        n_benign = (y_train == 0).sum()
        n_attack = (y_train == 1).sum()
        if n_attack > 0:
            scale_pos_weight = n_benign / n_attack
        else:
            scale_pos_weight = 1.0
        logger.info(f"Auto-computed scale_pos_weight: {scale_pos_weight:.4f}")

    model = XGBClassifier(
        n_estimators=xgb_cfg.get("n_estimators", 500),
        max_depth=xgb_cfg.get("max_depth", 8),
        learning_rate=xgb_cfg.get("learning_rate", 0.05),
        subsample=xgb_cfg.get("subsample", 0.8),
        colsample_bytree=xgb_cfg.get("colsample_bytree", 0.8),
        min_child_weight=xgb_cfg.get("min_child_weight", 5),
        gamma=xgb_cfg.get("gamma", 0.1),
        reg_alpha=xgb_cfg.get("reg_alpha", 0.1),
        reg_lambda=xgb_cfg.get("reg_lambda", 1.0),
        scale_pos_weight=scale_pos_weight,
        tree_method=xgb_cfg.get("tree_method", "hist"),
        n_jobs=xgb_cfg.get("n_jobs", -1),
        random_state=xgb_cfg.get("random_state", 42),
        verbosity=xgb_cfg.get("verbosity", 1),
        eval_metric=xgb_cfg.get("eval_metric", "logloss"),
        use_label_encoder=False,
        objective="binary:logistic",
    )

    logger.info("\nXGBoost Configuration:")
    for param, val in model.get_params().items():
        if param not in ("callbacks", "kwargs"):
            logger.info(f"  {param}: {val}")

    return model


def train(
    dataset: str,
    config_path: str = "config/config.yaml",
    mode: str = "native",
) -> Dict[str, Any]:
    """
    Full training pipeline.

    Args:
        dataset: "unsw" or "cicids"
        config_path: Path to config YAML
        mode: "native" (dataset features) or "zyder" (common schema)

    Returns:
        Dictionary with training results and metrics.
    """
    base_dir = Path(__file__).resolve().parent.parent
    config = load_config(base_dir / config_path)
    setup_logging(config, base_dir)

    logger.info("=" * 60)
    logger.info("  ZYDER — XGBoost Intrusion Detection Training")
    logger.info(f"  Dataset:  {dataset}")
    logger.info(f"  Mode:     {mode}")
    logger.info(f"  Config:   {config_path}")
    logger.info("=" * 60)

    # ---- 1. Load dataset and create labels ----
    preprocessor = get_preprocessor(dataset, config, base_dir)

    df = preprocessor.load_data()
    df = preprocessor.create_labels(df)

    y = df["label"].copy()
    X_raw = df.drop(columns=["label"])

    # ---- 2. Basic cleaning ----
    X_raw = preprocessor.basic_clean(X_raw)

    # Keep labels aligned
    y = y.loc[X_raw.index].reset_index(drop=True)
    X_raw = X_raw.reset_index(drop=True)

    # ---- 3. Remove near-duplicates ----
    X_raw, y = remove_near_duplicates(X_raw, y)

    # ---- 4. Split BEFORE fitting preprocessing ----
    X_train_raw, X_val_raw, X_test_raw, y_train, y_val, y_test = split_data(
        X_raw, y, config
    )

    # ---- 5. Fit preprocessing using TRAIN only ----
    X_train = preprocessor.fit_transform_train(X_train_raw)

    # ---- 6. Transform validation/test using TRAIN parameters ----
    X_val = preprocessor.transform_split(X_val_raw)
    X_test = preprocessor.transform_split(X_test_raw)

    # ---- 7. Map to ZYDER schema if requested ----
    if mode == "zyder":
        X_train = preprocessor.map_to_zyder_features(X_train)
        X_val = preprocessor.map_to_zyder_features(X_val)
        X_test = preprocessor.map_to_zyder_features(X_test)

    # Ensure all splits have identical feature columns/order
    preprocessor.feature_names = list(X_train.columns)

    X_val = X_val.reindex(
        columns=preprocessor.feature_names,
        fill_value=0
    )

    X_test = X_test.reindex(
        columns=preprocessor.feature_names,
        fill_value=0
    )

    # ---- 4. Build model ----
    model = build_xgboost(config, y_train)

    # ---- 5. Train ----
    logger.info("\nTraining XGBoost model...")
    t_start = time.time()

    xgb_cfg = config.get("xgboost", {})
    early_stopping = xgb_cfg.get("early_stopping_rounds", 50)

    model.fit(
        X_train, y_train,
        eval_set=[(X_val, y_val)],
        verbose=50,
    )

    train_time = time.time() - t_start
    logger.info(f"Training completed in {train_time:.1f}s")
    logger.info(f"Best iteration: {model.best_iteration if hasattr(model, 'best_iteration') else 'N/A'}")

    # ---- 6. Evaluate ----
    output_dir = base_dir / config["paths"]["outputs_dir"]
    evaluator = ZyderEvaluator(
        model=model,
        feature_names=preprocessor.feature_names,
        output_dir=output_dir,
        dataset_name=dataset,
    )

    threshold_cfg = config.get("detection", {}).get("threshold", 0.5)
    if isinstance(threshold_cfg, dict):
        threshold = threshold_cfg.get(dataset, threshold_cfg.get("default", 0.5))
    else:
        threshold = float(threshold_cfg)

    results = evaluator.evaluate(X_test, y_test, threshold=threshold)

    # ---- 7. Save model ----
    model_dir = base_dir / config["paths"]["models_dir"]
    model_dir.mkdir(parents=True, exist_ok=True)

    model_path = model_dir / f"zyder_xgboost_{dataset}.json"
    model.save_model(str(model_path))
    logger.info(f"\nSaved XGBoost model -> {model_path}")

    # Save preprocessing config
    preprocessor.save_config(model_dir)

    # Save training metadata
    meta = {
        "dataset": dataset,
        "mode": mode,
        "train_samples": int(len(X_train)),
        "val_samples": int(len(X_val)),
        "test_samples": int(len(X_test)),
        "n_features": int(len(preprocessor.feature_names)),
        "feature_names": preprocessor.feature_names,
        "training_time_seconds": round(train_time, 2),
        "threshold": threshold,
        "metrics": results["metrics"],
    }
    meta_path = model_dir / f"training_meta_{dataset}.json"
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2, default=str)
    logger.info(f"Saved training metadata -> {meta_path}")

    logger.info("\n" + "=" * 60)
    logger.info("  Training Complete!")
    logger.info("=" * 60)

    return results


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="ZYDER XGBoost Training")
    parser.add_argument(
        "--dataset", type=str, required=True,
        choices=["unsw", "cicids"],
        help="Dataset to train on: 'unsw' or 'cicids'",
    )
    parser.add_argument(
        "--config", type=str, default="config/config.yaml",
        help="Path to config file",
    )
    parser.add_argument(
        "--mode", type=str, default="native",
        choices=["native", "zyder"],
        help="Feature mode: 'native' (dataset-specific) or 'zyder' (common schema)",
    )

    args = parser.parse_args()
    train(dataset=args.dataset, config_path=args.config, mode=args.mode)
