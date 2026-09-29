"""
ZYDER Base Preprocessor
========================
Abstract base class defining the preprocessing contract.
All dataset-specific preprocessors must implement this interface.
"""

from __future__ import annotations

import logging
import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
import joblib
from sklearn.preprocessing import LabelEncoder

from preprocessing.feature_schema import (
    FeatureSchema,
    get_zyder_feature_names,
    LABEL_MAPPING,
)

logger = logging.getLogger("zyder.preprocessing")


class BasePreprocessor(ABC):
    """
    Abstract preprocessor that converts a raw dataset into the ZYDER
    common feature representation.

    Subclasses implement dataset-specific loading and mapping logic.
    The base class provides shared utilities for cleaning, saving, and
    loading preprocessing configurations.
    """

    def __init__(self, config: Dict[str, Any], base_dir: Path) -> None:
        """
        Args:
            config: Parsed YAML configuration dict.
            base_dir: Project root directory (for resolving relative paths).
        """
        self.config = config
        self.base_dir = base_dir
        self.label_encoders: Dict[str, LabelEncoder] = {}
        self.feature_names: List[str] = []
        self.imputation_values: Dict[str, float] = {}
        self.dataset_name: str = ""
        self._raw_df: Optional[pd.DataFrame] = None

    # ---- Abstract Methods (dataset-specific) ----

    @abstractmethod
    def load_data(self) -> pd.DataFrame:
        """Load raw CSV(s) and return a single DataFrame.
        Must inspect actual columns and log them."""
        ...

    @abstractmethod
    def create_labels(self, df: pd.DataFrame) -> pd.DataFrame:
        """Create binary 'label' column: 0=BENIGN, 1=ATTACK.
        Must NOT leak attack_cat into features."""
        ...

    @abstractmethod
    def get_columns_to_drop(self) -> List[str]:
        """Return columns to remove (IPs, IDs, timestamps, attack_cat, label)."""
        ...

    @abstractmethod
    def get_categorical_columns(self) -> List[str]:
        """Return columns that need label-encoding."""
        ...

    @abstractmethod
    def map_to_zyder_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Map dataset-native columns to the ZYDER common schema."""
        ...

    def basic_clean(self, df: pd.DataFrame) -> pd.DataFrame:
        df = df.copy()

        # Remove duplicate rows
        df = df.drop_duplicates()

        # Remove irrelevant columns
        cols_to_drop = self.get_columns_to_drop()
        existing_drops = [c for c in cols_to_drop if c in df.columns]
        df = df.drop(columns=existing_drops, errors="ignore")

        # Replace infinities with NaN.
        # Do NOT fill NaN here — imputation must be fitted on TRAIN only.
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        if len(numeric_cols) > 0:
            df[numeric_cols] = df[numeric_cols].replace(
                [np.inf, -np.inf], np.nan
            )

        return df

    def fit_transform_train(self, df: pd.DataFrame) -> pd.DataFrame:
        """Fit preprocessing using TRAINING data only."""
        df = df.copy()

        # Fit categorical encoders on TRAIN only
        cat_cols = [
            c for c in self.get_categorical_columns()
            if c in df.columns
        ]

        for col in cat_cols:
            le = LabelEncoder()
            values = df[col].astype(str).fillna("unknown")
            df[col] = le.fit_transform(values)
            self.label_encoders[col] = le

        # Calculate medians from TRAIN only
        numeric_cols = df.select_dtypes(include=[np.number]).columns

        self.imputation_values = {}

        for col in numeric_cols:
            median_value = df[col].median()

            if pd.isna(median_value):
                median_value = 0.0

            self.imputation_values[col] = float(median_value)
            df[col] = df[col].fillna(median_value)

        df = df.fillna(0)

        # Convert remaining object columns
        remaining_obj = df.select_dtypes(include=["object"]).columns.tolist()

        for col in remaining_obj:
            le = LabelEncoder()
            values = df[col].astype(str).fillna("unknown")
            df[col] = le.fit_transform(values)
            self.label_encoders[col] = le

        self.feature_names = list(df.columns)

        return df

    def transform_split(self, df: pd.DataFrame) -> pd.DataFrame:
        """Transform validation/test data using TRAIN parameters."""
        df = df.copy()

        # Use encoders learned from TRAIN
        for col, le in self.label_encoders.items():
            if col in df.columns:
                values = df[col].astype(str).fillna("unknown")

                df[col] = values.map(
                    lambda x: (
                        le.transform([x])[0]
                        if x in le.classes_
                        else 0
                    )
                )

        # Use medians learned from TRAIN
        for col, median_value in self.imputation_values.items():
            if col in df.columns:
                df[col] = df[col].fillna(median_value)

        numeric_cols = df.select_dtypes(include=[np.number]).columns

        if len(numeric_cols) > 0:
            df[numeric_cols] = df[numeric_cols].replace(
                [np.inf, -np.inf], np.nan
            )
            df[numeric_cols] = df[numeric_cols].fillna(0)

        df = df.fillna(0)

        # Match training feature order
        df = df.reindex(
            columns=self.feature_names,
            fill_value=0
        )

        return df

    # ---- Shared Preprocessing Pipeline ----

    def preprocess(self, mode: str = "native") -> Tuple[pd.DataFrame, pd.Series]:
        """
        Full preprocessing pipeline.

        Args:
            mode: "native" to use dataset-specific features (best accuracy),
                  "zyder" to map to common ZYDER schema (cross-dataset).

        Returns:
            (X, y) — feature matrix and binary labels.
        """
        logger.info("=" * 60)
        logger.info(f"Preprocessing {self.dataset_name} dataset (mode={mode})")
        logger.info("=" * 60)

        # Step 1: Load
        df = self.load_data()
        logger.info(f"Step 1 — Loaded: {df.shape[0]} rows, {df.shape[1]} columns")
        logger.info(f"  Columns: {list(df.columns)}")

        # Step 2: Create labels (before dropping anything)
        df = self.create_labels(df)
        y = df["label"].copy()
        logger.info(f"Step 2 — Labels created. Distribution:\n{y.value_counts().to_string()}")

        # Step 3: Remove duplicates
        n_before = len(df)
        df = df.drop_duplicates()
        y = y.loc[df.index]
        n_dropped = n_before - len(df)
        logger.info(f"Step 3 — Removed {n_dropped} duplicate rows ({len(df)} remaining)")

        # Step 4: Drop irrelevant columns
        cols_to_drop = self.get_columns_to_drop()
        existing_drops = [c for c in cols_to_drop if c in df.columns]
        df = df.drop(columns=existing_drops, errors="ignore")
        logger.info(f"Step 4 — Dropped columns: {existing_drops}")

        # Step 5: Handle categorical features
        cat_cols = [c for c in self.get_categorical_columns() if c in df.columns]
        for col in cat_cols:
            le = LabelEncoder()
            df[col] = df[col].astype(str).fillna("unknown")
            df[col] = le.fit_transform(df[col])
            self.label_encoders[col] = le
            logger.info(f"Step 5 — Encoded '{col}': {len(le.classes_)} categories")

        # Step 6: Handle missing values
        n_missing = df.isnull().sum().sum()
        if n_missing > 0:
            logger.info(f"Step 6 — Filling {n_missing} missing values with median")
            numeric_cols = df.select_dtypes(include=[np.number]).columns
            df[numeric_cols] = df[numeric_cols].fillna(df[numeric_cols].median())
            # Any remaining non-numeric NaN
            df = df.fillna(0)
        else:
            logger.info("Step 6 — No missing values found")

        # Step 7: Handle infinite values
        n_inf = np.isinf(df.select_dtypes(include=[np.number])).sum().sum()
        if n_inf > 0:
            logger.info(f"Step 7 — Replacing {n_inf} infinite values")
            numeric_cols = df.select_dtypes(include=[np.number]).columns
            df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan)
            df[numeric_cols] = df[numeric_cols].fillna(df[numeric_cols].median())
        else:
            logger.info("Step 7 — No infinite values found")

        # Step 8: Ensure all remaining columns are numeric
        remaining_obj = df.select_dtypes(include=["object"]).columns.tolist()
        if remaining_obj:
            logger.warning(f"Step 8 — Converting remaining object columns: {remaining_obj}")
            for col in remaining_obj:
                le = LabelEncoder()
                df[col] = le.fit_transform(df[col].astype(str))
                self.label_encoders[col] = le

        # Step 9: Map to ZYDER schema if requested
        if mode == "zyder":
            df = self.map_to_zyder_features(df)
            logger.info(f"Step 9 — Mapped to ZYDER schema: {df.shape[1]} features")

        # Align y with df after dedup
        y = y.loc[df.index].reset_index(drop=True)
        df = df.reset_index(drop=True)

        self.feature_names = list(df.columns)
        logger.info(f"Final feature matrix: {df.shape}")
        logger.info(f"Final features: {self.feature_names}")

        return df, y

    # ---- Persistence ----

    def save_config(self, model_dir: Path) -> None:
        """Save preprocessing configuration for inference reproducibility."""
        model_dir.mkdir(parents=True, exist_ok=True)

        # Save label encoders
        pkl_path = model_dir / f"preprocessing_{self.dataset_name}.pkl"
        joblib.dump({
    "label_encoders": self.label_encoders,
    "imputation_values": self.imputation_values,
    "feature_names": self.feature_names,
    "dataset_name": self.dataset_name,
}, pkl_path)
        logger.info(f"Saved preprocessing config to {pkl_path}")

        # Save feature schema
        schema = FeatureSchema(
            feature_names=self.feature_names,
            dataset_source=self.dataset_name,
        )
        schema_path = model_dir / "feature_schema.json"
        with open(schema_path, "w") as f:
            json.dump(schema.to_dict(), f, indent=2)
        logger.info(f"Saved feature schema to {schema_path}")

        # Save label mapping
        label_path = model_dir / "label_mapping.json"
        with open(label_path, "w") as f:
            json.dump({str(k): v for k, v in LABEL_MAPPING.items()}, f, indent=2)
        logger.info(f"Saved label mapping to {label_path}")

    def load_config(self, model_dir: Path) -> None:
        """Load saved preprocessing configuration."""
        pkl_path = model_dir / f"preprocessing_{self.dataset_name}.pkl"
        if not pkl_path.exists():
            raise FileNotFoundError(
                f"Preprocessing config not found: {pkl_path}. "
                "Train the model first."
            )

        saved = joblib.load(pkl_path)
        self.label_encoders = saved["label_encoders"]
        self.imputation_values = saved.get("imputation_values", {})
        self.feature_names = saved["feature_names"]
        logger.info(f"Loaded preprocessing config from {pkl_path}")

    def transform_single_flow(self, flow: Dict[str, Any]) -> pd.DataFrame:
        """
        Transform a single flow dict using saved preprocessing config.

        Args:
            flow: Dictionary with feature name -> value pairs.

        Returns:
            Single-row DataFrame matching training feature order.
        """
        row = {}
        for feat in self.feature_names:
            val = flow.get(feat, 0)
            # Apply label encoding if applicable
            if feat in self.label_encoders:
                le = self.label_encoders[feat]
                val_str = str(val)
                if val_str in le.classes_:
                    val = le.transform([val_str])[0]
                else:
                    # Unknown category — use 0
                    val = 0
            row[feat] = val

        df = pd.DataFrame([row], columns=self.feature_names)
        # Ensure numeric
        df = df.apply(pd.to_numeric, errors="coerce").fillna(0)
        return df
