"""
ZYDER CICIDS2017 Preprocessor
================================
Handles loading, cleaning, and transforming the CICIDS2017 dataset
into the ZYDER common feature representation.

Dataset specifics:
- 8 per-day CSV files (Monday through Friday)
- 79 columns (78 features + Label), extracted by CICFlowMeter
- Column names have leading/trailing whitespace (known issue)
- Contains inf values in Flow Bytes/s and Flow Packets/s
- Label column: ' Label' (with leading space)
- Labels: 'BENIGN' plus 14 attack types
- No source IP / Flow ID columns in features (only dest port)
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List

import numpy as np
import pandas as pd

from preprocessing.base_preprocessor import BasePreprocessor
from preprocessing.feature_schema import get_cicids_mapping, get_zyder_feature_names

logger = logging.getLogger("zyder.preprocessing.cicids")


class CICIDSPreprocessor(BasePreprocessor):
    """Preprocessor for the CICIDS2017 intrusion detection dataset."""

    def __init__(self, config: Dict[str, Any], base_dir: Path) -> None:
        super().__init__(config, base_dir)
        self.dataset_name = "cicids"

    def load_data(self) -> pd.DataFrame:
        """
        Load all CICIDS2017 per-day CSVs and concatenate.
        Strips whitespace from column names (known CICFlowMeter issue).
        """
        ds_config = self.config["datasets"]["cicids2017"]
        raw_files = ds_config.get("raw_files", [])

        if not raw_files:
            raise FileNotFoundError(
                "No CICIDS2017 data files configured. Check config.yaml"
            )

        dfs = []
        for fpath in raw_files:
            full_path = self.base_dir / fpath
            if full_path.exists():
                logger.info(f"  Loading {full_path.name}...")
                try:
                    chunk = pd.read_csv(full_path, encoding="utf-8", low_memory=False)
                except UnicodeDecodeError:
                    chunk = pd.read_csv(full_path, encoding="latin-1", low_memory=False)

                # Strip whitespace from column names (known issue)
                chunk.columns = chunk.columns.str.strip()
                dfs.append(chunk)
                logger.info(f"    -> {chunk.shape[0]} rows, {chunk.shape[1]} cols")
            else:
                logger.warning(f"  File not found: {full_path}")

        if not dfs:
            raise FileNotFoundError("No CICIDS2017 CSV files could be loaded.")

        # Verify all files have the same columns
        ref_cols = set(dfs[0].columns)
        for i, chunk in enumerate(dfs[1:], 2):
            if set(chunk.columns) != ref_cols:
                diff = set(chunk.columns).symmetric_difference(ref_cols)
                logger.warning(
                    f"  File {i} has different columns. Diff: {diff}. "
                    "Aligning to common columns."
                )

        df = pd.concat(dfs, ignore_index=True)
        logger.info(f"  Combined shape: {df.shape}")
        logger.info(f"  Columns after strip: {list(df.columns)}")

        # Replace infinity values immediately (very common in this dataset)
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        inf_count = np.isinf(df[numeric_cols]).sum().sum()
        if inf_count > 0:
            logger.info(f"  Replacing {inf_count} infinite values with NaN")
            df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan)

        return df

    def create_labels(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Create binary label: 0=BENIGN, 1=ATTACK.
        CICIDS2017 'Label' column is a string: 'BENIGN' or attack name.
        """
        df = df.copy()

        # Find the label column (may or may not have leading space after strip)
        label_col = None
        for candidate in ["Label", " Label", "label"]:
            if candidate in df.columns:
                label_col = candidate
                break

        if label_col is None:
            raise ValueError(
                "Cannot find Label column in CICIDS2017 data. "
                f"Available columns: {list(df.columns)}"
            )

        # Store original labels for logging
        original_labels = df[label_col].value_counts()
        logger.info(f"  Original label distribution:\n{original_labels.to_string()}")

        # Binary mapping: BENIGN -> 0, everything else -> 1
        df["label"] = (df[label_col].str.strip() != "BENIGN").astype(int)

        # Drop original label column
        if label_col != "label":
            df.drop(columns=[label_col], inplace=True, errors="ignore")

        return df

    def get_columns_to_drop(self) -> List[str]:
        """
        Columns to remove from features.
        CICIDS2017 standard CSV files typically don't include Flow ID,
        Source IP, Destination IP, or Timestamp in the column set.
        However, some versions do — drop them if present.
        """
        return [
            # Metadata (may or may not be present)
            "Flow ID", "Source IP", "Destination IP", "Timestamp",
            # Target column
            "Label", "label",
            # Duplicate header column
            "Fwd Header Length.1",
            # Bulk rate columns (often all zeros, not useful)
            "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate",
            "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate",
        ]

    def get_categorical_columns(self) -> List[str]:
        """CICIDS2017 has no categorical columns after label encoding."""
        return []

    def map_to_zyder_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Map CICIDS2017 columns to the ZYDER common feature schema.
        Features not available in CICIDS2017 are filled with 0.

        Note: CICIDS column names have inconsistent spacing. The mapping
        in feature_schema.py uses the original (pre-strip) names, but
        we strip here so we need to match stripped names.
        """
        mapping = get_cicids_mapping()
        zyder_names = get_zyder_feature_names()
        zyder_df = pd.DataFrame(index=df.index)

        # Build a stripped version of the mapping for matching
        df_cols_set = set(df.columns)

        for zyder_name in zyder_names:
            cicids_col = mapping.get(zyder_name)
            if cicids_col is not None:
                # Try both stripped and original
                stripped = cicids_col.strip()
                if stripped in df_cols_set:
                    zyder_df[zyder_name] = df[stripped].values
                elif cicids_col in df_cols_set:
                    zyder_df[zyder_name] = df[cicids_col].values
                else:
                    zyder_df[zyder_name] = 0
            else:
                zyder_df[zyder_name] = 0

        logger.info(f"  Mapped {len(zyder_names)} ZYDER features from CICIDS2017")
        return zyder_df
