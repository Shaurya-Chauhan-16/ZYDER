"""
ZYDER UNSW-NB15 Preprocessor
==============================
Handles loading, cleaning, and transforming the UNSW-NB15 dataset
into the ZYDER common feature representation.

Dataset specifics:
- Pre-split files: UNSW_NB15_training-set.csv (82,332 rows, 45 cols)
                   UNSW_NB15_testing-set.csv
- Raw files: UNSW-NB15_1.csv through UNSW-NB15_4.csv (no headers, 49 cols)
- Features doc: NUSW-NB15_features.csv
- Label column: 'label' (0=Normal, 1=Attack)
- Attack categories: 'attack_cat' (9 attack types + Normal)
- Categorical columns: proto, service, state
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd

from preprocessing.base_preprocessor import BasePreprocessor
from preprocessing.feature_schema import get_unsw_mapping, get_zyder_feature_names

logger = logging.getLogger("zyder.preprocessing.unsw")


class UNSWPreprocessor(BasePreprocessor):
    """Preprocessor for the UNSW-NB15 intrusion detection dataset."""

    def __init__(self, config: Dict[str, Any], base_dir: Path) -> None:
        super().__init__(config, base_dir)
        self.dataset_name = "unsw"

    def load_data(self) -> pd.DataFrame:
        """
        Load UNSW-NB15 data. Prefers pre-split training+testing CSVs
        (which have proper headers and 45 columns). Falls back to raw
        CSV files if pre-split are not found.
        """
        ds_config = self.config["datasets"]["unsw_nb15"]

        # Try pre-split files first (recommended — they have headers)
        train_path = self.base_dir / ds_config["training_set"]
        test_path = self.base_dir / ds_config["testing_set"]

        if train_path.exists() and test_path.exists():
            logger.info(f"Loading pre-split UNSW-NB15 files:")
            logger.info(f"  Training: {train_path}")
            logger.info(f"  Testing:  {test_path}")

            df_train = pd.read_csv(train_path)
            df_test = pd.read_csv(test_path)

            logger.info(f"  Training shape: {df_train.shape}")
            logger.info(f"  Testing shape:  {df_test.shape}")
            logger.info(f"  Training columns: {list(df_train.columns)}")

            # Combine for our own stratified splitting
            df = pd.concat([df_train, df_test], ignore_index=True)
            logger.info(f"  Combined shape: {df.shape}")
            return df

        # Fallback to raw CSV files
        logger.info("Pre-split files not found, loading raw UNSW-NB15 CSVs...")
        raw_files = ds_config.get("raw_files", [])
        features_path = self.base_dir / ds_config.get("features_file", "")

        if not raw_files:
            raise FileNotFoundError(
                "No UNSW-NB15 data files configured. Check config.yaml"
            )

        # Load feature names from the features file
        col_names = self._load_feature_names(features_path)

        dfs = []
        for fpath in raw_files:
            full_path = self.base_dir / fpath
            if full_path.exists():
                logger.info(f"  Loading {full_path}...")
                chunk = pd.read_csv(full_path, header=None, names=col_names)
                dfs.append(chunk)
                logger.info(f"    -> {chunk.shape[0]} rows")
            else:
                logger.warning(f"  File not found: {full_path}")

        if not dfs:
            raise FileNotFoundError("No UNSW-NB15 CSV files could be loaded.")

        df = pd.concat(dfs, ignore_index=True)
        logger.info(f"  Combined raw shape: {df.shape}")
        return df

    def _load_feature_names(self, features_path: Path) -> List[str]:
        """Load column names from NUSW-NB15_features.csv."""
        if features_path.exists():
            feat_df = pd.read_csv(features_path, encoding="latin-1")
            names = feat_df["Name"].str.strip().tolist()
            logger.info(f"  Loaded {len(names)} feature names from {features_path}")
            return names
        else:
            # Fallback: use the known column names from the pre-split set
            logger.warning(f"Features file not found: {features_path}. Using defaults.")
            return [
                "srcip", "sport", "dstip", "dsport", "proto", "state", "dur",
                "sbytes", "dbytes", "sttl", "dttl", "sloss", "dloss", "service",
                "Sload", "Dload", "Spkts", "Dpkts", "swin", "dwin", "stcpb",
                "dtcpb", "smeansz", "dmeansz", "trans_depth", "res_bdy_len",
                "Sjit", "Djit", "Stime", "Ltime", "Sintpkt", "Dintpkt",
                "tcprtt", "synack", "ackdat", "is_sm_ips_ports", "ct_state_ttl",
                "ct_flw_http_mthd", "is_ftp_login", "ct_ftp_cmd", "ct_srv_src",
                "ct_srv_dst", "ct_dst_ltm", "ct_src_ ltm", "ct_src_dport_ltm",
                "ct_dst_sport_ltm", "ct_dst_src_ltm", "attack_cat", "Label",
            ]

    def create_labels(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Create binary label column.
        UNSW-NB15 already has 'label' (0/1) in the pre-split sets.
        Raw CSVs may use 'Label' (capital L).
        """
        df = df.copy()

        if "label" in df.columns:
            # Pre-split sets: label is already 0/1
            df["label"] = df["label"].astype(int)
        elif "Label" in df.columns:
            # Raw CSVs
            df["label"] = df["Label"].astype(int)
            df.drop(columns=["Label"], inplace=True, errors="ignore")
        else:
            raise ValueError(
                "Cannot find 'label' or 'Label' column in UNSW-NB15 data. "
                f"Available columns: {list(df.columns)}"
            )

        logger.info(f"  Label distribution: {df['label'].value_counts().to_dict()}")
        return df

    def get_columns_to_drop(self) -> List[str]:
        """
        Columns to remove from features.
        - IPs: srcip, dstip (not generalizable, cause overfitting)
        - Ports: sport, dsport (in raw CSVs; pre-split doesn't have them)
        - IDs: id
        - Timestamps: Stime, Ltime
        - Target leak: attack_cat, label
        - TCP base seq numbers: stcpb, dtcpb (flow-specific, not generalizable)
        """
        return [
            # Identifiers
            "id", "srcip", "dstip", "sport", "dsport",
            # Timestamps
            "Stime", "Ltime",
            # Target / label columns (label is separated as y)
            "attack_cat", "label",
            # TCP base sequence numbers (flow-specific metadata)
            "stcpb", "dtcpb",
        ]

    def get_categorical_columns(self) -> List[str]:
        """Categorical columns requiring label encoding."""
        return ["proto", "service", "state"]

    def map_to_zyder_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Map UNSW-NB15 native columns to the ZYDER common feature schema.
        Features not available in UNSW-NB15 are filled with 0.
        """
        mapping = get_unsw_mapping()
        zyder_names = get_zyder_feature_names()
        zyder_df = pd.DataFrame(index=df.index)

        for zyder_name in zyder_names:
            unsw_col = mapping.get(zyder_name)
            if unsw_col is not None and unsw_col in df.columns:
                zyder_df[zyder_name] = df[unsw_col].values
            else:
                # Feature not available — fill with 0
                zyder_df[zyder_name] = 0

        # Derived features
        if "sload" in df.columns and "dload" in df.columns:
            # byte_rate: combined source + destination load (bits/s -> bytes/s)
            zyder_df["byte_rate"] = (df["sload"].values + df["dload"].values) / 8.0

        if "sinpkt" in df.columns and "dinpkt" in df.columns:
            # flow_iat_mean: average of source and dest inter-packet times
            zyder_df["flow_iat_mean"] = (
                df["sinpkt"].values + df["dinpkt"].values
            ) / 2.0

        logger.info(f"  Mapped {len(zyder_names)} ZYDER features from UNSW-NB15")
        return zyder_df
