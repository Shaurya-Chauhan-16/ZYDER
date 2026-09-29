from __future__ import annotations

import subprocess
import sys
import tempfile
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List

import pandas as pd

from preprocessing.cicflowmeter_mapper import (
    convert_cicflowmeter_to_cicids,
)


METADATA_COLUMNS = [
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "timestamp",
]


class FeatureExtractor(ABC):
    """Base class for dataset-specific PCAP feature extraction."""
    @abstractmethod
    def extract_features(self, pcap_path: str | Path) -> List[dict]:
        pass


class CICIDSFeatureExtractor(FeatureExtractor):
    def extract_features(self, pcap_path: str | Path) -> List[dict]:
        """
        Convert a PCAP into CICIDS-compatible flow dictionaries using CICFlowMeter.
        Each returned dictionary contains:
          - 71 CICIDS model features
          - network metadata used by ZYDER reporting
        """
        pcap_path = Path(pcap_path)
        if not pcap_path.exists():
            raise FileNotFoundError(f"PCAP not found: {pcap_path}")

        with tempfile.TemporaryDirectory(prefix="zyder-pcap-") as tmp:
            tmp = Path(tmp)

            raw_csv = tmp / "cicflow.csv"
            mapped_csv = tmp / "cicids.csv"

            script = (
                "import inspect\n"
                "from cicflowmeter.sniffer import create_sniffer\n"
                "params = inspect.signature(create_sniffer).parameters\n"
                f"kwargs = {{'input_file': {str(pcap_path)!r}, 'input_interface': None, 'output_mode': 'csv', 'output': {str(raw_csv)!r}, 'verbose': False}}\n"
                "if 'fields' in params:\n"
                "    kwargs['fields'] = None\n"
                "if 'input_directory' in params:\n"
                "    kwargs['input_directory'] = None\n"
                "sniffer, session = create_sniffer(**kwargs)\n"
                "sniffer.start()\n"
                "sniffer.join()\n"
                "session.flush_flows()\n"
            )

            command = [sys.executable, "-c", script]

            result = subprocess.run(command, capture_output=True, text=True)

            if result.returncode != 0:
                raise RuntimeError("CICFlowMeter failed:\n" + result.stderr)

            if not raw_csv.exists():
                raise RuntimeError("CICFlowMeter completed but produced no CSV.")

            raw_df = pd.read_csv(raw_csv)
            mapped = convert_cicflowmeter_to_cicids(raw_csv, mapped_csv)

            if mapped.empty:
                return []

            flows = []
            for index in range(len(mapped)):
                flow = mapped.iloc[index].to_dict()
                for column in METADATA_COLUMNS:
                    if column in raw_df.columns:
                        value = raw_df.iloc[index][column]
                        if pd.isna(value): value = None
                        flow[column] = value
                flows.append(flow)

            return flows





def extract_cicids_flows(pcap_path: str | Path) -> List[dict]:
    """Legacy wrapper for backward compatibility."""
    return CICIDSFeatureExtractor().extract_features(pcap_path)

def get_feature_extractor(dataset: str) -> FeatureExtractor:
    if dataset.lower() == "unsw":
        from detection.unsw_feature_extractor import UNSWFeatureExtractor
        return UNSWFeatureExtractor()
    return CICIDSFeatureExtractor()
