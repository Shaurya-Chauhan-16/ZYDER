"""
ZYDER Feature Schema
====================
Defines the common ZYDER feature representation that both UNSW-NB15
and CICIDS2017 are mapped into. This ensures a consistent feature
matrix regardless of the source dataset.

The mapping is derived from the ZYDER research paper's specification
of flow-level statistical and protocol features.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

# ============================================================
# ZYDER Common Feature Set
# ============================================================
# Each entry: (zyder_name, description, unsw_source, cicids_source)
# A source of None means the feature is not natively available
# in that dataset and will be set to 0.
# ============================================================

ZYDER_FEATURE_MAP: List[Dict[str, Optional[str]]] = [
    # --- Flow Identification (used for context, NOT model features) ---
    # src_ip, dst_ip are kept in metadata only, never in the feature matrix

    # --- Port & Protocol ---
    {"zyder": "src_port",           "desc": "Source port",                          "unsw": None,         "cicids": None},
    # NOTE: src_port is in raw UNSW (sport) but not in pre-split set;
    #       cicids has ' Source Port' but we use ' Destination Port' only since
    #       src_port is stripped from CICIDS columns. We handle via preprocessors.
    {"zyder": "dst_port",           "desc": "Destination port",                     "unsw": None,         "cicids": " Destination Port"},
    {"zyder": "protocol",           "desc": "Protocol (numerically encoded)",       "unsw": "proto",      "cicids": None},
    # CICIDS protocol is not in the standard CSV columns (metadata-only)

    # --- Duration ---
    {"zyder": "flow_duration",      "desc": "Flow duration",                        "unsw": "dur",        "cicids": " Flow Duration"},

    # --- Packet Counts ---
    {"zyder": "fwd_packet_count",   "desc": "Forward (src->dst) packet count",       "unsw": "spkts",      "cicids": " Total Fwd Packets"},
    {"zyder": "bwd_packet_count",   "desc": "Backward (dst->src) packet count",      "unsw": "dpkts",      "cicids": " Total Backward Packets"},

    # --- Byte Counts ---
    {"zyder": "fwd_bytes",          "desc": "Forward byte count",                   "unsw": "sbytes",     "cicids": "Total Length of Fwd Packets"},
    {"zyder": "bwd_bytes",          "desc": "Backward byte count",                  "unsw": "dbytes",     "cicids": " Total Length of Bwd Packets"},

    # --- Forward Packet Statistics ---
    {"zyder": "fwd_pkt_len_mean",   "desc": "Mean forward packet size",             "unsw": "smean",      "cicids": " Fwd Packet Length Mean"},
    {"zyder": "fwd_pkt_len_std",    "desc": "Std forward packet size",              "unsw": None,         "cicids": " Fwd Packet Length Std"},
    {"zyder": "fwd_pkt_len_max",    "desc": "Max forward packet size",              "unsw": None,         "cicids": " Fwd Packet Length Max"},
    {"zyder": "fwd_pkt_len_min",    "desc": "Min forward packet size",              "unsw": None,         "cicids": " Fwd Packet Length Min"},

    # --- Backward Packet Statistics ---
    {"zyder": "bwd_pkt_len_mean",   "desc": "Mean backward packet size",            "unsw": "dmean",      "cicids": " Bwd Packet Length Mean"},
    {"zyder": "bwd_pkt_len_std",    "desc": "Std backward packet size",             "unsw": None,         "cicids": " Bwd Packet Length Std"},
    {"zyder": "bwd_pkt_len_max",    "desc": "Max backward packet size",             "unsw": None,         "cicids": "Bwd Packet Length Max"},
    {"zyder": "bwd_pkt_len_min",    "desc": "Min backward packet size",             "unsw": None,         "cicids": " Bwd Packet Length Min"},

    # --- Rates ---
    {"zyder": "packet_rate",        "desc": "Packets per second",                   "unsw": "rate",       "cicids": " Flow Packets/s"},
    {"zyder": "byte_rate",          "desc": "Bytes per second",                     "unsw": None,         "cicids": "Flow Bytes/s"},
    # UNSW: byte_rate derived from sload + dload in preprocessor

    # --- Inter-Arrival Times ---
    {"zyder": "flow_iat_mean",      "desc": "Flow inter-arrival time mean",         "unsw": None,         "cicids": " Flow IAT Mean"},
    {"zyder": "flow_iat_std",       "desc": "Flow IAT standard deviation",          "unsw": None,         "cicids": " Flow IAT Std"},
    {"zyder": "fwd_iat_mean",       "desc": "Forward IAT mean",                     "unsw": "sinpkt",     "cicids": " Fwd IAT Mean"},
    {"zyder": "bwd_iat_mean",       "desc": "Backward IAT mean",                    "unsw": "dinpkt",     "cicids": " Bwd IAT Mean"},

    # --- TCP Flags ---
    {"zyder": "tcp_flags_syn",      "desc": "SYN flag count",                       "unsw": None,         "cicids": " SYN Flag Count"},
    {"zyder": "tcp_flags_fin",      "desc": "FIN flag count",                       "unsw": None,         "cicids": "FIN Flag Count"},
    {"zyder": "tcp_flags_rst",      "desc": "RST flag count",                       "unsw": None,         "cicids": " RST Flag Count"},
    {"zyder": "tcp_flags_psh",      "desc": "PSH flag count",                       "unsw": None,         "cicids": " PSH Flag Count"},
    {"zyder": "tcp_flags_ack",      "desc": "ACK flag count",                       "unsw": None,         "cicids": " ACK Flag Count"},

    # --- TTL ---
    {"zyder": "src_ttl",            "desc": "Source time-to-live",                   "unsw": "sttl",       "cicids": None},
    {"zyder": "dst_ttl",            "desc": "Destination time-to-live",              "unsw": "dttl",       "cicids": None},

    # --- TCP Timing ---
    {"zyder": "tcp_rtt",            "desc": "TCP round-trip time",                   "unsw": "tcprtt",     "cicids": None},
    {"zyder": "syn_ack_time",       "desc": "SYN-ACK time",                          "unsw": "synack",     "cicids": None},
    {"zyder": "ack_dat_time",       "desc": "ACK-DAT time",                          "unsw": "ackdat",     "cicids": None},

    # --- Source/Dest Load ---
    {"zyder": "src_load",           "desc": "Source bits per second",                "unsw": "sload",      "cicids": None},
    {"zyder": "dst_load",           "desc": "Destination bits per second",            "unsw": "dload",      "cicids": None},

    # --- Jitter ---
    {"zyder": "src_jitter",         "desc": "Source jitter (ms)",                    "unsw": "sjit",       "cicids": None},
    {"zyder": "dst_jitter",         "desc": "Destination jitter (ms)",               "unsw": "djit",       "cicids": None},

    # --- Packet Loss ---
    {"zyder": "src_loss",           "desc": "Source packets retransmitted/dropped",  "unsw": "sloss",      "cicids": None},
    {"zyder": "dst_loss",           "desc": "Dest packets retransmitted/dropped",    "unsw": "dloss",      "cicids": None},

    # --- Window Sizes ---
    {"zyder": "init_win_fwd",       "desc": "Initial TCP window (forward)",          "unsw": "swin",       "cicids": "Init_Win_bytes_forward"},
    {"zyder": "init_win_bwd",       "desc": "Initial TCP window (backward)",         "unsw": "dwin",       "cicids": " Init_Win_bytes_backward"},

    # --- Header Lengths ---
    {"zyder": "fwd_header_len",     "desc": "Forward header length",                 "unsw": None,         "cicids": " Fwd Header Length"},
    {"zyder": "bwd_header_len",     "desc": "Backward header length",                "unsw": None,         "cicids": " Bwd Header Length"},

    # --- Packet Size Aggregates ---
    {"zyder": "avg_pkt_size",       "desc": "Average packet size",                   "unsw": None,         "cicids": " Average Packet Size"},
    {"zyder": "pkt_len_variance",   "desc": "Packet length variance",                "unsw": None,         "cicids": " Packet Length Variance"},

    # --- Subflow ---
    {"zyder": "subflow_fwd_pkts",   "desc": "Subflow forward packets",               "unsw": None,         "cicids": "Subflow Fwd Packets"},
    {"zyder": "subflow_bwd_pkts",   "desc": "Subflow backward packets",              "unsw": None,         "cicids": " Subflow Bwd Packets"},

    # --- Active/Idle ---
    {"zyder": "active_mean",        "desc": "Active time mean",                      "unsw": None,         "cicids": "Active Mean"},
    {"zyder": "idle_mean",          "desc": "Idle time mean",                        "unsw": None,         "cicids": "Idle Mean"},

    # --- UNSW Connection Behavior Features ---
    {"zyder": "ct_srv_src",         "desc": "Conn count same service+src",           "unsw": "ct_srv_src", "cicids": None},
    {"zyder": "ct_srv_dst",         "desc": "Conn count same service+dst",           "unsw": "ct_srv_dst", "cicids": None},
    {"zyder": "ct_dst_ltm",         "desc": "Conn count dst in last 100",            "unsw": "ct_dst_ltm", "cicids": None},
    {"zyder": "ct_src_ltm",         "desc": "Conn count src in last 100",            "unsw": "ct_src_ltm", "cicids": None},
    {"zyder": "ct_state_ttl",       "desc": "Flows with same state+TTL",             "unsw": "ct_state_ttl", "cicids": None},
    {"zyder": "ct_src_dport_ltm",   "desc": "Conn count same src+dport",             "unsw": "ct_src_dport_ltm", "cicids": None},
    {"zyder": "ct_dst_sport_ltm",   "desc": "Conn count same dst+sport",             "unsw": "ct_dst_sport_ltm", "cicids": None},
    {"zyder": "ct_dst_src_ltm",     "desc": "Conn count same src+dst",               "unsw": "ct_dst_src_ltm", "cicids": None},

    # --- Content Features (UNSW) ---
    {"zyder": "trans_depth",        "desc": "HTTP transaction depth",                "unsw": "trans_depth",      "cicids": None},
    {"zyder": "response_body_len",  "desc": "HTTP response body length",             "unsw": "response_body_len","cicids": None},

    # --- Down/Up Ratio ---
    {"zyder": "down_up_ratio",      "desc": "Download/upload ratio",                 "unsw": None,         "cicids": " Down/Up Ratio"},

    # --- Active Data Packets ---
    {"zyder": "act_data_pkt_fwd",   "desc": "Fwd packets with payload",             "unsw": None,         "cicids": " act_data_pkt_fwd"},

    # --- FTP/HTTP indicators (UNSW) ---
    {"zyder": "is_ftp_login",       "desc": "FTP login detected",                   "unsw": "is_ftp_login",       "cicids": None},
    {"zyder": "ct_ftp_cmd",         "desc": "FTP command count",                     "unsw": "ct_ftp_cmd",         "cicids": None},
    {"zyder": "ct_flw_http_mthd",   "desc": "HTTP method flow count",               "unsw": "ct_flw_http_mthd",   "cicids": None},
    {"zyder": "is_sm_ips_ports",    "desc": "Same IPs and ports",                    "unsw": "is_sm_ips_ports",    "cicids": None},
]


def get_zyder_feature_names() -> List[str]:
    """Return ordered list of all ZYDER common feature names."""
    return [f["zyder"] for f in ZYDER_FEATURE_MAP]


def get_unsw_mapping() -> Dict[str, Optional[str]]:
    """Return {zyder_name: unsw_column_name} mapping."""
    return {f["zyder"]: f["unsw"] for f in ZYDER_FEATURE_MAP}


def get_cicids_mapping() -> Dict[str, Optional[str]]:
    """Return {zyder_name: cicids_column_name} mapping."""
    return {f["zyder"]: f["cicids"] for f in ZYDER_FEATURE_MAP}


def get_feature_descriptions() -> Dict[str, str]:
    """Return {zyder_name: human-readable description}."""
    return {f["zyder"]: f["desc"] for f in ZYDER_FEATURE_MAP}


# ============================================================
# Label Mapping
# ============================================================

LABEL_MAPPING = {
    0: "BENIGN",
    1: "ATTACK",
}

UNSW_ATTACK_CATEGORIES = [
    "Normal", "Generic", "Exploits", "Fuzzers", "DoS",
    "Reconnaissance", "Analysis", "Backdoor", "Shellcode", "Worms",
]

CICIDS_ATTACK_CATEGORIES = [
    "BENIGN", "DoS Hulk", "PortScan", "DDoS", "DoS GoldenEye",
    "FTP-Patator", "SSH-Patator", "DoS slowloris", "DoS Slowhttptest",
    "Bot", "Web Attack \u2013 Brute Force", "Web Attack \u2013 XSS",
    "Infiltration", "Web Attack \u2013 Sql Injection", "Heartbleed",
]


@dataclass
class FeatureSchema:
    """Saved feature schema for inference reproducibility."""
    feature_names: List[str] = field(default_factory=get_zyder_feature_names)
    label_mapping: Dict[int, str] = field(default_factory=lambda: LABEL_MAPPING.copy())
    dataset_source: str = ""
    n_features: int = 0

    def __post_init__(self) -> None:
        self.n_features = len(self.feature_names)

    def to_dict(self) -> dict:
        return {
            "feature_names": self.feature_names,
            "label_mapping": {str(k): v for k, v in self.label_mapping.items()},
            "dataset_source": self.dataset_source,
            "n_features": self.n_features,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "FeatureSchema":
        schema = cls(
            feature_names=d["feature_names"],
            label_mapping={int(k): v for k, v in d["label_mapping"].items()},
            dataset_source=d.get("dataset_source", ""),
        )
        return schema
