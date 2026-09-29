import logging
from pathlib import Path
from typing import List, Dict, Any

from detection.pcap_pipeline import FeatureExtractor
from detection.zeek_backend import ZeekUNSWBackend
from detection.unsw_packet_features import parse_pcap
from detection.unsw_feature_builder import build_features

logger = logging.getLogger("zyder.detection.unsw")

class UNSWFeatureExtractor(FeatureExtractor):
    def __init__(self):
        self.backend = ZeekUNSWBackend()

    def extract_features(self, pcap_path: str | Path) -> List[dict]:
        if not self.backend.is_installed():
            raise RuntimeError("Zeek is not installed or not in PATH.")

        logger.info(f"Executing Zeek on {pcap_path}")
        logs = self.backend.execute(pcap_path)
        
        conn_log = logs.get("conn", [])
        http_log = logs.get("http", [])
        ftp_log = logs.get("ftp", [])
        
        http_lookup = {}
        http_method_counts = {}
        for h in http_log:
            uid = h.get("uid")
            http_lookup[uid] = h
            if h.get("method"):
                http_method_counts[uid] = http_method_counts.get(uid, 0) + 1
                
        ftp_lookup = {}
        ftp_cmd_counts = {}
        ftp_has_login = {}
        for f in ftp_log:
            uid = f.get("uid")
            ftp_lookup[uid] = f
            if f.get("command"):
                ftp_cmd_counts[uid] = ftp_cmd_counts.get(uid, 0) + 1
            if f.get("user"):
                ftp_has_login[uid] = 1

        zeek_flows = []
        for conn in conn_log:
            uid = conn.get("uid")
            
            is_ftp_login = ftp_has_login.get(uid, 0)
            ct_ftp_cmd = ftp_cmd_counts.get(uid, 0)
            ct_flw_http_mthd = http_method_counts.get(uid, 0)
            
            zeek_flows.append({
                "src": conn.get("id.orig_h"),
                "dst": conn.get("id.resp_h"),
                "sport": conn.get("id.orig_p"),
                "dport": conn.get("id.resp_p"),
                "dur": conn.get("duration", 0.0),
                "proto": conn.get("proto", "unknown"),
                "service": conn.get("service", "-"),
                "state": conn.get("conn_state", "-"),
                "spkts": conn.get("orig_pkts", 0),
                "dpkts": conn.get("resp_pkts", 0),
                "sbytes": conn.get("orig_ip_bytes", 0),
                "dbytes": conn.get("resp_ip_bytes", 0),
                "trans_depth": http_lookup.get(uid, {}).get("trans_depth", 0),
                "response_body_len": http_lookup.get(uid, {}).get("response_body_len", 0),
                "is_ftp_login": is_ftp_login,
                "ct_ftp_cmd": ct_ftp_cmd,
                "ct_flw_http_mthd": ct_flw_http_mthd
            })
            
        logger.info("Executing Scapy Packet-level Parsing...")
        scapy_flows = parse_pcap(pcap_path)
        
        logger.info("Building UNSW-NB15 Features...")
        final_flows = build_features(zeek_flows, scapy_flows)
        
        return final_flows
