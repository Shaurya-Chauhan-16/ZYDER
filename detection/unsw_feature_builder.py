import logging
import math
from typing import List, Dict, Any

logger = logging.getLogger("zyder.detection.unsw_builder")

def build_features(zeek_flows: List[Dict[str, Any]], packet_flows: Dict[Any, Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Fuses Zeek L7 logs and Scapy packet metrics into the canonical UNSW-NB15 flow array.
    Passes the output to the State Tracker to compute window metrics.
    Produces EXACTLY 40 features in the verified order.
    """
    from detection.unsw_state_tracker import UNSWStateTracker
    
    EXPECTED_FEATURES = [
        "dur", "proto", "service", "state", "spkts", "dpkts", "sbytes", "dbytes", 
        "rate", "sttl", "dttl", "sload", "dload", "sloss", "dloss", "sinpkt", 
        "dinpkt", "sjit", "djit", "swin", "dwin", "tcprtt", "synack", "ackdat", 
        "smean", "dmean", "trans_depth", "response_body_len", "ct_srv_src", 
        "ct_state_ttl", "ct_dst_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm", 
        "ct_dst_src_ltm", "is_ftp_login", "ct_ftp_cmd", "ct_flw_http_mthd", 
        "ct_src_ltm", "ct_srv_dst", "is_sm_ips_ports"
    ]
    
    merged = []
    
    # Map protocol names for lookup
    proto_map = {"tcp": 6, "udp": 17, "icmp": 1}
    
    for zf in zeek_flows:
        src = zf.get("src")
        dst = zf.get("dst")
        sport = zf.get("sport")
        dport = zf.get("dport")
        zproto = str(zf.get("proto", "")).lower()
        proto_id = proto_map.get(zproto, 0)
        
        # Match against Scapy flows
        pkt_data = packet_flows.get((src, dst, sport, dport, proto_id), {})
        
        # Fallback to Zeek durations/bytes if Scapy missed it
        dur = pkt_data.get("dur") if pkt_data.get("dur") else zf.get("dur", 0.0)
        spkts = pkt_data.get("spkts", zf.get("spkts", 0))
        dpkts = pkt_data.get("dpkts", zf.get("dpkts", 0))
        sbytes = pkt_data.get("sbytes", zf.get("sbytes", 0))
        dbytes = pkt_data.get("dbytes", zf.get("dbytes", 0))
        
        smean = sbytes / spkts if spkts > 0 else 0
        dmean = dbytes / dpkts if dpkts > 0 else 0
        rate = (spkts + dpkts) / dur if dur > 0 else 0.0
        sload = (sbytes * 8) / dur if dur > 0 else 0.0
        dload = (dbytes * 8) / dur if dur > 0 else 0.0
        
        is_sm_ips_ports = 1 if (src == dst and sport == dport) else 0
        
        # Build base dictionary
        flow = {
            # Metadata for tracker
            "src": src, "dst": dst, "sport": sport, "dport": dport,
            "last_time": pkt_data.get("last_time", 0.0),
            
            # Features
            "dur": dur, "proto": zf.get("proto", "-"), "service": zf.get("service", "-"), "state": zf.get("state", "-"),
            "spkts": spkts, "dpkts": dpkts, "sbytes": sbytes, "dbytes": dbytes,
            "rate": rate, "sttl": pkt_data.get("sttl", 0), "dttl": pkt_data.get("dttl", 0),
            "sload": sload, "dload": dload, "sloss": pkt_data.get("sloss", 0), "dloss": pkt_data.get("dloss", 0),
            "sinpkt": pkt_data.get("sinpkt", 0.0), "dinpkt": pkt_data.get("dinpkt", 0.0),
            "sjit": pkt_data.get("sjit", 0.0), "djit": pkt_data.get("djit", 0.0),
            "swin": pkt_data.get("swin", 0), "dwin": pkt_data.get("dwin", 0),
            "tcprtt": pkt_data.get("tcprtt", 0.0), "synack": pkt_data.get("synack", 0.0), "ackdat": pkt_data.get("ackdat", 0.0),
            "smean": int(smean), "dmean": int(dmean),
            "trans_depth": zf.get("trans_depth", 0), "response_body_len": zf.get("response_body_len", 0),
            "is_ftp_login": zf.get("is_ftp_login", 0), "ct_ftp_cmd": zf.get("ct_ftp_cmd", 0),
            "ct_flw_http_mthd": zf.get("ct_flw_http_mthd", 0), "is_sm_ips_ports": is_sm_ips_ports
        }
        merged.append(flow)
        
    # Run through State Tracker
    tracker = UNSWStateTracker()
    tracked_flows = tracker.process_flows(merged)
    
    # Finalize 40-feature array
    final_output = []
    for f in tracked_flows:
        # Assertions
        missing = [x for x in EXPECTED_FEATURES if x not in f]
        if missing:
            raise ValueError(f"Missing features: {missing}")
            
        for k, v in f.items():
            if k in EXPECTED_FEATURES and isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                f[k] = 0.0
                
        final = {k: f[k] for k in EXPECTED_FEATURES}
        
        # Keep metadata for downstream
        final["src_ip"] = f["src"]
        final["dst_ip"] = f["dst"]
        final["src_port"] = f["sport"]
        final["dst_port"] = f["dport"]
        final["protocol"] = f.get("proto")
        final["timestamp"] = f.get("last_time")
        
        assert len([k for k in final.keys() if k in EXPECTED_FEATURES]) == 40
        final_output.append(final)
        
    logger.info(f"UNSW FEATURE VALIDATION: Feature count: 40/40. Successfully generated {len(final_output)} records.")
    return final_output
