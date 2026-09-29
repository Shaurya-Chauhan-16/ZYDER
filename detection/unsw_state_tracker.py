import collections
from typing import Dict, List, Any

class UNSWStateTracker:
    """
    Implements the 100-connection sliding window described by the UNSW-NB15 methodology.
    The window includes the current connection, so counts evaluate to at least 1 
    for self-matching criteria.
    """
    def __init__(self):
        # We store up to 99 previous connections. When combined with the current connection,
        # the effective window size is exactly 100.
        self.history = collections.deque(maxlen=99)
        
    def process_flows(self, flows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        # Order flows by last time to properly replicate the sliding window sequence
        sorted_flows = sorted(flows, key=lambda f: f.get("last_time", 0.0))
        
        for flow in sorted_flows:
            src = flow.get("src")
            dst = flow.get("dst")
            sport = flow.get("sport")
            dport = flow.get("dport")
            service = flow.get("service")
            state = flow.get("state")
            sttl = flow.get("sttl")
            dttl = flow.get("dttl")
            
            is_http = 1 if service and service.lower() == "http" else 0
            has_http_mthd = flow.get("ct_flw_http_mthd", 0) > 0
            has_ftp_cmd = flow.get("ct_ftp_cmd", 0) > 0
            
            # The current connection matches its own attributes (N=1)
            c_srv_src = 1
            c_dst_ltm = 1
            c_src_dport_ltm = 1
            c_dst_sport_ltm = 1
            c_dst_src_ltm = 1
            c_src_ltm = 1
            c_srv_dst = 1
            c_state_ttl = 1
            
            for h in self.history:
                if h["service"] == service and h["src"] == src: c_srv_src += 1
                if h["dst"] == dst: c_dst_ltm += 1
                if h["src"] == src and h["dport"] == dport: c_src_dport_ltm += 1
                if h["dst"] == dst and h["sport"] == sport: c_dst_sport_ltm += 1
                if h["src"] == src and h["dst"] == dst: c_dst_src_ltm += 1
                if h["src"] == src: c_src_ltm += 1
                if h["service"] == service and h["dst"] == dst: c_srv_dst += 1
                if h["state"] == state and h["sttl"] == sttl and h["dttl"] == dttl: c_state_ttl += 1
                
            flow["ct_srv_src"] = c_srv_src
            flow["ct_dst_ltm"] = c_dst_ltm
            flow["ct_src_dport_ltm"] = c_src_dport_ltm
            flow["ct_dst_sport_ltm"] = c_dst_sport_ltm
            flow["ct_dst_src_ltm"] = c_dst_src_ltm
            flow["ct_src_ltm"] = c_src_ltm
            flow["ct_srv_dst"] = c_srv_dst
            flow["ct_state_ttl"] = c_state_ttl
            
            # Add self to history (pushes oldest out if len > 99)
            self.history.append({
                "src": src, "dst": dst, "sport": sport, "dport": dport, 
                "service": service, "state": state, "sttl": sttl, "dttl": dttl,
                "is_http": is_http, "has_http_mthd": has_http_mthd, "has_ftp_cmd": has_ftp_cmd
            })
            
        return sorted_flows
