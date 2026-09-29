import logging
from pathlib import Path
from scapy.all import PcapReader, IP, TCP, UDP
from typing import Dict, Any, List

logger = logging.getLogger("zyder.detection.unsw_packet")

def parse_pcap(pcap_path: str | Path) -> Dict[str, dict]:
    """
    Parses PCAP directly to extract packet-level timing, TCP, and TTL metrics
    required for UNSW-NB15 features.
    """
    flows = {}
    
    with PcapReader(str(pcap_path)) as pcap:
        for pkt in pcap:
            if IP not in pkt:
                continue
                
            ip_layer = pkt[IP]
            src = ip_layer.src
            dst = ip_layer.dst
            proto = ip_layer.proto
            
            sport, dport = 0, 0
            if TCP in pkt:
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
            elif UDP in pkt:
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
                
            # Create a directional tuple. To group bidirectional packets, 
            # we always key by the first seen direction.
            forward_tuple = (src, dst, sport, dport, proto)
            reverse_tuple = (dst, src, dport, sport, proto)
            
            is_forward = True
            flow_key = forward_tuple
            
            if reverse_tuple in flows:
                flow_key = reverse_tuple
                is_forward = False
            elif forward_tuple not in flows:
                flows[forward_tuple] = {
                    "src": src, "dst": dst, "sport": sport, "dport": dport, "proto_id": proto,
                    "s_pkts": [], "d_pkts": [],
                    "s_bytes": 0, "d_bytes": 0,
                    "sttl": ip_layer.ttl, "dttl": 0,
                    "swin": pkt[TCP].window if TCP in pkt else 0, "dwin": 0,
                    "s_seqs": set(), "d_seqs": set(),
                    "sloss": 0, "dloss": 0,
                    "syn_time": 0.0, "synack_time": 0.0, "ack_time": 0.0
                }
            
            flow = flows[flow_key]
            ts = float(pkt.time)
            length = len(pkt)
            
            if is_forward:
                flow["s_pkts"].append(ts)
                flow["s_bytes"] += length
                if TCP in pkt:
                    tcp_layer = pkt[TCP]
                    if tcp_layer.seq in flow["s_seqs"] and len(tcp_layer.payload) > 0:
                        flow["sloss"] += 1
                    flow["s_seqs"].add(tcp_layer.seq)
                    flags = tcp_layer.flags
                    if "S" in flags and "A" not in flags and flow["syn_time"] == 0.0:
                        flow["syn_time"] = ts
                    if "A" in flags and "S" not in flags and flow["synack_time"] > 0.0 and flow["ack_time"] == 0.0:
                        flow["ack_time"] = ts
            else:
                flow["d_pkts"].append(ts)
                flow["d_bytes"] += length
                if flow["dttl"] == 0: flow["dttl"] = ip_layer.ttl
                if TCP in pkt and flow["dwin"] == 0: flow["dwin"] = pkt[TCP].window
                
                if TCP in pkt:
                    tcp_layer = pkt[TCP]
                    if tcp_layer.seq in flow["d_seqs"] and len(tcp_layer.payload) > 0:
                        flow["dloss"] += 1
                    flow["d_seqs"].add(tcp_layer.seq)
                    flags = tcp_layer.flags
                    if "S" in flags and "A" in flags and flow["synack_time"] == 0.0:
                        flow["synack_time"] = ts
                        
    # Process derived metrics
    result = {}
    for k, flow in flows.items():
        s_pkts = flow["s_pkts"]
        d_pkts = flow["d_pkts"]
        
        # Inter-packet arrival time and Jitter (avg abs diff)
        def calc_timing(ts_list):
            if len(ts_list) < 2: return 0.0, 0.0
            diffs = [ts_list[i] - ts_list[i-1] for i in range(1, len(ts_list))]
            mean_diff = sum(diffs) / len(diffs)
            if len(diffs) < 2: return mean_diff * 1000.0, 0.0
            jitters = [abs(diffs[i] - diffs[i-1]) for i in range(1, len(diffs))]
            mean_jitter = sum(jitters) / len(jitters)
            return mean_diff * 1000.0, mean_jitter * 1000.0
            
        sinpkt, sjit = calc_timing(s_pkts)
        dinpkt, djit = calc_timing(d_pkts)
        
        synack = max(0.0, flow["synack_time"] - flow["syn_time"]) if flow["synack_time"] and flow["syn_time"] else 0.0
        ackdat = max(0.0, flow["ack_time"] - flow["synack_time"]) if flow["ack_time"] and flow["synack_time"] else 0.0
        tcprtt = synack + ackdat
        
        dur = max(s_pkts[-1] if s_pkts else 0.0, d_pkts[-1] if d_pkts else 0.0) - min(s_pkts[0] if s_pkts else 0.0, d_pkts[0] if d_pkts else 0.0)
        
        result[k] = {
            "dur": max(0.0, dur),
            "sttl": flow["sttl"], "dttl": flow["dttl"],
            "sloss": flow["sloss"], "dloss": flow["dloss"],
            "sinpkt": sinpkt, "dinpkt": dinpkt,
            "sjit": sjit, "djit": djit,
            "swin": flow["swin"], "dwin": flow["dwin"],
            "tcprtt": tcprtt, "synack": synack, "ackdat": ackdat,
            "spkts": len(s_pkts), "dpkts": len(d_pkts),
            "sbytes": flow["s_bytes"], "dbytes": flow["d_bytes"],
            "last_time": max(s_pkts[-1] if s_pkts else 0.0, d_pkts[-1] if d_pkts else 0.0)
        }
    return result
