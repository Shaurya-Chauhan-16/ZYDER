from scapy.all import IP, TCP, Raw, wrpcap
from pathlib import Path

OUT = Path("/tmp/zyder-multiflow")
OUT.mkdir(exist_ok=True)

attack_packets = []
benign_packets = []

# ---------------------------------------------------------
# ATTACK TRAFFIC
# TCP flows directed to port 445.
# These are controlled test flows for validating the
# ZYDER Suricata signature layer.
# ---------------------------------------------------------

for i in range(100):

    src_ip = f"10.10.{i // 250}.{(i % 250) + 1}"
    src_port = 40000 + i

    dst_ip = "192.168.1.1"
    dst_port = 445

    sport_seq = 100000 + i * 100

    # SYN
    attack_packets.append(
        IP(src=src_ip, dst=dst_ip) /
        TCP(
            sport=src_port,
            dport=dst_port,
            flags="S",
            seq=sport_seq
        )
    )

    # ACK + small payload
    attack_packets.append(
        IP(src=src_ip, dst=dst_ip) /
        TCP(
            sport=src_port,
            dport=dst_port,
            flags="PA",
            seq=sport_seq + 1,
            ack=1
        ) /
        Raw(load=b"ZYDER-CONTROLLED-TEST")
    )

# ---------------------------------------------------------
# BENIGN TRAFFIC
# TCP flows directed to port 8000.
# This port is not covered by the ZYDER SMB rule.
# ---------------------------------------------------------

for i in range(100):

    src_ip = f"127.0.0.1"
    src_port = 50000 + i

    dst_ip = "127.0.0.1"
    dst_port = 8000

    seq = 200000 + i * 100

    # SYN
    benign_packets.append(
        IP(src=src_ip, dst=dst_ip) /
        TCP(
            sport=src_port,
            dport=dst_port,
            flags="S",
            seq=seq
        )
    )

    # ACK + benign payload
    benign_packets.append(
        IP(src=src_ip, dst=dst_ip) /
        TCP(
            sport=src_port,
            dport=dst_port,
            flags="PA",
            seq=seq + 1,
            ack=1
        ) /
        Raw(load=b"ZYDER-BENIGN-TEST")
    )

attack_pcap = OUT / "zyder-100-attack.pcap"
benign_pcap = OUT / "zyder-100-benign.pcap"

wrpcap(str(attack_pcap), attack_packets)
wrpcap(str(benign_pcap), benign_packets)

print("=" * 60)
print("ZYDER MULTI-FLOW PCAP GENERATION")
print("=" * 60)
print(f"Attack PCAP : {attack_pcap}")
print("Attack flows: 100")
print(f"Benign PCAP : {benign_pcap}")
print("Benign flows: 100")
