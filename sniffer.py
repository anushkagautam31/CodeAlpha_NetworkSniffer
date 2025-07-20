from scapy.all import sniff, IP
from datetime import datetime

# Add more protocol names
protocol_names = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    50: "ESP",
    51: "AH"
}

def process_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto_num = packet[IP].proto
        proto_name = protocol_names.get(proto_num, f"Unknown({proto_num})")
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] {src_ip} → {dst_ip} | Protocol: {proto_name}")

print("Sniffing packets... (Make network activity)")
sniff(count=10, prn=process_packet)

