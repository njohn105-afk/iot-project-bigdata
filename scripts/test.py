from scapy.all import PcapReader
from scapy.layers.inet import IP, TCP

print("starting")

count = 0

# Other packet fields that may be useful later

# packet.time -> timestamp (unix) | useful for building time windows
# len(packet) -> packet length | total packet size in bytes

# Todo: output to csv



with PcapReader("data/day1_only.pcap") as packets:
    for packet in packets:
        count+=1
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            print(f"Source IP: {src_ip}, Destination IP: {dst_ip}")

        if packet.haslayer(TCP):
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"TCP Packet - Source Port: {src_port}, Destination Port: {dst_port}")
        if count == 10:
            break 

print("Completed 1000 packets")
