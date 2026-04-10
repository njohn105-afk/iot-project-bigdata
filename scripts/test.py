from scapy.all import PcapReader
from scapy.layers.inet import IP, TCP


count = 0

# Other packet fields that may be useful later
# packet.time -> timestamp (unix) | useful for building time windows
# len(packet) -> packet length | total packet size in bytes
# Todo: output to csv



with PcapReader("data/day1_only.pcap") as packets:
    for packet in packets:
        count+=1
        print(packet);
        if count == 10:
            break

print("Test complete")
