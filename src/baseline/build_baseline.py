from pathlib import Path
from scapy.all import rdpcap
import pandas as pd


def get_protocol_name(pkt) -> str:
    if pkt.haslayer("TCP"):
        return "TCP"
    if pkt.haslayer("UDP"):
        return "UDP"
    if pkt.haslayer("ICMP"):
        return "ICMP"
    return "OTHER"


def safe_ip(pkt, field: str):
    if pkt.haslayer("IP"):
        return getattr(pkt["IP"], field, None)
    return None


def build_baseline(pcap_path: str) -> pd.DataFrame:
    packets = rdpcap(pcap_path)
    rows = []

    print(len(packets))

    for i, pkt in enumerate(packets):
        try:
            rows.append(
                {
                    "packet_id": i,
                    "timestamp": float(pkt.time),
                    "length": len(pkt),
                    "src_ip": safe_ip(pkt, "src"),
                    "dst_ip": safe_ip(pkt, "dst"),
                    "protocol": get_protocol_name(pkt),
                }
            )
        except Exception:
            continue

    df = pd.DataFrame(rows)
    return df


def main():
    input_path = Path("data/raw/day1_only.pcap")
    output_path = Path("data/processed/baseline.csv")

    if not input_path.exists():
        raise FileNotFoundError(
            f"Could not find pcap file at {input_path}. "
            "Put your .pcap file in data/raw/ and rename it to sample.pcap, "
            "or update the path in this script."
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    df = build_baseline(str(input_path))
    df.to_csv(output_path, index=False)

    print("Baseline created successfully.")
    print(f"Rows: {len(df)}")
    print(f"Saved to: {output_path}")
    print(df.head())


if __name__ == "__main__":
    main()