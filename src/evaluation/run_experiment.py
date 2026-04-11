from pathlib import Path
import pandas as pd


# =========================
# LOAD DATA
# =========================
def load_dataset(path: str) -> pd.DataFrame:
    df = pd.read_csv(path)
    return df


# =========================
# GLOBAL QUERIES
# =========================
def packet_count(df):
    return len(df)


def avg_packet_length(df):
    return df["length"].mean()


def protocol_distribution(df):
    return df["protocol"].value_counts(normalize=True)


# =========================
# TIME WINDOW QUERIES
# =========================
def add_time_window(df, window_size=1):
    df = df.copy()
    df["time_window"] = (df["timestamp"] // window_size).astype(int)
    return df


def packet_count_per_window(df):
    return df.groupby("time_window").size()


def avg_length_per_window(df):
    return df.groupby("time_window")["length"].mean()


# =========================
# ENDPOINT QUERIES
# =========================
def top_sources(df):
    return df["src_ip"].value_counts()


def top_destinations(df):
    return df["dst_ip"].value_counts()


# =========================
# MAIN EXPERIMENT
# =========================
def main():
    baseline_path = Path("data/processed/baseline.csv")
    corrupted_path = Path("data/corrupted/corrupted_10pct.csv")

    baseline = load_dataset(baseline_path)
    corrupted = load_dataset(corrupted_path)

    print("=== GLOBAL METRICS ===")
    print(f"Baseline count: {packet_count(baseline)}")
    print(f"Corrupted count: {packet_count(corrupted)}")

    print(f"Baseline avg length: {avg_packet_length(baseline):.2f}")
    print(f"Corrupted avg length: {avg_packet_length(corrupted):.2f}")

    print("\n=== PROTOCOL DISTRIBUTION ===")
    print("Baseline:")
    print(protocol_distribution(baseline))
    print("\nCorrupted:")
    print(protocol_distribution(corrupted))

    # =========================
    # TIME WINDOW ANALYSIS
    # =========================
    baseline_tw = add_time_window(baseline, window_size=1)
    corrupted_tw = add_time_window(corrupted, window_size=1)

    baseline_counts = packet_count_per_window(baseline_tw)
    corrupted_counts = packet_count_per_window(corrupted_tw)

    print("\n=== TIME WINDOW PACKET COUNTS ===")
    print("Baseline (first 10):")
    print(baseline_counts.head(10))
    print("\nCorrupted (first 10):")
    print(corrupted_counts.head(10))

    # =========================
    # ENDPOINT ANALYSIS
    # =========================
    print("\n=== TOP SOURCE IPS ===")
    print("Baseline:")
    print(top_sources(baseline).head())
    print("\nCorrupted:")
    print(top_sources(corrupted).head())

    print("\n=== TOP DESTINATION IPS ===")
    print("Baseline:")
    print(top_destinations(baseline).head())
    print("\nCorrupted:")
    print(top_destinations(corrupted).head())

    # =========================
    # SAVE RESULTS
    # =========================
    output_dir = Path("reports/figures")
    output_dir.mkdir(parents=True, exist_ok=True)

    baseline_counts.to_csv(output_dir / "baseline_time_counts.csv")
    corrupted_counts.to_csv(output_dir / "corrupted_time_counts.csv")

    print("\nSaved time window results to reports/figures/")


if __name__ == "__main__":
    main()