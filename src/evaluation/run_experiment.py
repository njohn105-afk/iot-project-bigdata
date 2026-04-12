import os
import sys
from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt

# METHODS
sys.path.append(os.path.abspath("src"))
from methods.visible_only import perform_visible_only
from methods.imputation import perform_imputation

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

def full_time(df):
    """
    Calculates elapsed time start->finish in seconds.
    """
     
    return df.iloc[-1]["timestamp"] - df.iloc[0]["timestamp"]

# =========================
# TIME WINDOW QUERIES
# =========================
def add_time_window(df, window_size=1):
    df = df.copy()
    
    t0 = df["timestamp"].min()
    df["elapsed"] = df["timestamp"] - t0
    
    # build windows on normalized time (start from 0)
    df["time_window"] = (df["elapsed"] // window_size).astype(int)
    
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
# HELPERS
# =========================

# Used for single value comparison
def similarity_score(a: float, b: float) -> float:
    """
    Computes similarity score in [0,1] between values a and b.
    """

    if a == 0 and b == 0:
        return 1.0
    if max(abs(a), abs(b)) == 0:
        return 1.0

    return max(0.0, 1.0 - abs(a - b) / max(abs(a), abs(b)))

# Used for multiple series value comparisons
def series_similarity(s1: pd.Series, s2: pd.Series) -> float:
    """
    Computes similarity score in [0,1] between series s1 and s2.
    """

    all_idx = s1.index.union(s2.index)
    s1 = s1.reindex(all_idx, fill_value=0).astype(float)
    s2 = s2.reindex(all_idx, fill_value=0).astype(float)

    denom = s1.abs().sum() + s2.abs().sum()
    if denom == 0:
        return 1.0

    l1 = (s1 - s2).abs().sum()
    return max(0.0, 1.0 - (l1 / denom))

# Can be used as a metric in determining the effectiveness of a method.
def accuracy_comparison(
        baseline_df: pd.DataFrame, 
        result_df: pd.DataFrame,
        weights: dict | None = None,

        ):
    """
    Computes a "similarity score" between a resulting dataframe and a given baseline dataframe.
    Weights by row_count, window_counts, protocol_dist, src_dist, dst_dist
    """

    if weights is None:
        weights = {
            "row_count": 0.20,
            "window_counts": 0.30,
            "protocol_dist": 0.20,
            "src_dist": 0.15,
            "dst_dist": 0.15,
        }

    scores = {}

    # Row count similarity
    scores["row_count"] = similarity_score(packet_count(baseline_df), packet_count(result_df))

    # Per-window packet counts similarity

    scores["window_counts"] = series_similarity(
        packet_count_per_window(baseline_df), 
        packet_count_per_window(result_df)
    )

    # Protocol distribution

    scores["protocol_dist"] = series_similarity(
        protocol_distribution(baseline_df),
        protocol_distribution(result_df),
    )

    # Src & Dst distribution

    scores["src_dist"] = series_similarity(
        top_sources(baseline_df),
        top_sources(result_df),
    )

    scores["dst_dist"] = series_similarity(
        top_destinations(baseline_df),
        top_destinations(result_df),
    )

    total_weight = sum(weights.values())
    if total_weight == 0:
        final_score = 0
    else:
        final_score = sum(scores[k] * weights[k] for k in scores) / total_weight

    similarity_percent = round(final_score * 100, 3)

    return similarity_percent, scores




# =========================
# MAIN EXPERIMENT
# =========================
def main():
    baseline_path = Path("data/processed/baseline.csv")
    corrupted_path = Path("data/corrupted/corrupted_10pct.csv")

    baseline = load_dataset(baseline_path)
    corrupted = load_dataset(corrupted_path)
    lost_packet_count = packet_count(baseline) - packet_count(corrupted)

    # Useful pre-experiment context & analysis
    print("=== BASELINE vs. CORRUPTED GLOBAL METRICS ===")

    print(f"""
    Baseline packet count: {packet_count(baseline)}
    Packets lost: {lost_packet_count} [{(lost_packet_count/packet_count(baseline) * 100):.2f}%]

    """)

    # Perform select operations on corrupted dataset
    # If needed, add time windows/other necessary values to dataset before performing
    baseline = add_time_window(baseline, window_size=1)
    result_df = add_time_window(corrupted, window_size=1)

    result_df = perform_visible_only(result_df)


    similarity_percent, scores = accuracy_comparison(
        baseline,
        result_df,
        None
    )

    print("=== QUERIES ON POST-METHOD DATASET ===")
    print(f"""
        Overall similarity score: {similarity_percent}%
        Similarity breakdown
        ----
        Row count: {scores["row_count"]*100}%
        Packet count per window: {scores["window_counts"]*100}%
        Protocol Distribution: {scores["protocol_dist"]*100}%
        Src Distribution: {scores["src_dist"]*100}%
        Dst Distribution: {scores["dst_dist"]*100}%
        
    """)

    print("Corrupted rows:", len(corrupted))
    print("Imputed rows:", len(result_df))
    print("Baseline rows:", len(baseline))

    print("Corrupted window counts head:")
    print(packet_count_per_window(add_time_window(corrupted, 1)).head(10))

    print("This method window counts head:")
    print(packet_count_per_window(result_df).head(10))

    print("Baseline window counts head:")
    print(packet_count_per_window(baseline).head(10))


    # =========================
    # SAVE RESULTS
    # =========================
    #output_dir = Path("reports/figures")
    #output_dir.mkdir(parents=True, exist_ok=True)

    #baseline_counts.to_csv(output_dir / "baseline_time_counts.csv")
    #corrupted_counts.to_csv(output_dir / "corrupted_time_counts.csv")

    print("\nSaved time window results to reports/figures/")


if __name__ == "__main__":
    main()