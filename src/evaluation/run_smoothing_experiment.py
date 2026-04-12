from pathlib import Path
import pandas as pd
import os
import sys

sys.path.append(os.path.abspath("src"))


from methods.exponential_smoothing import apply_smoothing

def mae(series_a: pd.Series, series_b: pd.Series) -> float:
	aligned = pd.DataFrame({"a": series_a, "b": series_b}).fillna(0)
	return (aligned["a"] - aligned["b"]).abs().mean()


def main():
    baseline_path = Path("data/processed/baseline_windows.csv")

    baseline = pd.read_csv(baseline_path).set_index("time_window")

    corrupted_paths = sorted(Path("data/corrupted").glob("corrupted_*_windows.csv"))
    if not corrupted_paths:
        raise FileNotFoundError("No corrupted window datasets found in data/corrupted.")

    baseline_windows = baseline.index
    baseline = baseline.reindex(baseline_windows).fillna(0)

    out_dir = Path("reports/figures")
    out_dir.mkdir(parents=True, exist_ok=True)

    summaries = []

    for corrupted_path in corrupted_paths:
        corrupted = pd.read_csv(corrupted_path).set_index("time_window")
        corrupted = corrupted.reindex(baseline_windows).fillna(0)

        method_df = apply_smoothing(
            corrupted.reset_index()
        ).set_index("time_window")

        method_df = method_df.reindex(baseline_windows).fillna(0)

        corrupted_count_mae = mae(baseline["packet_count"], corrupted["packet_count"])
        corrupted_avg_mae = mae(baseline["avg_length"], corrupted["avg_length"])

        method_count_mae = mae(baseline["packet_count"], method_df["smooth_packet_count"])
        method_avg_mae = mae(baseline["avg_length"], method_df["smooth_avg_length"])

        dataset_name = corrupted_path.stem
        print(f"=== {dataset_name} ===")
        print(f"Corrupted packet-count MAE: {corrupted_count_mae:.4f}")
        print(f"Smoothing packet-count MAE: {method_count_mae:.4f}")
        print(f"Corrupted avg-length MAE:   {corrupted_avg_mae:.4f}")
        print(f"Smoothing avg-length MAE:   {method_avg_mae:.4f}")
        print()

        comparison = pd.DataFrame(
            {
                "baseline_packet_count": baseline["packet_count"],
                "corrupted_packet_count": corrupted["packet_count"],
                "method_packet_count": method_df["smooth_packet_count"],
                "baseline_avg_length": baseline["avg_length"],
                "corrupted_avg_length": corrupted["avg_length"],
                "method_avg_length": method_df["final_avg_length"],
            }
        )

        comparison["corrupted_count_abs_error"] = (
            comparison["baseline_packet_count"] - comparison["corrupted_packet_count"]
        ).abs()

        comparison["method_count_abs_error"] = (
            comparison["baseline_packet_count"] - comparison["method_packet_count"]
        ).abs()

        comparison["corrupted_avg_abs_error"] = (
            comparison["baseline_avg_length"] - comparison["corrupted_avg_length"]
        ).abs()

        comparison["method_avg_abs_error"] = (
            comparison["baseline_avg_length"] - comparison["method_avg_length"]
        ).abs()

        comparison.to_csv(out_dir / f"{dataset_name}_smoothing_comparison.csv")

        changed_windows = (
            comparison["method_packet_count"].round(6) != comparison["corrupted_packet_count"].round(6)
        ).sum()
        total_windows = len(comparison)

        summaries.append(
            {
                "dataset": dataset_name,
                "corrupted_packet_count_mae": corrupted_count_mae,
                "smoothing_packet_count_mae": method_count_mae,
                "corrupted_avg_length_mae": corrupted_avg_mae,
                "smoothing_avg_length_mae": method_avg_mae,
                "changed_window_count": changed_windows,
                "changed_window_pct": (changed_windows / total_windows) if total_windows else 0.0,
            }
        )

    summary_df = pd.DataFrame(summaries)
    summary_df.to_csv(out_dir / "window_smoothing_summary.csv", index=False)

    print("Saved:")
    print("- reports/figures/window_smoothing_summary.csv")
    print("- reports/figures/*_smoothing_comparison.csv")


if __name__ == "__main__":
    main()

