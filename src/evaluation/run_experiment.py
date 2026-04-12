from pathlib import Path
import pandas as pd


def mae(series_a: pd.Series, series_b: pd.Series) -> float:
    aligned = pd.DataFrame({"a": series_a, "b": series_b}).fillna(0)
    return (aligned["a"] - aligned["b"]).abs().mean()


def main():
    baseline_path = Path("data/processed/baseline_windows.csv")
    baseline = pd.read_csv(baseline_path).set_index("time_window")

    corrupted_paths = sorted(Path("data/corrupted").glob("corrupted_*_windows.csv"))
    if not corrupted_paths:
        raise FileNotFoundError("No corrupted window datasets found in data/corrupted.")

    out_dir = Path("reports/figures")
    out_dir.mkdir(parents=True, exist_ok=True)

    summaries = []

    for corrupted_path in corrupted_paths:
        corrupted = pd.read_csv(corrupted_path).set_index("time_window")

        all_windows = sorted(set(baseline.index).union(set(corrupted.index)))
        baseline_aligned = baseline.reindex(all_windows).fillna(0)
        corrupted_aligned = corrupted.reindex(all_windows).fillna(0)

        count_mae = mae(
            baseline_aligned["packet_count"],
            corrupted_aligned["packet_count"],
        )
        avg_len_mae = mae(
            baseline_aligned["avg_length"],
            corrupted_aligned["avg_length"],
        )

        dataset_name = corrupted_path.stem
        print(f"=== {dataset_name} ===")
        print(f"Window count MAE: {count_mae:.4f}")
        print(f"Window avg-length MAE: {avg_len_mae:.4f}")

        comparison = pd.DataFrame(
            {
                "baseline_packet_count": baseline_aligned["packet_count"],
                "corrupted_packet_count": corrupted_aligned["packet_count"],
                "baseline_avg_length": baseline_aligned["avg_length"],
                "corrupted_avg_length": corrupted_aligned["avg_length"],
            }
        )
        comparison["count_abs_error"] = (
            comparison["baseline_packet_count"] - comparison["corrupted_packet_count"]
        ).abs()
        comparison["avg_length_abs_error"] = (
            comparison["baseline_avg_length"] - comparison["corrupted_avg_length"]
        ).abs()

        comparison.to_csv(out_dir / f"{dataset_name}_baseline_vs_corrupted.csv")

        summaries.append(
            {
                "dataset": dataset_name,
                "corrupted_packet_count_mae": count_mae,
                "corrupted_avg_length_mae": avg_len_mae,
            }
        )

    summary_df = pd.DataFrame(summaries)
    summary_df.to_csv(out_dir / "window_baseline_vs_corrupted.csv", index=False)
    print("Saved:")
    print("- reports/figures/window_baseline_vs_corrupted.csv")
    print("- reports/figures/*_baseline_vs_corrupted.csv")


if __name__ == "__main__":
    main()