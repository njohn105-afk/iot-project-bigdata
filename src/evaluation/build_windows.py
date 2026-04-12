from pathlib import Path
import pandas as pd


def build_windows(df: pd.DataFrame, window_size: int = 1) -> pd.DataFrame:
    data = df.copy()

    if data.empty:
        return pd.DataFrame(columns=["time_window", "packet_count", "avg_length"])

    data["time_window"] = (data["timestamp"] // window_size).astype(int)

    windows = (
        data.groupby("time_window")
        .agg(
            packet_count=("packet_id", "count"),
            avg_length=("length", "mean"),
        )
        .reset_index()
    )

    return windows


def main():
    baseline_path = Path("data/processed/baseline.csv")
    baseline_out = Path("data/processed/baseline_windows.csv")

    baseline_df = pd.read_csv(baseline_path)

    baseline_windows = build_windows(baseline_df, window_size=1)
    baseline_windows.to_csv(baseline_out, index=False)

    corrupted_paths = sorted(
        path
        for path in Path("data/corrupted").glob("corrupted_*.csv")
        if not path.name.endswith("_windows.csv")
        and "windows" not in path.stem
    )
    corrupted_windows_paths = []

    for corrupted_path in corrupted_paths:
        corrupted_df = pd.read_csv(corrupted_path)
        if "timestamp" not in corrupted_df.columns:
            print(f"Skipping (no timestamp column): {corrupted_path}")
            continue
        corrupted_windows = build_windows(corrupted_df, window_size=1)
        corrupted_out = corrupted_path.with_name(f"{corrupted_path.stem}_windows.csv")
        corrupted_windows.to_csv(corrupted_out, index=False)
        corrupted_windows_paths.append(corrupted_out)

    print("Built window datasets.")
    print(f"Baseline windows saved to: {baseline_out}")
    for path in corrupted_windows_paths:
        print(f"Corrupted windows saved to: {path}")

    print()
    print("Baseline windows preview:")
    print(baseline_windows.head())
    if corrupted_windows_paths:
        preview_df = pd.read_csv(corrupted_windows_paths[0])
        print()
        print("Corrupted windows preview:")
        print(preview_df.head())


if __name__ == "__main__":
    main()