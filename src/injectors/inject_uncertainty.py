import argparse
from pathlib import Path
import numpy as np
import pandas as pd


def inject_packet_loss(df: pd.DataFrame, loss_rate: float, rng: np.random.Generator) -> pd.DataFrame:
    """
    Randomly removes rows to simulate packet loss.
    loss_rate = percentage of packets to drop (0.1 = 10%).
    """
    keep_mask = rng.random(len(df)) > loss_rate
    return df.loc[keep_mask].reset_index(drop=True)


def inject_length_noise(df: pd.DataFrame, noise_std: float, rng: np.random.Generator) -> pd.DataFrame:
    """
    Adds Gaussian noise to the length column.
    """
    if noise_std <= 0:
        return df

    noisy = df.copy()
    noise = rng.normal(loc=0.0, scale=noise_std, size=len(noisy))
    noisy["length"] = (noisy["length"] + noise).clip(lower=0)
    return noisy


def parse_float_list(raw: str) -> list[float]:
    return [float(item.strip()) for item in raw.split(",") if item.strip()]


def main():
    parser = argparse.ArgumentParser(description="Inject packet loss and noise into baseline data.")
    parser.add_argument("--input", default="data/processed/baseline.csv")
    parser.add_argument("--out-dir", default="data/corrupted")
    parser.add_argument("--loss-rates", default="0.1,0.3,0.5")
    parser.add_argument("--noise-stds", default="0.1,0.3,0.5")
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args()

    input_path = Path(args.input)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    loss_rates = parse_float_list(args.loss_rates)
    noise_stds = parse_float_list(args.noise_stds)

    df = pd.read_csv(input_path)
    rng = np.random.default_rng(args.seed)

    print(f"Original rows: {len(df)}")

    for loss_rate in loss_rates:
        for noise_std in noise_stds:
            corrupted = inject_packet_loss(df, loss_rate=loss_rate, rng=rng)
            corrupted = inject_length_noise(corrupted, noise_std=noise_std, rng=rng)

            loss_label = f"{int(round(loss_rate * 100))}pct"
            if noise_std > 0:
                noise_label = f"_noise{noise_std}"
            else:
                noise_label = ""

            out_name = f"corrupted_{loss_label}{noise_label}.csv"
            out_path = out_dir / out_name
            corrupted.to_csv(out_path, index=False)

            print(f"Saved: {out_path} (rows={len(corrupted)})")


if __name__ == "__main__":
    main()