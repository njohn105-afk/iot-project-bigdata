import pandas as pd
import random


def inject_packet_loss(df, loss_rate=0.1):
    """
    Randomly removes rows to simulate packet loss
    loss_rate = percentage of packets to drop (0.1 = 10%)
    """
    keep_mask = [random.random() > loss_rate for _ in range(len(df))]
    return df[keep_mask].reset_index(drop=True)


def main():
    input_path = "data/processed/baseline.csv"
    output_path = "data/corrupted/corrupted_10pct.csv"

    df = pd.read_csv(input_path)

    print(f"Original rows: {len(df)}")

    corrupted_df = inject_packet_loss(df, loss_rate=0.1)

    print(f"After packet loss: {len(corrupted_df)}")

    corrupted_df.to_csv(output_path, index=False)

    print(f"Saved corrupted dataset to: {output_path}")


if __name__ == "__main__":
    main()