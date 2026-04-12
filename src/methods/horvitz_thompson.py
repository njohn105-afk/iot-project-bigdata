import pandas as pd
import numpy as np

from statsmodels.tsa.holtwinters import ExponentialSmoothing


def apply_horvitz(
        windows_df: pd.DataFrame,
        p_observed: float = 0.9,

        
        ):
        df = windows_df.copy().sort_values("time_window").reset_index(drop=True)

        
        df["final_packet_count"] = df["packet_count"].astype(float) / p_observed

        # Round final packet counts
        df["final_packet_count"] = df["final_packet_count"].round()

        if "avg_length" in df.columns:
            df["final_avg_length"] = df["avg_length"].astype(float)

        return df

