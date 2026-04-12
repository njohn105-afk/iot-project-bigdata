import pandas as pd
import numpy as np

from statsmodels.tsa.holtwinters import ExponentialSmoothing




def apply_smoothing(
    windows_df: pd.DataFrame):
    """
	Exponential smoothing approach to accounting for missed data

	Input columns expected:
	- time_window
	- packet_count
	- avg_length

	"""
    df = windows_df.copy().sort_values("time_window").reset_index(drop=True)

    # packet_count series
    packet_model = ExponentialSmoothing(
        df["packet_count"].astype(float),
        trend=None,
        seasonal=None,
        initialization_method="estimated",
    )
    packet_fit = packet_model.fit(optimized=True)
    df["smooth_packet_count"] = packet_fit.fittedvalues

    # avg_length series
    avg_model = ExponentialSmoothing(
        df["avg_length"].astype(float),
        trend=None,
        seasonal=None,
        initialization_method="estimated",
    )
    avg_fit = avg_model.fit(optimized=True)
    df["smooth_avg_length"] = avg_fit.fittedvalues

    return df









    