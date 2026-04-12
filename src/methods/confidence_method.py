import pandas as pd
import numpy as np


def apply_confidence_method(
	windows_df: pd.DataFrame,
	neighborhood: int = 2,
	loss_tolerance: float = 0.15,
	loss_gate_ratio: float = 0.6,
	length_tolerance: float = 0.2,
	min_active_loss_pct: float = 0.2,
	min_active_noise_pct: float = 0.2,
	min_expected_packets: float = 1.0,
	min_confidence: float = 0.1,
	min_length_confidence: float = 0.1,
	max_confidence: float = 1.0,
) -> pd.DataFrame:
	"""
	Confidence-weighted reconstruction for packet loss and length noise.

	Input columns expected:
	- time_window
	- packet_count
	- avg_length

	Output columns:
	- time_window
	- observed_packet_count
	- expected_packet_count
	- final_packet_count
	- observed_avg_length
	- expected_avg_length
	- final_avg_length
	- confidence
	- length_confidence
	"""
	required = {"time_window", "packet_count", "avg_length"}
	missing = required - set(windows_df.columns)
	if missing:
		raise ValueError(f"Missing required columns: {sorted(missing)}")

	df = windows_df.copy().sort_values("time_window").reset_index(drop=True)

	if df.empty:
		return pd.DataFrame(
			columns=[
				"time_window",
				"observed_packet_count",
				"expected_packet_count",
				"final_packet_count",
				"observed_avg_length",
				"expected_avg_length",
				"final_avg_length",
				"confidence",
				"length_confidence",
			]
		)

	if not 0 <= loss_tolerance < 1:
		raise ValueError("loss_tolerance must be in [0, 1).")
	if not 0 < loss_gate_ratio <= 1:
		raise ValueError("loss_gate_ratio must be in (0, 1].")
	if not 0 <= length_tolerance < 1:
		raise ValueError("length_tolerance must be in [0, 1).")
	if not 0 <= min_active_loss_pct <= 1:
		raise ValueError("min_active_loss_pct must be in [0, 1].")
	if not 0 <= min_active_noise_pct <= 1:
		raise ValueError("min_active_noise_pct must be in [0, 1].")

	df["observed_packet_count"] = df["packet_count"]
	df["observed_avg_length"] = df["avg_length"]

	counts = df["packet_count"].fillna(0)
	lengths = df["avg_length"]

	# Expected values from neighboring windows only (exclude current window).
	prev_counts = counts.shift(1).rolling(window=neighborhood, min_periods=1).median()
	next_counts = (
		counts[::-1].shift(1).rolling(window=neighborhood, min_periods=1).median()[::-1]
	)
	expected_counts = pd.concat([prev_counts, next_counts], axis=1).median(axis=1)

	prev_lengths = lengths.shift(1).rolling(window=neighborhood, min_periods=1).median()
	next_lengths = (
		lengths[::-1].shift(1).rolling(window=neighborhood, min_periods=1).median()[::-1]
	)
	expected_lengths = pd.concat([prev_lengths, next_lengths], axis=1).median(axis=1)

	expected_counts = expected_counts.fillna(counts.median())
	expected_lengths = expected_lengths.fillna(lengths.median())

	expected_safe = expected_counts.where(expected_counts >= min_expected_packets, np.nan)
	ratio = (counts / expected_safe).clip(lower=0.0, upper=1.0).fillna(1.0)

	# Treat small deviations as reliable; only correct when loss is substantial.
	confidence = np.where(
		ratio >= (1 - loss_tolerance),
		1.0,
		ratio / max(1e-6, (1 - loss_tolerance)),
	)
	confidence = np.nan_to_num(confidence, nan=1.0, posinf=1.0, neginf=min_confidence)
	confidence = np.clip(confidence, a_min=min_confidence, a_max=max_confidence)

	final_counts = confidence * counts + (1 - confidence) * expected_counts

	# Only apply corrections when loss is substantial and never reduce counts.
	loss_gate = ratio < loss_gate_ratio
	active_loss_pct = float(np.mean(loss_gate)) if len(loss_gate) else 0.0
	if active_loss_pct < min_active_loss_pct:
		confidence = np.ones(len(counts))
		final_counts = counts
	else:
		final_counts = np.where(loss_gate, final_counts, counts)
		final_counts = np.maximum(final_counts, counts)

	observed_lengths = lengths.fillna(expected_lengths)
	length_safe = expected_lengths.replace(0, np.nan)
	length_dev = ((observed_lengths - expected_lengths).abs() / length_safe).fillna(0)

	# Length confidence decreases as relative deviation grows beyond tolerance.
	active_noise_pct = float(np.mean(length_dev > length_tolerance)) if len(length_dev) else 0.0
	if active_noise_pct < min_active_noise_pct:
		length_confidence = np.ones(len(observed_lengths))
		final_lengths = observed_lengths
	else:
		length_confidence = np.where(
			length_dev <= length_tolerance,
			1.0,
			1 - (length_dev - length_tolerance) / max(1e-6, length_tolerance),
		)
		length_confidence = np.nan_to_num(
			length_confidence, nan=1.0, posinf=1.0, neginf=min_length_confidence
		)
		length_confidence = np.clip(
			length_confidence, a_min=min_length_confidence, a_max=max_confidence
		)

		final_lengths = (
			length_confidence * observed_lengths + (1 - length_confidence) * expected_lengths
		)

	df["expected_packet_count"] = expected_counts
	df["expected_avg_length"] = expected_lengths
	df["confidence"] = confidence
	df["length_confidence"] = length_confidence
	df["final_packet_count"] = final_counts
	df["final_avg_length"] = final_lengths

	return df[
		[
			"time_window",
			"observed_packet_count",
			"expected_packet_count",
			"final_packet_count",
			"observed_avg_length",
			"expected_avg_length",
			"final_avg_length",
			"confidence",
			"length_confidence",
		]
	]
