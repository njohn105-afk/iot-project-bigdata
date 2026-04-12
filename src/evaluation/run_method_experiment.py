from pathlib import Path
import pandas as pd
import os
import sys

sys.path.append(os.path.abspath("src"))

from methods.confidence_method import apply_confidence_method
import evaluation.metrics as m

def mae(series_a: pd.Series, series_b: pd.Series) -> float:
	aligned = pd.DataFrame({"a": series_a, "b": series_b}).fillna(0)
	return (aligned["a"] - aligned["b"]).abs().mean()


def tune_confidence_method(
	baseline: pd.DataFrame,
	corrupted: pd.DataFrame,
) -> tuple[dict, pd.DataFrame]:
	param_grid = []
	for neighborhood in [2, 3, 4, 5]:
		for loss_tolerance in [0.1, 0.2, 0.3]:
			for loss_gate_ratio in [0.5, 0.6, 0.7]:
				for length_tolerance in [0.1, 0.2, 0.3]:
					for min_confidence in [0.3, 0.4, 0.5, 0.7, 0.8]:
						for min_length_confidence in [0.3, 0.4, 0.5, 0.7, 0.8]:
							for min_expected_packets in [1.0, 2.0]:
								param_grid.append(
									{
										"neighborhood": neighborhood,
										"loss_tolerance": loss_tolerance,
										"loss_gate_ratio": loss_gate_ratio,
										"length_tolerance": length_tolerance,
										"min_active_loss_pct": 0.2,
										"min_active_noise_pct": 0.2,
										"min_confidence": min_confidence,
										"min_length_confidence": min_length_confidence,
										"min_expected_packets": min_expected_packets,
									}
								)

	results = []
	avg_length_scale = max(1e-6, baseline["avg_length"].median())
	for params in param_grid:
		method_df = apply_confidence_method(
			corrupted.reset_index(),
			**params,
		).set_index("time_window")

		method_df = method_df.reindex(baseline.index).fillna(0)

		method_count_mae = mae(baseline["packet_count"], method_df["final_packet_count"])
		method_avg_mae = mae(baseline["avg_length"], method_df["final_avg_length"])
		score = method_count_mae + (method_avg_mae / avg_length_scale)
		changed_windows = (
			method_df["final_packet_count"] != corrupted["packet_count"]
		).sum()

		results.append(
			{
				**params,
				"method_packet_count_mae": method_count_mae,
				"method_avg_length_mae": method_avg_mae,
				"combined_score": score,
				"mean_confidence": method_df["confidence"].mean(),
				"mean_length_confidence": method_df["length_confidence"].mean(),
				"min_confidence": method_df["confidence"].min(),
				"max_confidence": method_df["confidence"].max(),
				"changed_window_count": changed_windows,
				"changed_window_pct": (
					changed_windows / len(method_df)
					if len(method_df)
					else 0.0
				),
			}
		)

	results_df = pd.DataFrame(results)
	results_df = results_df.sort_values(
		["combined_score", "method_packet_count_mae", "changed_window_pct"],
		ascending=[True, True, True],
	)

	best_row = results_df.iloc[0]
	best_params = {
		"neighborhood": int(best_row["neighborhood"]),
		"loss_tolerance": float(best_row["loss_tolerance"]),
		"loss_gate_ratio": float(best_row["loss_gate_ratio"]),
		"length_tolerance": float(best_row["length_tolerance"]),
		"min_active_loss_pct": float(best_row["min_active_loss_pct"]),
		"min_active_noise_pct": float(best_row["min_active_noise_pct"]),
		"min_confidence": float(best_row["min_confidence"]),
		"min_length_confidence": float(best_row["min_length_confidence"]),
		"min_expected_packets": float(best_row["min_expected_packets"]),
	}

	return best_params, results_df


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

		best_params, tuning_results = tune_confidence_method(baseline, corrupted)
		method_df = apply_confidence_method(
			corrupted.reset_index(),
			**best_params,
		).set_index("time_window")
		method_df = method_df.reindex(baseline_windows).fillna(0)

		corrupted_count_mae = mae(baseline["packet_count"], corrupted["packet_count"])
		method_count_mae = mae(baseline["packet_count"], method_df["final_packet_count"])

		corrupted_avg_mae = mae(baseline["avg_length"], corrupted["avg_length"])
		method_avg_mae = mae(baseline["avg_length"], method_df["final_avg_length"])

		corrupted_similarity, corrupted_similarity_scores = m.window_accuracy_comparison(
			baseline,
			corrupted,
		)

		method_similarity, method_similarity_scores = m.window_accuracy_comparison(
            baseline[["packet_count", "avg_length"]],
			method_df.rename(columns={
				"final_packet_count": "packet_count",
				"final_avg_length": "avg_length",
			})[["packet_count", "avg_length"]],
		)

		dataset_name = corrupted_path.stem
		print(f"=== {dataset_name} ===")
		print(f"Corrupted packet-count MAE: {corrupted_count_mae:.4f}")
		print(f"Method packet-count MAE:    {method_count_mae:.4f}")
		print(f"Corrupted avg-length MAE:   {corrupted_avg_mae:.4f}")
		print(f"Method avg-length MAE:      {method_avg_mae:.4f}")
		print(f"Corrupted similarity score: {corrupted_similarity:.3f}%")
		print(f"Method similarity score:    {method_similarity:.3f}%")
		print("Best params:")
		print(best_params)
		print()

		comparison = pd.DataFrame(
			{
				"baseline_packet_count": baseline["packet_count"],
				"corrupted_packet_count": corrupted["packet_count"],
				"expected_packet_count": method_df["expected_packet_count"],
				"method_packet_count": method_df["final_packet_count"],
				"baseline_avg_length": baseline["avg_length"],
				"corrupted_avg_length": corrupted["avg_length"],
				"expected_avg_length": method_df["expected_avg_length"],
				"method_avg_length": method_df["final_avg_length"],
				"confidence": method_df["confidence"],
				"length_confidence": method_df["length_confidence"],
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

		comparison.to_csv(out_dir / f"{dataset_name}_method_comparison.csv")
		tuning_results.to_csv(out_dir / f"{dataset_name}_method_tuning.csv", index=False)

		changed_windows = (
			comparison["method_packet_count"] != comparison["corrupted_packet_count"]
		).sum()
		total_windows = len(comparison)

		summaries.append(
			{
				"dataset": dataset_name,
				"corrupted_packet_count_mae": corrupted_count_mae,
				"method_packet_count_mae": method_count_mae,
				"corrupted_avg_length_mae": corrupted_avg_mae,
				"method_avg_length_mae": method_avg_mae,
				"mean_confidence": method_df["confidence"].mean(),
				"mean_length_confidence": method_df["length_confidence"].mean(),
				"min_confidence": method_df["confidence"].min(),
				"max_confidence": method_df["confidence"].max(),
				"changed_window_count": changed_windows,
				"changed_window_pct": (changed_windows / total_windows) if total_windows else 0.0,
				"best_neighborhood": best_params["neighborhood"],
				"best_loss_tolerance": best_params["loss_tolerance"],
				"best_loss_gate_ratio": best_params["loss_gate_ratio"],
				"best_length_tolerance": best_params["length_tolerance"],
				"best_min_active_loss_pct": best_params["min_active_loss_pct"],
				"best_min_active_noise_pct": best_params["min_active_noise_pct"],
				"best_min_confidence": best_params["min_confidence"],
				"best_min_length_confidence": best_params["min_length_confidence"],
				"best_min_expected_packets": best_params["min_expected_packets"],
				"corrupted_similarity_score": corrupted_similarity,
                "method_similarity_score": method_similarity,
                "corrupted_row_count_similarity": corrupted_similarity_scores["row_count"],
                "corrupted_packet_count_similarity": corrupted_similarity_scores["packet_count"],
                "corrupted_avg_length_similarity": corrupted_similarity_scores["avg_length"],
                "method_row_count_similarity": method_similarity_scores["row_count"],
                "method_packet_count_similarity": method_similarity_scores["packet_count"],
                "method_avg_length_similarity": method_similarity_scores["avg_length"],
			}
		)

	summary_df = pd.DataFrame(summaries)
	summary_df.to_csv(out_dir / "window_method_summary.csv", index=False)

	print("Saved:")
	print("- reports/figures/window_method_summary.csv")
	print("- reports/figures/*_method_comparison.csv")
	print("- reports/figures/*_method_tuning.csv")


if __name__ == "__main__":
	main()
