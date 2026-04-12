from pathlib import Path
import pandas as pd




def similarity_score(a: float, b: float) -> float:
    """
    Computes similarity score in [0,1] between values a and b.
    """
    if a == 0 and b == 0:
        return 1.0
    if max(abs(a), abs(b)) == 0:
        return 1.0

    return max(0.0, 1.0 - abs(a - b) / max(abs(a), abs(b)))


def series_similarity(s1: pd.Series, s2: pd.Series, fill_value: float = 0.0) -> float:
    """
    Computes similarity score in [0,1] between aligned numeric series.
    """
    all_idx = s1.index.union(s2.index)
    s1 = s1.reindex(all_idx).fillna(fill_value).astype(float)
    s2 = s2.reindex(all_idx).fillna(fill_value).astype(float)

    denom = s1.abs().sum() + s2.abs().sum()
    if denom == 0:
        return 1.0

    l1 = (s1 - s2).abs().sum()
    return max(0.0, 1.0 - (l1 / denom))


def window_accuracy_comparison(
    baseline_df: pd.DataFrame,
    result_df: pd.DataFrame,
    weights: dict | None = None,
):
    """
    Computes a similarity score between two window dataframes.
    Uses packet_count and avg_length
    """
    if weights is None:
        weights = {
            "row_count": 0.15,
            "packet_count": 0.45,
            "avg_length": 0.40,
        }

    scores = {}

    # number of windows
    scores["row_count"] = similarity_score(len(baseline_df), len(result_df))

    # packet-count similarity
    scores["packet_count"] = series_similarity(
        baseline_df["packet_count"],
        result_df["packet_count"],
        fill_value=0.0,
    )
    # avg length similarity
    scores["avg_length"] = series_similarity(
        baseline_df["avg_length"],
        result_df["avg_length"],
        fill_value=0.0,
    )

    total_weight = sum(weights.values())
    if total_weight == 0:
        final_score = 0.0
    else:
        final_score = sum(scores[k] * weights[k] for k in scores) / total_weight

    similarity_percent = round(final_score * 100, 3)
    return similarity_percent, scores