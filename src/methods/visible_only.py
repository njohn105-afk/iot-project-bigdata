
from pathlib import Path
import pandas as pd







def perform_visible_only(df) -> pd.DataFrame:
    """
    Baseline method: Outputs a copy of the corrupted dataset (no change)
    """

    return df.copy()









