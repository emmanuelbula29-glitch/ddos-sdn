"""
Phase 3 — Data Preprocessing and Cleaning
==========================================
Loads data/raw_combined.csv, cleans it, encodes labels, and saves the
result to data/cleaned.csv along with models/label_encoder.joblib.

Author: B.Sc. Software Engineering Project
Project: Adaptive ML-based DDoS Detection and Mitigation System with SDN
"""

import logging
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOG_DIR = PROJECT_ROOT / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "preprocessing.log", mode="w"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger(__name__)

DATA_DIR = PROJECT_ROOT / "data"
MODELS_DIR = PROJECT_ROOT / "models"
MODELS_DIR.mkdir(parents=True, exist_ok=True)

RAW_PATH = DATA_DIR / "raw_combined.csv"
CLEANED_PATH = DATA_DIR / "cleaned.csv"
LABEL_ENCODER_PATH = MODELS_DIR / "label_encoder.joblib"


def preprocess(raw_path: Path, cleaned_path: Path, encoder_path: Path) -> pd.DataFrame:
    """Main preprocessing pipeline.  Returns the cleaned DataFrame."""

    # -----------------------------------------------------------------------
    # Step 1: Load data
    # -----------------------------------------------------------------------
    logger.info(f"Loading {raw_path}")
    df = pd.read_csv(raw_path, low_memory=False)
    original_count = len(df)
    logger.info(f"Original row count: {original_count:,}")

    # -----------------------------------------------------------------------
    # Step 2: Strip whitespace from column names
    # -----------------------------------------------------------------------
    df.columns = [col.strip() for col in df.columns]
    logger.info(f"Stripped whitespace from {len(df.columns)} column names")

    # -----------------------------------------------------------------------
    # Step 3: Replace inf / -inf with NaN
    # -----------------------------------------------------------------------
    inf_mask = np.isinf(df.select_dtypes(include=[np.number])).any(axis=1)
    inf_count = inf_mask.sum()
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    logger.info(f"Rows with inf/-inf values: {inf_count:,}")
    df.drop(df.index[inf_mask], inplace=True)
    df.reset_index(drop=True, inplace=True)

    # -----------------------------------------------------------------------
    # Step 4: Drop rows with NaN
    # -----------------------------------------------------------------------
    before_nan = len(df)
    nan_count = df.isna().any(axis=1).sum()
    df.dropna(inplace=True)
    df.reset_index(drop=True, inplace=True)
    after_nan = len(df)
    logger.info(f"Rows removed due to NaN: {nan_count:,}  (before={before_nan:,}, after={after_nan:,})")

    # -----------------------------------------------------------------------
    # Step 5: Drop duplicate rows
    # -----------------------------------------------------------------------
    before_dedup = len(df)
    dup_count = df.duplicated().sum()
    df.drop_duplicates(inplace=True)
    df.reset_index(drop=True, inplace=True)
    after_dedup = len(df)
    logger.info(f"Duplicate rows removed: {dup_count:,}  (before={before_dedup:,}, after={after_dedup:,})")

    # -----------------------------------------------------------------------
    # Step 6: Encode labels
    # -----------------------------------------------------------------------
    label_col = "Label"
    if label_col not in df.columns:
        # Try case-insensitive match
        for col in df.columns:
            if col.strip().lower() == "label":
                label_col = col
                break
        else:
            raise KeyError("No 'Label' column found in the data")

    le = LabelEncoder()
    df[label_col] = le.fit_transform(df[label_col].astype(str))
    logger.info(f"LabelEncoder fitted with {len(le.classes_)} classes:")
    for idx, cls in enumerate(le.classes_):
        logger.info(f"  {idx}: {cls}")

    # Save encoder
    import joblib
    joblib.dump(le, encoder_path)
    logger.info(f"Label encoder saved to {encoder_path}")

    # -----------------------------------------------------------------------
    # Step 7: Save cleaned DataFrame
    # -----------------------------------------------------------------------
    df.to_csv(cleaned_path, index=False)
    logger.info(f"Cleaned data saved to {cleaned_path}")
    logger.info(f"Final row count: {len(df):,}")

    # -----------------------------------------------------------------------
    # Step 8: Final class distribution
    # -----------------------------------------------------------------------
    dist = df[label_col].value_counts().sort_index()
    logger.info("Final class distribution (encoded):")
    for enc_val, count in dist.items():
        label = le.inverse_transform([enc_val])[0]
        logger.info(f"  {label:20s} (encoded={enc_val}): {count:>8,}")

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------
    logger.info("---")
    logger.info("SUMMARY")
    logger.info(f"  Original rows:           {original_count:>12,}")
    logger.info(f"  Rows removed (inf):      {inf_count:>12,}")
    logger.info(f"  Rows removed (NaN):      {nan_count:>12,}")
    logger.info(f"  Rows removed (duplicates):{dup_count:>12,}")
    logger.info(f"  Final rows:              {len(df):>12,}")

    return df


def main():
    logger.info("=" * 70)
    logger.info("PHASE 3 — Data Preprocessing and Cleaning")
    logger.info("=" * 70)
    df = preprocess(RAW_PATH, CLEANED_PATH, LABEL_ENCODER_PATH)
    logger.info("PHASE 3 COMPLETE")


if __name__ == "__main__":
    main()