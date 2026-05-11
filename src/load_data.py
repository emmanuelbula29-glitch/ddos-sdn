"""
Phase 2 — Dataset Download and Loading
=======================================
Loads all CIC-DDoS2019 Parquet files from data/, concatenates into a single
DataFrame, normalises labels, and saves the combined raw CSV.

Author: B.Sc. Software Engineering Project
Project: Adaptive ML-based DDoS Detection and Mitigation System with SDN
"""

import logging
import sys
from pathlib import Path

import pandas as pd

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
        logging.FileHandler(LOG_DIR / "data_loading.log", mode="w"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger(__name__)

DATA_DIR = PROJECT_ROOT / "data"
RAW_COMBINED_PATH = DATA_DIR / "raw_combined.csv"

# ---------------------------------------------------------------------------
# Label normalisation mapping
# ---------------------------------------------------------------------------
# CIC-DDoS2019 labels vary across files.  Normalise attack names while
# keeping "Benign" unchanged.
LABEL_MAP = {
    "Benign": "Benign",
    "LDAP": "DrDoS_LDAP",
    "MSSQL": "DrDoS_MSSQL",
    "UDP": "DrDoS_UDP",
    "UDP-lag": "DrDoS_UDP",
    "Syn": "DoS_Syn",
    "Portmap": "Portmap",
    "NetBIOS": "DrDoS_NetBIOS",
    "NTP": "DrDoS_NTP",
    "DNS": "DrDoS_DNS",
    "SNMP": "DrDoS_SNMP",
    "TFTP": "DrDoS_TFTP",
    "WebDDoS": "WebDDoS",
}


def normalise_label(label: str) -> str:
    """Return a canonical label, mapping variant names to the unified form."""
    stripped = label.strip()
    return LABEL_MAP.get(stripped, stripped)


def load_all_parquet(data_dir: Path) -> pd.DataFrame:
    """
    Load every *.parquet file in *data_dir*, concatenate, and return
    a single DataFrame with normalised labels.
    """
    parquet_files = sorted(data_dir.glob("*.parquet"))
    if not parquet_files:
        logger.error(f"No Parquet files found in {data_dir}")
        raise FileNotFoundError(f"No .parquet files in {data_dir}")

    logger.info(f"Found {len(parquet_files)} Parquet file(s) in {data_dir}")

    frames = []
    for pq_file in parquet_files:
        logger.info(f"Loading {pq_file.name} ...")
        try:
            df = pd.read_parquet(pq_file)
            logger.info(f"  -> {df.shape[0]:,} rows, {df.shape[1]} columns")
            frames.append(df)
        except Exception as e:
            logger.error(f"  -> Failed to read {pq_file.name}: {e}")
            raise

    combined = pd.concat(frames, ignore_index=True)
    logger.info(
        f"Combined DataFrame: {combined.shape[0]:,} rows × {combined.shape[1]} columns"
    )

    # Normalise label column
    label_col = combined.columns[-1]
    logger.info(f"Label column detected: '{label_col}'")
    combined[label_col] = combined[label_col].apply(normalise_label)

    return combined


def main():
    """Main entry point for Phase 2."""
    logger.info("=" * 70)
    logger.info("PHASE 2 — Dataset Loading (Parquet -> CSV)")
    logger.info("=" * 70)

    combined_df = load_all_parquet(DATA_DIR)

    # -----------------------------------------------------------------------
    # Save combined CSV
    # -----------------------------------------------------------------------
    combined_df.to_csv(RAW_COMBINED_PATH, index=False)
    logger.info(f"Saved raw combined data to {RAW_COMBINED_PATH}")
    logger.info(f"Final shape: {combined_df.shape[0]:,} rows × {combined_df.shape[1]} columns")

    # -----------------------------------------------------------------------
    # Class distribution
    # -----------------------------------------------------------------------
    label_col = combined_df.columns[-1]
    dist = combined_df[label_col].value_counts()
    logger.info(f"Class distribution ({len(dist)} classes):")
    for label, count in dist.items():
        pct = count / len(combined_df) * 100
        logger.info(f"  {label:20s}: {count:>8,}  ({pct:.2f}%)")

    logger.info("PHASE 2 COMPLETE")


if __name__ == "__main__":
    main()