"""
Phase 4 — Feature Selection and SMOTE Resampling
==================================================
Loads cleaned data, selects top-25 features via RandomForest importance,
applies SMOTE to the training set only, and saves all splits.

Author: B.Sc. Software Engineering Project
Project: Adaptive ML-based DDoS Detection and Mitigation System with SDN
"""

import json
import logging
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from imblearn.over_sampling import SMOTE
from sklearn.feature_selection import VarianceThreshold
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOG_DIR = PROJECT_ROOT / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
FIG_DIR = PROJECT_ROOT / "figures"
FIG_DIR.mkdir(parents=True, exist_ok=True)
SPLITS_DIR = PROJECT_ROOT / "data" / "splits"
SPLITS_DIR.mkdir(parents=True, exist_ok=True)
MODELS_DIR = PROJECT_ROOT / "models"
MODELS_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "feature_selection.log", mode="w"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger(__name__)

CLEANED_PATH = PROJECT_ROOT / "data" / "cleaned.csv"
FEATURES_JSON = MODELS_DIR / "selected_features.json"
SCALER_PATH = MODELS_DIR / "scaler.joblib"


def load_cleaned(path: Path) -> pd.DataFrame:
    """Load the cleaned dataset."""
    logger.info(f"Loading cleaned data from {path}")
    df = pd.read_csv(path)
    logger.info(f"Loaded {df.shape[0]:,} rows × {df.shape[1]} columns")
    return df


def apply_variance_threshold(df: pd.DataFrame, threshold: float = 0.0) -> pd.DataFrame:
    """Drop zero-variance features."""
    feature_cols = [c for c in df.columns if c != "Label"]
    selector = VarianceThreshold(threshold=threshold)
    selector.fit(df[feature_cols])
    kept = [f for f, m in zip(feature_cols, selector.get_support()) if m]
    dropped = [f for f, m in zip(feature_cols, selector.get_support()) if not m]
    if dropped:
        logger.info(f"VarianceThreshold dropped {len(dropped)} feature(s): {dropped}")
    else:
        logger.info("VarianceThreshold: no features dropped (all have variance > 0)")
    return df[kept + ["Label"]], kept


def stratified_split(df: pd.DataFrame, test_size: float = 0.2, random_state: int = 42):
    """Split features and labels into stratified train / test sets."""
    X = df.drop(columns=["Label"])
    y = df["Label"]
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, stratify=y, random_state=random_state
    )
    logger.info(f"Train set: {len(X_train):,} samples  |  Test set: {len(X_test):,} samples")
    return X_train, X_test, y_train, y_test


def scale_features(X_train: pd.DataFrame, X_test: pd.DataFrame, scaler_path: Path):
    """Fit StandardScaler on train, transform both.  Save the scaler."""
    import joblib

    scaler = StandardScaler()
    X_train_scaled = pd.DataFrame(
        scaler.fit_transform(X_train), columns=X_train.columns, index=X_train.index
    )
    X_test_scaled = pd.DataFrame(
        scaler.transform(X_test), columns=X_test.columns, index=X_test.index
    )
    joblib.dump(scaler, scaler_path)
    logger.info(f"Scaler saved to {scaler_path}")
    return X_train_scaled, X_test_scaled


def select_top_features(
    X_train: pd.DataFrame, y_train: pd.Series, top_k: int = 25, random_state: int = 42
):
    """Train a preliminary RandomForest on a 10% subsample and pick top-k features."""
    from sklearn.ensemble import RandomForestClassifier
    import joblib

    # Stratified 10% subsample for speed
    _, X_sub, _, y_sub = train_test_split(
        X_train, y_train, train_size=0.10, stratify=y_train, random_state=random_state
    )
    logger.info(f"Preliminary RF trained on {len(X_sub):,} samples (10% of train)")

    rf = RandomForestClassifier(
        n_estimators=200,
        min_samples_leaf=2,
        n_jobs=-1,
        random_state=random_state,
    )
    rf.fit(X_sub, y_sub)

    importances = rf.feature_importances_
    ranked = sorted(zip(X_train.columns, importances), key=lambda x: -x[1])

    top_features = [f for f, _ in ranked[:top_k]]
    scores = {f: float(s) for f, s in ranked[:top_k]}

    # Save selected features
    with open(FEATURES_JSON, "w") as fh:
        json.dump(top_features, fh, indent=2)
    logger.info(f"Top {top_k} features saved to {FEATURES_JSON}")

    # Print ranking table
    logger.info("Feature importance ranking (top 25):")
    logger.info(f"{'Rank':<5} {'Feature':<35} {'Score':>10}")
    logger.info("-" * 52)
    for rank, (feat, score) in enumerate(ranked[:top_k], 1):
        logger.info(f"{rank:<5} {feat:<35} {score:>10.6f}")

    # Plot
    plot_feature_importance(ranked[:top_k])

    return top_features, scores


def plot_feature_importance(ranked_features):
    """Save a horizontal bar chart of feature importances."""
    features, scores = zip(*ranked_features)
    fig, ax = plt.subplots(figsize=(10, 8))
    sns.barplot(x=list(scores), y=list(features), palette="viridis", ax=ax)
    ax.set_xlabel("Importance Score")
    ax.set_ylabel("Feature")
    ax.set_title("Top 25 Feature Importances (Preliminary RandomForest)")
    plt.tight_layout()
    fig.savefig(FIG_DIR / "feature_importance.png", dpi=150)
    plt.close(fig)
    logger.info(f"Feature importance plot saved to {FIG_DIR / 'feature_importance.png'}")


def apply_smote(X_train: pd.DataFrame, y_train: pd.Series):
    """Apply SMOTE(k_neighbors=5) to the training set only."""
    logger.info("Class distribution BEFORE SMOTE:")
    for label, count in y_train.value_counts().sort_index().items():
        logger.info(f"  class {label}: {count:,}")

    smote = SMOTE(k_neighbors=5, random_state=42)
    X_res, y_res = smote.fit_resample(X_train, y_train)

    logger.info("Class distribution AFTER SMOTE:")
    for label, count in pd.Series(y_res).value_counts().sort_index().items():
        logger.info(f"  class {label}: {count:,}")

    return X_res, y_res


def save_splits(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_test: np.ndarray,
    y_test: np.ndarray,
    out_dir: Path,
):
    """Save train/test splits as .npy files."""
    np.save(out_dir / "X_train_smote.npy", X_train)
    np.save(out_dir / "y_train_smote.npy", y_train)
    np.save(out_dir / "X_test.npy", X_test)
    np.save(out_dir / "y_test.npy", y_test)
    logger.info(f"Splits saved to {out_dir}")
    logger.info(f"  X_train_smote: {X_train.shape}")
    logger.info(f"  y_train_smote: {y_train.shape}")
    logger.info(f"  X_test:         {X_test.shape}")
    logger.info(f"  y_test:         {y_test.shape}")


def main():
    logger.info("=" * 70)
    logger.info("PHASE 4 — Feature Selection and SMOTE Resampling")
    logger.info("=" * 70)

    # -----------------------------------------------------------------------
    # Step 1: Load cleaned data
    # -----------------------------------------------------------------------
    df = load_cleaned(CLEANED_PATH)

    # -----------------------------------------------------------------------
    # Step 2: VarianceThreshold
    # -----------------------------------------------------------------------
    df, kept_cols = apply_variance_threshold(df, threshold=0.0)

    # -----------------------------------------------------------------------
    # Step 3: Stratified split (80/20)
    # -----------------------------------------------------------------------
    X_train, X_test, y_train, y_test = stratified_split(df)

    # -----------------------------------------------------------------------
    # Step 4: Scale features (StandardScaler fitted on train only)
    # -----------------------------------------------------------------------
    X_train, X_test = scale_features(X_train, X_test, SCALER_PATH)

    # -----------------------------------------------------------------------
    # Step 5: Feature selection via RF importance
    # -----------------------------------------------------------------------
    top_features, scores = select_top_features(X_train, y_train, top_k=25)
    X_train = X_train[top_features]
    X_test = X_test[top_features]

    # -----------------------------------------------------------------------
    # Step 6: SMOTE on training set only
    # -----------------------------------------------------------------------
    X_train_smote, y_train_smote = apply_smote(X_train, y_train)

    # -----------------------------------------------------------------------
    # Step 7: Save splits
    # -----------------------------------------------------------------------
    save_splits(
        X_train_smote.values,
        y_train_smote.values,
        X_test.values,
        y_test.values,
        SPLITS_DIR,
    )

    logger.info("PHASE 4 COMPLETE")


if __name__ == "__main__":
    main()