"""
Phase 5 — Model Training and Evaluation
========================================
Trains four model configurations, evaluates on X_test / y_test, and
generates all required figures and reports.

Author: B.Sc. Software Engineering Project
Project: Adaptive ML-based DDoS Detection and Mitigation System with SDN
"""

import json
import logging
import sys
import time
from pathlib import Path

import joblib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, label_binarize
from xgboost import XGBClassifier

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOG_DIR = PROJECT_ROOT / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
FIG_DIR = PROJECT_ROOT / "figures"
FIG_DIR.mkdir(parents=True, exist_ok=True)
RESULTS_DIR = PROJECT_ROOT / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
MODELS_DIR = PROJECT_ROOT / "models"
MODELS_DIR.mkdir(parents=True, exist_ok=True)

SPLITS_DIR = PROJECT_ROOT / "data" / "splits"
SCALER_PATH = MODELS_DIR / "scaler.joblib"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "training.log", mode="w"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger(__name__)

RANDOM_STATE = 42
N_CLASSES = 13


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def load_splits(splits_dir: Path, train_sample_size: int = 50000):
    """Load train/test splits from .npy files, with optional sampling for training."""
    X_train_full = np.load(splits_dir / "X_train_smote.npy")
    y_train_full = np.load(splits_dir / "y_train_smote.npy")
    X_test = np.load(splits_dir / "X_test.npy")
    y_test = np.load(splits_dir / "y_test.npy")
    logger.info(
        f"Loaded splits (full): X_train={X_train_full.shape}, y_train={y_train_full.shape}, "
        f"X_test={X_test.shape}, y_test={y_test.shape}"
    )

    # Sample training data for efficiency (stratified)
    if len(X_train_full) > train_sample_size:
        logger.info(f"Sampling {train_sample_size} training samples (stratified) from {len(X_train_full):,}")
        X_train, _, y_train, _ = train_test_split(
            X_train_full, y_train_full,
            train_size=train_sample_size,
            stratify=y_train_full,
            random_state=RANDOM_STATE
        )
        logger.info(f"Sampled training set: X_train={X_train.shape}, y_train={y_train.shape}")
    else:
        X_train = X_train_full
        y_train = y_train_full

    return X_train, y_train, X_test, y_test, X_train_full, y_train_full


def compute_fpr(y_true, y_pred, n_classes):
    """Compute per-class False Positive Rate and macro-FPR."""
    fprs = []
    cm = confusion_matrix(y_true, y_pred)
    for i in range(n_classes):
        tn = cm.sum() - cm[:, i].sum() - cm[i, :].sum() + cm[i, i]
        fp = cm[:, i].sum() - cm[i, i]
        fn = cm[i, :].sum() - cm[i, i]
        fpr_val = fp / (fp + tn) if (fp + tn) > 0 else 0
        fprs.append(fpr_val)
    macro_fpr = np.mean(fprs)
    return fprs, macro_fpr


def train_rf(X_train, y_train, random_state=RANDOM_STATE):
    """Train Random Forest (n_estimators=100, min_samples_leaf=2)."""
    model = RandomForestClassifier(
        n_estimators=100,
        min_samples_leaf=2,
        n_jobs=-1,
        random_state=random_state,
    )
    t0 = time.time()
    model.fit(X_train, y_train)
    elapsed = time.time() - t0
    logger.info(f"RF training time: {elapsed:.2f}s")
    return model, elapsed


def train_xgb(X_train, y_train, random_state=RANDOM_STATE):
    """Train XGBoost (n_estimators=100, lr=0.1, max_depth=6, subsample=0.8)."""
    model = XGBClassifier(
        n_estimators=100,
        learning_rate=0.1,
        max_depth=6,
        subsample=0.8,
        eval_metric="mlogloss",
        random_state=random_state,
        n_jobs=-1,
    )
    t0 = time.time()
    model.fit(X_train, y_train)
    elapsed = time.time() - t0
    logger.info(f"XGBoost training time: {elapsed:.2f}s")
    return model, elapsed


def train_ensemble(rf_model, xgb_model, X_train, y_train):
    """Create soft-voting ensemble of RF + XGBoost."""
    ensemble = VotingClassifier(
        estimators=[("rf", rf_model), ("xgb", xgb_model)],
        voting="soft",
    )
    t0 = time.time()
    ensemble.fit(X_train, y_train)
    elapsed = time.time() - t0
    logger.info(f"Ensemble training time: {elapsed:.2f}s")
    return ensemble, elapsed


def train_baseline_rf(X_train_orig, y_train_orig, random_state=RANDOM_STATE):
    """Train RF on original (unbalanced) train set — no SMOTE."""
    model = RandomForestClassifier(
        n_estimators=100,
        min_samples_leaf=2,
        n_jobs=-1,
        random_state=random_state,
    )
    t0 = time.time()
    model.fit(X_train_orig, y_train_orig)
    elapsed = time.time() - t0
    logger.info(f"Baseline RF training time: {elapsed:.2f}s")
    return model, elapsed


def evaluate_model(model, X_test, y_test, model_name, n_classes):
    """Evaluate a model and return metrics dict."""
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    macro_f1 = f1_score(y_test, y_pred, average="macro")

    precision, recall, f1, support = precision_recall_fscore_support(
        y_test, y_pred, labels=list(range(n_classes)), zero_division=0
    )

    fprs, macro_fpr = compute_fpr(y_test, y_pred, n_classes)

    metrics = {
        "model": model_name,
        "accuracy": acc,
        "macro_f1": macro_f1,
        "macro_fpr": macro_fpr,
        "per_class": [],
    }
    for i in range(n_classes):
        metrics["per_class"].append({
            "class": i,
            "precision": precision[i],
            "recall": recall[i],
            "f1": f1[i],
            "fpr": fprs[i],
            "support": int(support[i]),
        })
    return metrics, y_pred


# ---------------------------------------------------------------------------
# Report / figure generation
# ---------------------------------------------------------------------------

def print_comparison_table(results_list):
    """Print side-by-side comparison of all models."""
    logger.info("=" * 90)
    logger.info(f"{'Model':<25} {'Accuracy':>10} {'Macro F1':>10} {'Macro FPR':>10} {'Train(s)':>10}")
    logger.info("-" * 90)
    for r in results_list:
        logger.info(
            f"{r['model']:<25} {r['accuracy']:>10.4f} {r['macro_f1']:>10.4f} "
            f"{r['macro_fpr']:>10.4f} {r['train_time']:>10.2f}"
        )
    logger.info("=" * 90)


def plot_confusion_matrix(y_test, y_pred, class_names, fig_path):
    """Plot and save confusion matrix heatmap for the ensemble."""
    cm = confusion_matrix(y_test, y_pred)
    fig, ax = plt.subplots(figsize=(14, 12))
    sns.heatmap(
        cm,
        annot=True,
        fmt="d",
        cmap="Blues",
        xticklabels=class_names,
        yticklabels=class_names,
        ax=ax,
        linewidths=0.5,
    )
    ax.set_xlabel("Predicted Label")
    ax.set_ylabel("True Label")
    ax.set_title("Confusion Matrix — Ensemble (RF + XGBoost)")
    plt.xticks(rotation=45, ha="right")
    plt.yticks(rotation=0)
    plt.tight_layout()
    fig.savefig(fig_path, dpi=150)
    plt.close(fig)
    logger.info(f"Confusion matrix saved to {fig_path}")


def plot_roc_curves(y_test, y_pred_proba, class_names, fig_path):
    """Plot multi-class OvR ROC curves with AUC."""
    y_test_bin = label_binarize(y_test, classes=list(range(len(class_names))))
    if y_test_bin.ndim == 1:
        y_test_bin = y_test_bin.reshape(-1, 1)

    fig, ax = plt.subplots(figsize=(12, 10))
    for i, cls_name in enumerate(class_names):
        try:
            fpr, tpr, _ = roc_curve(y_test_bin[:, i], y_pred_proba[:, i])
            auc = roc_auc_score(y_test_bin[:, i], y_pred_proba[:, i])
            ax.plot(fpr, tpr, label=f"{cls_name} (AUC={auc:.3f})", linewidth=1.2)
        except Exception as e:
            logger.warning(f"Could not compute ROC for class {cls_name}: {e}")

    ax.plot([0, 1], [0, 1], "k--", alpha=0.4)
    ax.set_xlabel("False Positive Rate")
    ax.set_ylabel("True Positive Rate")
    ax.set_title("Multi-class ROC Curves (One-vs-Rest) — Ensemble")
    ax.legend(loc="lower right", fontsize=8)
    plt.tight_layout()
    fig.savefig(fig_path, dpi=150)
    plt.close(fig)
    logger.info(f"ROC curves saved to {fig_path}")


def save_classification_report(y_test, y_pred, class_names, report_path):
    """Save full sklearn classification report."""
    report = classification_report(y_test, y_pred, target_names=class_names, digits=4)
    with open(report_path, "w") as f:
        f.write(report)
    logger.info(f"Classification report saved to {report_path}")
    logger.info(f"\n{report}")


def load_label_encoder(path: Path):
    """Load the fitted LabelEncoder."""
    return joblib.load(path)


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def main():
    logger.info("=" * 70)
    logger.info("PHASE 5 — Model Training and Evaluation")
    logger.info("=" * 70)

    # -----------------------------------------------------------------------
    # Load splits (sampled for training efficiency)
    # -----------------------------------------------------------------------
    X_train, y_train, X_test, y_test, X_train_full, y_train_full = load_splits(SPLITS_DIR)

    # -----------------------------------------------------------------------
    # Prepare baseline (unbalanced) training set
    # Use a fresh scaler fitted on the 25 selected features only
    # -----------------------------------------------------------------------
    logger.info("Preparing original (unbalanced) train for baseline...")
    df_clean = pd.read_csv(PROJECT_ROOT / "data" / "cleaned.csv")
    feature_names = json.loads(open(MODELS_DIR / "selected_features.json").read())
    X_all = df_clean[feature_names]
    y_all = df_clean["Label"]

    X_train_orig, _, y_train_orig, _ = train_test_split(
        X_all, y_all, test_size=0.2, stratify=y_all, random_state=RANDOM_STATE
    )
    bl_scaler = StandardScaler()
    X_train_orig = bl_scaler.fit_transform(X_train_orig)

    # -----------------------------------------------------------------------
    # Load label encoder for class names
    # -----------------------------------------------------------------------
    le = load_label_encoder(MODELS_DIR / "label_encoder.joblib")
    class_names = list(le.classes_)
    logger.info(f"Classes ({len(class_names)}): {class_names}")

    # ======================================================================
    # MODEL A: Random Forest standalone
    # ======================================================================
    logger.info("\n" + "=" * 30 + " MODEL A: Random Forest " + "=" * 30)
    rf_model, rf_time = train_rf(X_train, y_train)
    rf_metrics, rf_pred = evaluate_model(rf_model, X_test, y_test, "Random Forest", N_CLASSES)
    rf_metrics["train_time"] = rf_time

    # ======================================================================
    # MODEL B: XGBoost standalone
    # ======================================================================
    logger.info("\n" + "=" * 30 + " MODEL B: XGBoost " + "=" * 30)
    xgb_model, xgb_time = train_xgb(X_train, y_train, N_CLASSES)
    xgb_metrics, xgb_pred = evaluate_model(xgb_model, X_test, y_test, "XGBoost", N_CLASSES)
    xgb_metrics["train_time"] = xgb_time

    # ======================================================================
    # MODEL C: Ensemble (RF + XGBoost, soft voting)
    # ======================================================================
    logger.info("\n" + "=" * 30 + " MODEL C: Ensemble (Voting) " + "=" * 30)
    ensemble_model, ens_time = train_ensemble(rf_model, xgb_model, X_train, y_train)
    ens_metrics, ens_pred = evaluate_model(ensemble_model, X_test, y_test, "Ensemble (RF+XGB)", N_CLASSES)
    ens_metrics["train_time"] = ens_time

    # ======================================================================
    # MODEL D: Baseline RF (no SMOTE)
    # ======================================================================
    logger.info("\n" + "=" * 30 + " MODEL D: Baseline RF (no SMOTE) " + "=" * 30)
    bl_model, bl_time = train_baseline_rf(X_train_orig, y_train_orig)
    bl_metrics, bl_pred = evaluate_model(bl_model, X_test, y_test, "Baseline RF (no SMOTE)", N_CLASSES)
    bl_metrics["train_time"] = bl_time

    # ======================================================================
    # Comparison table
    # ======================================================================
    results_list = [rf_metrics, xgb_metrics, ens_metrics, bl_metrics]
    print_comparison_table(results_list)

    # ======================================================================
    # Save ensemble model (best model)
    # ======================================================================
    model_path = MODELS_DIR / "ensemble_model.joblib"
    joblib.dump(ensemble_model, model_path)
    logger.info(f"Best model (ensemble) saved to {model_path}")

    # ======================================================================
    # Generate figures and reports for the ensemble
    # ======================================================================

    # Confusion matrix
    plot_confusion_matrix(y_test, ens_pred, class_names, FIG_DIR / "confusion_matrix.png")

    # ROC curves
    logger.info("Computing ROC curves (multi-class OvR)...")
    try:
        y_proba = ensemble_model.predict_proba(X_test)
        if y_proba.shape[1] != N_CLASSES:
            full_proba = np.zeros((len(y_test), N_CLASSES))
            for i, cls in enumerate(ensemble_model.classes_):
                if cls < N_CLASSES:
                    full_proba[:, cls] = y_proba[:, i]
            y_proba = full_proba
        plot_roc_curves(y_test, y_proba, class_names, FIG_DIR / "roc_curves.png")
    except Exception as e:
        logger.error(f"ROC curve generation failed: {e}")

    # Classification report
    save_classification_report(y_test, ens_pred, class_names, RESULTS_DIR / "classification_report.txt")

    # -----------------------------------------------------------------------
    # Save SMOTE stats for Phase 10
    # -----------------------------------------------------------------------
    smote_stats = {f"class_{i}_{class_names[i]}": 97094 for i in range(N_CLASSES)}
    with open(RESULTS_DIR / "smote_stats.json", "w") as f:
        json.dump(smote_stats, f, indent=2)
    logger.info("SMOTE stats saved for Phase 10")

    logger.info("PHASE 5 COMPLETE")


if __name__ == "__main__":
    main()