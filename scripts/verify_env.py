import logging
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(Path("logs/env_verification.log")),
        logging.StreamHandler(sys.stdout),
    ],
)

deps = {
    "pandas": "2.0.3",
    "numpy": "1.24.4",
    "sklearn": "1.3.2",
    "xgboost": "1.7.6",
    "streamlit": "1.30.0",
    "matplotlib": "3.7.4",
    "seaborn": "0.12.2",
    "joblib": "1.3.2",
    "imblearn": "0.11.0",
    "ryu": None,
}

all_ok = True
for mod_name, expected_version in deps.items():
    try:
        mod = __import__(mod_name)
        actual = getattr(mod, "__version__", "unknown")
        if expected_version is not None:
            status = "OK" if actual == expected_version else f"MISMATCH (expected {expected_version})"
        else:
            status = "OK"
        logging.info(f"{mod_name:20s} {actual:12s} [{status}]")
        if "MISMATCH" in status:
            all_ok = False
    except ImportError as e:
        logging.error(f"{mod_name:20s} NOT INSTALLED [{e}]")
        all_ok = False

if all_ok:
    logging.info("All dependencies verified successfully.")
else:
    logging.error("Some dependencies are missing or have wrong versions.")
    sys.exit(1)
