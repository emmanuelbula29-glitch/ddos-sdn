You are building a complete, working implementation of an adaptive ML-based DDoS detection and mitigation system integrated with a Software Defined Network (SDN), as described in the project specification below. Follow every phase in strict order. Do not skip phases or proceed to the next until the current one is fully working and its outputs are logged.

---

SYSTEM CONTEXT:

- The project is a final-year B.Sc. Software Engineering project at Veritas University, Abuja
- All code must be clean, modular, well-commented, and production-quality
- Every result (record counts, accuracy, FPR, latency, etc.) must be real — no placeholder values

---

PHASE 1 — ENVIRONMENT SETUP

Install and verify all dependencies at their exact pinned versions:
  pandas==2.0.3, numpy==1.24.4, scikit-learn==1.3.2, imbalanced-learn==0.11.0,
  xgboost==1.7.6, ryu==4.34, mininet==2.3.0, streamlit==1.30.0,
  matplotlib==3.7.4, seaborn==0.12.2, joblib==1.3.2

Verify imports are working with a short test script that imports each library and prints its version. Fix any dependency conflicts before proceeding.

---

PHASE 2 — DATASET DOWNLOAD AND LOADING

Download the CIC-DDoS2019 dataset from: https://www.unb.ca/cic/datasets/ddos-2019.html
The dataset is split into multiple CSV files by day and attack type.

Write a script called load_data.py that:
1. Loads all CSV files using pandas and concatenates them into one DataFrame
2. Prints the exact shape of the combined DataFrame (rows × columns)
3. Prints the class distribution (value_counts on the label column)
4. Saves the combined raw DataFrame to data/raw_combined.csv
5. Logs all output to logs/data_loading.log

The label column may be named 'Label' or ' Label' — strip whitespace from all column names.

---

PHASE 3 — DATA PREPROCESSING AND CLEANING

Write preprocess.py that:
1. Loads data/raw_combined.csv
2. Strips all column name whitespace
3. Replaces np.inf and -np.inf with np.nan
4. Drops all rows with NaN values (log exact count dropped)
5. Drops duplicate rows (log exact count dropped)
6. Encodes the label column using sklearn LabelEncoder — save encoder to models/label_encoder.joblib
7. Logs the final class distribution after cleaning with exact counts
8. Saves the cleaned DataFrame to data/cleaned.csv

Print and log: original row count, rows removed (inf), rows removed (NaN), rows removed (duplicates), final row count.

---

PHASE 4 — FEATURE SELECTION AND SMOTE RESAMPLING

Write feature_selection.py that:
1. Loads data/cleaned.csv
2. Applies VarianceThreshold(threshold=0.0) — log which features are dropped
3. Splits data into train (80%) and test (20%) using stratified split on label column
4. Fits StandardScaler on train set only — saves to models/scaler.joblib
5. Transforms both train and test sets
6. Trains a preliminary RandomForest on a 10% stratified subsample of train to get feature importances
7. Selects the top 25 features by importance — saves feature list to models/selected_features.json
8. Subsets both train and test to those 25 features
9. Applies SMOTE(k_neighbors=5) to train set ONLY — logs class distribution before and after
10. Saves: X_train_smote.npy, y_train_smote.npy, X_test.npy, y_test.npy to data/splits/

Print feature importance ranking table (rank, feature name, score) for all 25 features.
Generate and save a horizontal bar chart of feature importances to figures/feature_importance.png.

---

PHASE 5 — MODEL TRAINING AND EVALUATION

Write train_evaluate.py that:

1. Loads splits from data/splits/
2. Trains these four configurations:
   a. Random Forest standalone: n_estimators=200, min_samples_leaf=2, n_jobs=-1
   b. XGBoost standalone: n_estimators=200, learning_rate=0.1, max_depth=6, subsample=0.8, eval_metric='mlogloss'
   c. Ensemble (RF + XGBoost, soft voting) using sklearn VotingClassifier
   d. Baseline: RandomForest without SMOTE (train on original unbalanced train set, same 25 features)

3. For each model, evaluates on X_test / y_test and computes:
   - Overall accuracy
   - Per-class precision, recall, F1-score (from classification_report)
   - Macro-averaged F1
   - False Positive Rate (FPR): benign flows misclassified as attacks / total actual benign flows
   - Training time in seconds

4. Prints a comparison table of all four models side by side

5. Generates and saves:
   - figures/confusion_matrix.png — seaborn heatmap for the ensemble model
   - figures/roc_curves.png — multi-class OvR ROC curves for all 12 classes with AUC in legend
   - results/classification_report.txt — full sklearn classification_report for ensemble

6. Serialises the best model (ensemble) to models/ensemble_model.joblib

Log exact training times. Do not use placeholder values anywhere.

---

PHASE 6 — RYU SDN CONTROLLER APPLICATION

Write ryu_app/ddos_controller.py as a Ryu application that:
1. Inherits from ryu.base.app_manager.RyuApp
2. On switch connection (EventOFPSwitchFeatures): installs a table-miss entry to send unmatched packets to controller
3. Starts a background threading.Timer polling flow stats from all switches every 5 seconds
4. On EventOFPFlowStatsReply:
   - Extracts per-flow byte count, packet count, duration, port info
   - Reconstructs the 25-feature vector (matching selected_features.json)
   - Loads models/scaler.joblib and models/ensemble_model.joblib at startup (not per-flow)
   - Passes feature vector to ensemble model for classification
   - If prediction != BENIGN: installs a FlowMod DROP rule with hard_timeout=60, priority=100
   - Logs alert to logs/alerts.csv: timestamp, src_ip, dst_ip, src_port, dst_port, protocol, predicted_class, confidence
5. Pushes alert events to a thread-safe queue consumed by the Streamlit dashboard

Write a startup script ryu_app/start_controller.sh that launches the Ryu app correctly.

---

PHASE 7 — MININET TOPOLOGY

Write mininet_topo/topology.py using the Mininet Python API that:
1. Creates: 1 Ryu controller (c0 at localhost:6633, OpenFlow 1.3), 3 switches (s1, s2, s3), 6 legitimate hosts (h1-h6), 2 attacker nodes (a1, a2 connected to s1)
2. Configures all links with TCLink: bw=100, delay='5ms'
3. Connects all components and starts the network
4. Starts a simple HTTP server on each legitimate host
5. Includes instructions (as comments) for running each of the 5 test scenarios using hping3 from a1/a2:
   - Scenario 1: SYN flood, 10000 pps, single attacker
   - Scenario 2: UDP flood, two simultaneous attackers
   - Scenario 3: DNS amplification
   - Scenario 4: Mixed SYN + UDP flood simultaneously
   - Scenario 5: High-volume legitimate HTTP (no attack)

---

PHASE 8 — STREAMLIT DASHBOARD

Write dashboard/app.py as a Streamlit app that:
1. Reads alert events from logs/alerts.csv and the shared queue
2. Provides 4 views:
   - Live classification feed: last 50 flows with label and confidence score
   - Attack frequency chart: bar chart of detected attack counts per class
   - System status panel: active flow rules installed, total flows classified, session FPR
   - Raw flow statistics table: manual inspection view
3. Auto-refreshes every 2 seconds
4. Allows administrator to manually clear a flow rule (write override to logs/overrides.csv)

---

PHASE 9 — END-TO-END SIMULATION AND RESULTS

Write a results collection script results/collect_results.py that:
1. Runs each of the 5 Mininet scenarios sequentially (or documents manual steps clearly)
2. For each scenario, measures and logs:
   - Detection latency (seconds from first malicious packet to FlowMod installation)
   - Mitigation effectiveness (% reduction in attack packets/s at target, 30s pre vs 30s post)
   - False Positive Rate during scenario
3. Saves all results to results/simulation_results.csv
4. Generates figures/traffic_timeseries.png — packets/s at target host for Scenario 1 with flow rule installation marker

---

PHASE 10 — FILL ALL CHAPTER 4 PLACEHOLDERS

After all experiments are run, produce a file results/chapter4_values.txt containing the actual measured values for every placeholder in Chapter 4 of the project document:
- Post-cleaning record count
- Feature importance scores (Table 4.3)
- SMOTE synthetic sample counts (Table 4.4)
- Training time for all four models
- Per-class precision, recall, F1 for all 12 classes (Table 4.5)
- Aggregate accuracy, macro F1, FPR, training time for all 4 models (Table 4.6)
- AUC-ROC scores for all 12 classes (Table 4.7)
- Detection latency, mitigation effectiveness, FPR for all 5 scenarios (Table 4.8)

---

CODE QUALITY RULES (apply to every file):
- Every function must have a docstring
- Use logging module (not just print) for all important outputs — write to both console and logs/
- No hardcoded paths — use pathlib.Path throughout
- All random operations use random_state=42 for reproducibility
- Handle exceptions explicitly — never bare except clauses
- Each script is independently runnable with a clear if __name__ == '__main__': block
- Follow PEP 8 style

---

DELIVERABLES CHECKLIST (confirm each is complete before finishing):
[ ] requirements.txt with pinned versions
[ ] load_data.py + logs/data_loading.log
[ ] preprocess.py + data/cleaned.csv + models/label_encoder.joblib
[ ] feature_selection.py + models/scaler.joblib + models/selected_features.json + data/splits/
[ ] train_evaluate.py + models/ensemble_model.joblib + results/classification_report.txt
[ ] figures/feature_importance.png, confusion_matrix.png, roc_curves.png
[ ] ryu_app/ddos_controller.py + ryu_app/start_controller.sh
[ ] mininet_topo/topology.py
[ ] dashboard/app.py
[ ] results/simulation_results.csv + figures/traffic_timeseries.png
[ ] results/chapter4_values.txt with all real measured numbers