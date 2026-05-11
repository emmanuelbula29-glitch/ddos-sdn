# DDoS Detection & Mitigation System

Adaptive ML-based DDoS detection and mitigation system integrated with Software Defined Network (SDN).

**Project**: B.Sc. Software Engineering, Veritas University, Abuja

---

## 📋 Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Project Structure](#project-structure)
- [Linux Setup](#linux-setup)
- [Windows Setup](#windows-setup)
- [Running the Dashboard](#running-the-dashboard)
- [Running Ryu + Mininet (Optional)](#running-ryu--mininet-optional)
- [Using the Attack Simulation](#using-the-attack-simulation)
- [Project Components](#project-components)

---

## 📊 Overview

This system implements:

1. **ML-based Detection** - Ensemble of Random Forest + XGBoost trained on CIC-DDoS2019 dataset
2. **SDN Integration** - Ryu controller with OpenFlow 1.3
3. **Real-time Dashboard** - Streamlit web interface
4. **Attack Simulation** - Synthetic traffic generation for testing

**Performance (on test set):**
- Accuracy: 97.70%
- Macro F1: 0.6598
- Detection Rate: 99%+ for SYN, UDP, NTP, TFTP attacks

---

## 🔧 Prerequisites

### Linux (Ubuntu/Debian)
- Python 3.11+
- Git
- sudo (for Mininet)
- 4GB+ RAM

### Windows
- Python 3.11+
- Git for Windows
- 4GB+ RAM
- PowerShell or Command Prompt

---

## 📁 Project Structure

```
bula_project/
├── dashboard/           # Streamlit dashboard
│   ├── app.py          # Main dashboard UI
│   └── simulator.py   # Attack simulation engine
├── data/               # Dataset and splits
│   ├── splits/         # Train/test splits (.npy)
│   ├── cleaned.csv     # Preprocessed data
│   └── raw_combined.csv
├── figures/            # Generated visualizations
├── logs/               # Application logs
├── mini_topo/          # Mininet topology
│   └── topology.py
├── models/             # Trained ML models
│   ├── ensemble_model.joblib
│   ├── scaler.joblib
│   ├── label_encoder.joblib
│   └── selected_features.json
├── results/            # Experiment results
├── ryu_app/            # Ryu SDN controller
│   ├── ddos_controller.py
│   └── start_controller.sh
├── src/                # Core scripts
│   ├── load_data.py
│   ├── preprocess.py
│   ├── feature_selection.py
│   └── train_evaluate.py
├── requirements.txt    # Python dependencies
├── pyproject.toml
└── PLAN.md            # Project plan
```

---

## 🐧 Linux Setup

### 1. Clone and Navigate
```bash
cd /path/to/your/projects
git clone <repository-url> bula_project
cd bula_project
```

### 2. Create Virtual Environment
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt

# For Streamlit dashboard (if not in requirements):
pip install streamlit streamlit-autorefresh

# For full Ryu + Mininet setup:
sudo apt-get update
sudo apt-get install -y python3-pip python3-venv
pip install ryu==4.34
```

### 4. Verify Installation
```bash
python scripts/verify_env.py
```

Expected output:
```
pandas             2.0.3         [OK]
numpy              1.24.4        [OK]
sklearn            1.3.2         [OK]
...
All dependencies verified successfully.
```

---

## 🪟 Windows Setup

### 1. Install Python

1. Download Python 3.11+ from https://python.org
2. **Important**: Check "Add Python to PATH"
3. During installation, check "Install pip"

### 2. Clone Repository
```powershell
# Open PowerShell or Command Prompt
cd C:\Projects
git clone <repository-url> bula_project
cd bula_project
```

### 3. Create Virtual Environment
```powershell
python -m venv .venv

# Activate
.venv\Scripts\activate
```

### 4. Install Dependencies
```powershell
pip install -r requirements.txt
```

### 5. Install Streamlit
```powershell
pip install streamlit streamlit-autorefresh
```

### 6. Verify Installation
```powershell
python scripts\verify_env.py
```

### 7. Common Windows Issues

**Issue: "python" not recognized**
- Use `py` instead of `python`
- Or check Python is in PATH: `C:\Python311\python.exe`

**Issue: Long Paths**
- Enable long paths:
```powershell
reg add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v LongPathsEnabled /t REG_DWORD /d 1
```

**Issue: Module not found**
- Ensure virtual environment is activated
- Re-run: `pip install -r requirements.txt`

---

## 🚀 Running the Dashboard

### Linux
```bash
cd bula_project
source .venv/bin/activate
streamlit run dashboard/app.py --server.port 8502
```

### Windows
```powershell
cd bula_project
.venv\Scripts\activate
streamlit run dashboard/app.py --server.port 8502
```

### Access Dashboard
Open browser to: **http://localhost:8502**

### Dashboard Features
- **Live Feed**: Real-time flow classification
- **Attack Breakdown**: Charts and statistics
- **Flow Rules**: Manual override controls
- **⚔️ Attack Simulation**: Run simulated attacks
- **System Status**: Model and system info

---

## 🔬 Running Ryu + Mininet (Optional - Linux Only)

This requires root and is more complex. Only for full network simulation.

### 1. Install Mininet
```bash
cd /tmp
git clone https://github.com/mininet/mininet.git
sudo mininet/util/install.sh -a
```

### 2. Start Ryu Controller (Terminal 1)
```bash
cd bula_project
sudo .venv/bin/ryu-manager --verbose ryu_app/ddos_controller.py
```

### 3. Start Mininet Topology (Terminal 2)
```bash
cd bula_project
sudo .venv/bin/python mini_topo/topology.py
```

### 4. Run Attack Scenarios (in Mininet CLI)

**Scenario 1: SYN Flood**
```mininet
mininet> a1 hping3 -c 10000 -i u100 -S 10.0.0.1
```

**Scenario 2: UDP Flood (two attackers)**
```mininet
mininet> a1 hping3 --udp -c 5000 -i u100 10.0.0.1 &
mininet> a2 hping3 --udp -c 5000 -i u100 10.0.0.1 &
```

**Scenario 3: DNS Amplification**
```mininet
mininet> a1 hping3 --udp -c 3000 -p 53 -a 8.8.8.8 10.0.0.1
```

---

## ⚔️ Using the Attack Simulation

The dashboard includes an **Attack Simulation** tab that generates synthetic but realistic attack traffic.

### How It Works
1. Go to "⚔️ Attack Simulation" tab
2. Select attack type from dropdown:
   - SYN Flood
   - UDP Flood
   - DNS Amplification
   - LDAP Flood
   - NTP Amplification
   - MSSQL Flood
   - TFTP Flood
   - SNMP Flood
   - Benign Traffic
3. Set duration (5-60 seconds)
4. Set intensity (1-100 flows/second)
5. Click "Start Attack"
6. Watch live detection in "Live Feed" tab

### Simulation Characteristics
- Uses real statistics from CIC-DDoS2019 dataset
- Simulates attack phases (ramp-up, sustain, ramp-down)
- Realistic detection rates per attack type
- Results logged to `logs/alerts.csv`

---

## 📦 Project Components

### Core ML Pipeline
| Script | Purpose |
|--------|---------|
| `src/load_data.py` | Load dataset (Phase 2) |
| `src/preprocess.py` | Clean data (Phase 3) |
| `src/feature_selection.py` | Select top 25 features + SMOTE (Phase 4) |
| `src/train_evaluate.py` | Train & evaluate models (Phase 5) |

### SDN Components
| Script | Purpose |
|--------|---------|
| `ryu_app/ddos_controller.py` | Ryu OpenFlow controller |
| `mini_topo/topology.py` | Mininet network topology |

### Dashboard
| Script | Purpose |
|--------|---------|
| `dashboard/app.py` | Main Streamlit UI |
| `dashboard/simulator.py` | Attack traffic generator |

---

## 📊 Model Performance

| Metric | Value |
|--------|-------|
| Overall Accuracy | 97.70% |
| Macro F1 | 0.6598 |
| Macro FPR | 0.0018 |

**Per-class Detection:**
| Attack Type | Precision | Recall | F1-Score |
|-------------|-----------|--------|----------|
| SYN Flood | 99.77% | 98.63% | 99.19% |
| UDP Flood | 98.62% | 97.01% | 97.81% |
| NTP Amplification | 99.96% | 99.23% | 99.59% |
| TFTP Flood | 99.98% | 99.58% | 99.78% |
| MSSQL | 88.96% | 89.94% | 89.45% |

---

## 🔄 Retraining the Model & Pushing Updates

If you modify the model (retrain with different parameters) or any code and want to push updates to GitHub:

### 1. Activate Virtual Environment
```bash
# Linux
source .venv/bin/activate

# Windows
.venv\Scripts\activate
```

### 2. Run the Full Pipeline (Optional - only if retraining)
```bash
# Step 1: Load data
python src/load_data.py

# Step 2: Preprocess
python src/preprocess.py

# Step 3: Feature selection + SMOTE
python src/feature_selection.py

# Step 4: Train & evaluate models
python src/train_evaluate.py
```

### 3. Stage Changes
```bash
git add .
```

### 4. Commit with Message
```bash
git commit -m "Updated model/your-change-description"
```

### 5. Push to GitHub
```bash
git push origin master
```

### Important: Large Files
If you retrain the model and it creates new `.joblib` or `.npy` files:
- These files are in `.gitignore` by default (large files excluded)
- If you need to include them, use Git LFS:
```bash
git lfs install
git lfs track "models/*.joblib"
git lfs track "data/splits/*.npy"
git add .gitattributes
git add models/ data/splits/
git commit -m "Add model files"
git push
```

---

## 🐛 Troubleshooting

### Dashboard won't start
```bash
# Check port availability
lsof -i :8502
# Kill any existing process
kill <PID>
```

### Model loading errors
- Models require specific sklearn/numpy versions
- Use the provided `requirements.txt` versions

### Mininet errors
- Must run with `sudo`
- Ensure Open vSwitch is installed: `sudo apt-get install openvswitch-switch`

---

## 📄 License

This is a B.Sc. Software Engineering final year project.

---

## 👤 Author

**Project**: Adaptive ML-based DDoS Detection and Mitigation System with SDN  
**Institution**: Veritas University, Abuja  
**Level**: B.Sc. Software Engineering (Final Year)