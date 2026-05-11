import os
import threading
import time
from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st
from streamlit_autorefresh import st_autorefresh

PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOG_DIR = PROJECT_ROOT / "logs"
DATA_DIR = PROJECT_ROOT / "data"
MODELS_DIR = PROJECT_ROOT / "models"

ALERTS_PATH = LOG_DIR / "alerts.csv"
OVERRIDES_PATH = LOG_DIR / "overrides.csv"
FLOWS_PATH = DATA_DIR / "live_flows.csv"

st.set_page_config(
    page_title="DDoS Shield",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

st_autorefresh(interval=2000, limit=None, key="dashboard_refresh")

# ── Global dark theme injection ──────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600&display=swap');

:root {
    --bg-base:      #0a0c0f;
    --bg-surface:   #111419;
    --bg-card:      #161b22;
    --bg-hover:     #1c2330;
    --border:       #21262d;
    --border-bright:#30363d;
    --text-primary: #e6edf3;
    --text-muted:   #7d8590;
    --text-dim:     #484f58;
    --accent-green: #3fb950;
    --accent-red:   #f85149;
    --accent-amber: #d29922;
    --accent-blue:  #388bfd;
    --accent-teal:  #39c5cf;
    --accent-purple:#bc8cff;
    --font-mono:    'JetBrains Mono', monospace;
    --font-ui:      'IBM Plex Sans', sans-serif;
}

html, body, [class*="css"] {
    font-family: var(--font-ui) !important;
    background-color: var(--bg-base) !important;
    color: var(--text-primary) !important;
}

/* Top app bar */
header[data-testid="stHeader"] {
    background: var(--bg-surface) !important;
    border-bottom: 1px solid var(--border) !important;
}

/* Sidebar */
[data-testid="stSidebar"] {
    background: var(--bg-surface) !important;
    border-right: 1px solid var(--border) !important;
}

/* All cards / block containers */
[data-testid="stVerticalBlock"] > [data-testid="stVerticalBlockBorderWrapper"],
[data-testid="element-container"] { background: transparent !important; }

/* Metric cards */
[data-testid="metric-container"] {
    background: var(--bg-card) !important;
    border: 1px solid var(--border) !important;
    border-radius: 8px !important;
    padding: 1rem 1.25rem !important;
}
[data-testid="stMetricLabel"] {
    font-family: var(--font-mono) !important;
    font-size: 11px !important;
    letter-spacing: 0.08em !important;
    color: var(--text-muted) !important;
    text-transform: uppercase !important;
}
[data-testid="stMetricValue"] {
    font-family: var(--font-mono) !important;
    font-size: 28px !important;
    font-weight: 600 !important;
    color: var(--text-primary) !important;
}
[data-testid="stMetricDelta"] { font-family: var(--font-mono) !important; }

/* Tabs */
[data-testid="stTabs"] button {
    font-family: var(--font-mono) !important;
    font-size: 12px !important;
    letter-spacing: 0.05em !important;
    color: var(--text-muted) !important;
    text-transform: uppercase !important;
    border-bottom: 2px solid transparent !important;
    padding: 0.5rem 1rem !important;
    background: transparent !important;
}
[data-testid="stTabs"] button[aria-selected="true"] {
    color: var(--accent-teal) !important;
    border-bottom-color: var(--accent-teal) !important;
}
[data-testid="stTabs"] [role="tablist"] {
    border-bottom: 1px solid var(--border) !important;
    background: transparent !important;
    gap: 4px !important;
}

/* Dataframe / table */
[data-testid="stDataFrame"] {
    border: 1px solid var(--border) !important;
    border-radius: 6px !important;
    overflow: hidden !important;
}
[data-testid="stDataFrame"] thead th {
    background: var(--bg-surface) !important;
    color: var(--text-muted) !important;
    font-family: var(--font-mono) !important;
    font-size: 11px !important;
    letter-spacing: 0.08em !important;
    text-transform: uppercase !important;
    border-bottom: 1px solid var(--border) !important;
}
[data-testid="stDataFrame"] tbody tr:nth-child(even) {
    background: rgba(255,255,255,0.02) !important;
}
[data-testid="stDataFrame"] tbody tr:hover {
    background: var(--bg-hover) !important;
}
[data-testid="stDataFrame"] td {
    font-family: var(--font-mono) !important;
    font-size: 12px !important;
    color: var(--text-primary) !important;
    border-bottom: 1px solid var(--border) !important;
}

/* Bar chart */
[data-testid="stBarChart"] { background: transparent !important; }

/* Info / warning banners */
[data-testid="stInfo"] {
    background: rgba(56, 139, 253, 0.08) !important;
    border: 1px solid rgba(56, 139, 253, 0.25) !important;
    border-radius: 6px !important;
    color: var(--text-muted) !important;
    font-family: var(--font-mono) !important;
    font-size: 12px !important;
}
[data-testid="stError"] {
    background: rgba(248, 81, 73, 0.08) !important;
    border: 1px solid rgba(248, 81, 73, 0.25) !important;
    border-radius: 6px !important;
    font-family: var(--font-mono) !important;
    font-size: 12px !important;
}
[data-testid="stSuccess"] {
    background: rgba(63, 185, 80, 0.08) !important;
    border: 1px solid rgba(63, 185, 80, 0.25) !important;
    border-radius: 6px !important;
    font-family: var(--font-mono) !important;
    font-size: 12px !important;
}
[data-testid="stWarning"] {
    background: rgba(210, 153, 34, 0.08) !important;
    border: 1px solid rgba(210, 153, 34, 0.25) !important;
    border-radius: 6px !important;
    font-family: var(--font-mono) !important;
    font-size: 12px !important;
}

/* Inputs */
[data-testid="stTextInput"] input,
[data-testid="stSelectbox"] select {
    background: var(--bg-surface) !important;
    border: 1px solid var(--border-bright) !important;
    border-radius: 6px !important;
    color: var(--text-primary) !important;
    font-family: var(--font-mono) !important;
    font-size: 13px !important;
}
[data-testid="stTextInput"] input:focus,
[data-testid="stSelectbox"] select:focus {
    border-color: var(--accent-teal) !important;
    box-shadow: 0 0 0 2px rgba(57, 197, 207, 0.15) !important;
}

/* Button */
[data-testid="baseButton-secondary"], button[kind="secondary"] {
    background: var(--bg-surface) !important;
    border: 1px solid var(--border-bright) !important;
    color: var(--text-primary) !important;
    border-radius: 6px !important;
    font-family: var(--font-mono) !important;
    font-size: 12px !important;
    letter-spacing: 0.03em !important;
    transition: border-color 0.15s, background 0.15s !important;
}
[data-testid="baseButton-secondary"]:hover, button[kind="secondary"]:hover {
    border-color: var(--accent-teal) !important;
    background: var(--bg-hover) !important;
    color: var(--accent-teal) !important;
}

/* Divider */
hr { border-color: var(--border) !important; }

/* Subheaders */
h1, h2, h3 {
    font-family: var(--font-ui) !important;
    font-weight: 600 !important;
    color: var(--text-primary) !important;
}

/* Caption / footer */
[data-testid="stCaptionContainer"] {
    font-family: var(--font-mono) !important;
    font-size: 11px !important;
    color: var(--text-dim) !important;
    letter-spacing: 0.05em !important;
}

/* Scrollbar */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: var(--bg-base); }
::-webkit-scrollbar-thumb { background: var(--border-bright); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: var(--text-dim); }
</style>
""", unsafe_allow_html=True)


# ── Helpers ──────────────────────────────────────────────────────────────────

ATTACK_CLASSES = {
    "DDoS": "🔴",
    "DoS": "🟠",
    "PortScan": "🟡",
    "BruteForce": "🟠",
    "Infiltration": "🔴",
    "Botnet": "🔴",
    "Web Attack": "🟡",
    "Heartbleed": "🔴",
    "Benign": "🟢",
}


def severity_tag(label: str) -> str:
    icon = ATTACK_CLASSES.get(label, "⚪")
    return f"{icon} {label}"


def load_alerts() -> pd.DataFrame:
    if ALERTS_PATH.exists():
        try:
            df = pd.read_csv(ALERTS_PATH)
            if "predicted_class" in df.columns:
                df["class_display"] = df["predicted_class"].apply(severity_tag)
            return df
        except Exception as e:
            st.error(f"Error loading alerts: {e}")
    return pd.DataFrame()


def load_overrides() -> pd.DataFrame:
    if OVERRIDES_PATH.exists():
        try:
            return pd.read_csv(OVERRIDES_PATH)
        except Exception:
            pass
    return pd.DataFrame()


def save_override(src_ip: str, dst_ip: str, action: str):
    timestamp = datetime.now().isoformat()
    new_row = pd.DataFrame([{"timestamp": timestamp, "src_ip": src_ip, "dst_ip": dst_ip, "action": action}])
    if OVERRIDES_PATH.exists():
        existing = pd.read_csv(OVERRIDES_PATH)
        new_row = pd.concat([existing, new_row], ignore_index=True)
    new_row.to_csv(OVERRIDES_PATH, index=False)


def init_overrides_file():
    if not OVERRIDES_PATH.exists():
        pd.DataFrame(columns=["timestamp", "src_ip", "dst_ip", "action"]).to_csv(OVERRIDES_PATH, index=False)


def delta_label(current: int, label: str) -> str:
    """Placeholder delta — replace with real windowed comparison if available."""
    return None


# ── Header ───────────────────────────────────────────────────────────────────

init_overrides_file()

st.markdown("""
<div style="display:flex; align-items:center; justify-content:space-between; padding:0.5rem 0 1.25rem 0; border-bottom:1px solid #21262d; margin-bottom:1.5rem;">
  <div style="display:flex; align-items:center; gap:14px;">
    <span style="font-size:28px;">🛡️</span>
    <div>
      <div style="font-family:'IBM Plex Sans',sans-serif; font-size:20px; font-weight:600; color:#e6edf3; line-height:1.2;">DDoS Shield</div>
      <div style="font-family:'JetBrains Mono',monospace; font-size:11px; color:#7d8590; letter-spacing:0.08em; text-transform:uppercase; margin-top:2px;">Adaptive Detection &amp; Mitigation</div>
    </div>
  </div>
  <div style="font-family:'JetBrains Mono',monospace; font-size:11px; color:#3fb950; letter-spacing:0.06em;">
    ● LIVE &nbsp;·&nbsp; <span style="color:#7d8590;">AUTO-REFRESH 2s</span>
  </div>
</div>
""", unsafe_allow_html=True)

alerts_df = load_alerts()

# ── Stat bar ─────────────────────────────────────────────────────────────────

total = len(alerts_df)
attack_count = int(len(alerts_df[alerts_df["predicted_class"] != "Benign"])) if not alerts_df.empty else 0
benign_count = int(len(alerts_df[alerts_df["predicted_class"] == "Benign"])) if not alerts_df.empty else 0
attack_rate = f"{(attack_count / total * 100):.1f}%" if total > 0 else "—"
unique_classes = int(alerts_df["predicted_class"].nunique()) if not alerts_df.empty else 0

col1, col2, col3, col4, col5 = st.columns(5)
with col1:
    st.metric("Total Flows", f"{total:,}")
with col2:
    st.metric("Attacks Detected", f"{attack_count:,}")
with col3:
    st.metric("Benign Flows", f"{benign_count:,}")
with col4:
    st.metric("Attack Rate", attack_rate)
with col5:
    st.metric("Attack Classes", unique_classes)

st.markdown("<div style='margin-top:1.5rem'></div>", unsafe_allow_html=True)

# ── Import simulator ───────────────────────────────────────────────────────
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from dashboard.simulator import (
    get_attack_types,
    get_status,
    start_simulation,
    stop_simulation,
    simulator,
)

# ── Tabs ─────────────────────────────────────────────────────────────────────

tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "Live Feed",
    "Attack Breakdown",
    "Flow Rules",
    "⚔️ Attack Simulation",
    "System",
])

# ── Tab 1: Live Feed ──────────────────────────────────────────────────────────
with tab1:
    col_left, col_right = st.columns([3, 1])

    with col_left:
        st.markdown("""
        <div style="font-family:'JetBrains Mono',monospace; font-size:11px; color:#7d8590;
             letter-spacing:0.08em; text-transform:uppercase; margin-bottom:0.75rem;">
          Last 50 classified flows
        </div>
        """, unsafe_allow_html=True)

        if not alerts_df.empty:
            display_cols = [c for c in ["timestamp", "src_ip", "dst_ip", "protocol",
                                        "predicted_class", "confidence"] if c in alerts_df.columns]
            if "class_display" in alerts_df.columns:
                display_cols = [c if c != "predicted_class" else "class_display" for c in display_cols]

            recent = alerts_df.tail(50)[display_cols]
            st.dataframe(
                recent[::-1],
                use_container_width=True,
                hide_index=True,
                height=520,
            )
        else:
            st.info("No flows recorded yet. Waiting for traffic...")

    with col_right:
        st.markdown("""
        <div style="font-family:'JetBrains Mono',monospace; font-size:11px; color:#7d8590;
             letter-spacing:0.08em; text-transform:uppercase; margin-bottom:0.75rem;">
          Class legend
        </div>
        """, unsafe_allow_html=True)
        for cls, icon in ATTACK_CLASSES.items():
            color = "#f85149" if icon == "🔴" else "#d29922" if icon == "🟠" else "#e3b341" if icon == "🟡" else "#3fb950"
            st.markdown(f"""
            <div style="display:flex; align-items:center; gap:8px; padding:5px 0;
                 border-bottom:1px solid #21262d; font-family:'JetBrains Mono',monospace; font-size:12px;">
              <span style="color:{color}; font-size:8px;">●</span>
              <span style="color:#e6edf3;">{cls}</span>
            </div>
            """, unsafe_allow_html=True)

        if not alerts_df.empty and "predicted_class" in alerts_df.columns:
            last_class = alerts_df["predicted_class"].iloc[-1]
            last_ts = alerts_df.get("timestamp", pd.Series(["—"])).iloc[-1]
            icon = ATTACK_CLASSES.get(last_class, "⚪")
            color = "#f85149" if last_class != "Benign" else "#3fb950"
            st.markdown(f"""
            <div style="margin-top:1.5rem; padding:12px; background:#161b22; border:1px solid #21262d;
                 border-radius:8px; border-left:3px solid {color};">
              <div style="font-family:'JetBrains Mono',monospace; font-size:10px; color:#7d8590;
                   text-transform:uppercase; letter-spacing:0.08em; margin-bottom:4px;">Last event</div>
              <div style="font-family:'JetBrains Mono',monospace; font-size:14px; font-weight:600;
                   color:{color};">{icon} {last_class}</div>
              <div style="font-family:'JetBrains Mono',monospace; font-size:10px; color:#484f58;
                   margin-top:4px;">{last_ts}</div>
            </div>
            """, unsafe_allow_html=True)

# ── Tab 2: Attack Breakdown ───────────────────────────────────────────────────
with tab2:
    if not alerts_df.empty:
        attack_df = alerts_df[alerts_df["predicted_class"] != "Benign"]

        if not attack_df.empty:
            col_chart, col_table = st.columns([2, 1])

            with col_chart:
                st.markdown("""
                <div style="font-family:'JetBrains Mono',monospace; font-size:11px; color:#7d8590;
                     letter-spacing:0.08em; text-transform:uppercase; margin-bottom:0.75rem;">
                  Attack frequency by class
                </div>
                """, unsafe_allow_html=True)
                counts = attack_df["predicted_class"].value_counts()
                st.bar_chart(counts, height=340, use_container_width=True)

            with col_table:
                st.markdown("""
                <div style="font-family:'JetBrains Mono',monospace; font-size:11px; color:#7d8590;
                     letter-spacing:0.08em; text-transform:uppercase; margin-bottom:0.75rem;">
                  Counts
                </div>
                """, unsafe_allow_html=True)
                counts_df = counts.reset_index()
                counts_df.columns = ["Class", "Count"]
                counts_df["Share"] = (counts_df["Count"] / counts_df["Count"].sum() * 100).round(1).astype(str) + "%"
                st.dataframe(counts_df, use_container_width=True, hide_index=True)

            # Timeline if timestamp present
            if "timestamp" in alerts_df.columns:
                st.markdown("""
                <div style="font-family:'JetBrains Mono',monospace; font-size:11px; color:#7d8590;
                     letter-spacing:0.08em; text-transform:uppercase; margin-top:1.5rem; margin-bottom:0.75rem;">
                  Attack volume over time
                </div>
                """, unsafe_allow_html=True)
                try:
                    ts_df = attack_df.copy()
                    ts_df["timestamp"] = pd.to_datetime(ts_df["timestamp"], errors="coerce")
                    ts_df = ts_df.dropna(subset=["timestamp"])
                    if not ts_df.empty:
                        timeline = ts_df.set_index("timestamp").resample("1min").size().rename("attacks")
                        st.line_chart(timeline, height=200, use_container_width=True)
                except Exception:
                    pass
        else:
            st.info("No attacks detected yet.")
    else:
        st.info("No data available.")

# ── Tab 3: Flow Rules ─────────────────────────────────────────────────────────
with tab3:
    col_form, col_rules = st.columns([1, 2])

    with col_form:
        st.markdown("""
        <div style="font-family:'JetBrains Mono',monospace; font-size:11px; color:#7d8590;
             letter-spacing:0.08em; text-transform:uppercase; margin-bottom:0.75rem;">
          Add override rule
        </div>
        """, unsafe_allow_html=True)

        with st.container():
            src_ip = st.text_input("Source IP", placeholder="e.g. 192.168.1.10")
            dst_ip = st.text_input("Destination IP", placeholder="e.g. 10.0.0.1")
            action = st.selectbox("Action", ["block", "allow"])

            if st.button("Apply Rule →", use_container_width=True):
                if src_ip and dst_ip:
                    save_override(src_ip, dst_ip, action)
                    color = "#f85149" if action == "block" else "#3fb950"
                    st.success(f"Rule saved: **{action}** `{src_ip}` → `{dst_ip}`")
                else:
                    st.warning("Both IPs required.")

    with col_rules:
        st.markdown("""
        <div style="font-family:'JetBrains Mono',monospace; font-size:11px; color:#7d8590;
             letter-spacing:0.08em; text-transform:uppercase; margin-bottom:0.75rem;">
          Active override rules
        </div>
        """, unsafe_allow_html=True)
        overrides_df = load_overrides()
        if not overrides_df.empty:
            st.dataframe(overrides_df, use_container_width=True, hide_index=True, height=400)
        else:
            st.info("No override rules configured.")

# ── Tab 4: Attack Simulation ───────────────────────────────────────────────────
with tab4:
    st.markdown("""
    <div style="font-family:'JetBrains Mono',monospace; font-size:11px; color:#7d8590;
         letter-spacing:0.08em; text-transform:uppercase; margin-bottom:1rem;">
      Simulate network attacks and watch the detection system respond in real-time
    </div>
    """, unsafe_allow_html=True)

    sim_status = get_status()

    if sim_status["status"] == "running":
        st.markdown(f"""
        <div style="padding:1rem; background:rgba(248,81,73,0.1); border:1px solid rgba(248,81,73,0.3);
             border-radius:8px; margin-bottom:1.5rem;">
          <div style="display:flex; align-items:center; gap:8px;">
            <span style="color:#f85149; font-size:16px;">🔴</span>
            <span style="font-family:'JetBrains Mono',monospace; font-size:14px; color:#f85149; font-weight:600;">
              Simulation Running: {sim_status['attack']}
            </span>
          </div>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div style="padding:1rem; background:rgba(63,185,80,0.1); border:1px solid rgba(63,185,80,0.3);
             border-radius:8px; margin-bottom:1.5rem;">
          <div style="display:flex; align-items:center; gap:8px;">
            <span style="color:#3fb950; font-size:16px;">🟢</span>
            <span style="font-family:'JetBrains Mono',monospace; font-size:14px; color:#3fb950;">
              Ready to simulate
            </span>
          </div>
        </div>
        """, unsafe_allow_html=True)

    col_sim1, col_sim2 = st.columns([1, 1])

    with col_sim1:
        st.markdown("""
        <div style="font-family:'JetBrains Mono',monospace; font-size:11px; color:#7d8590;
             letter-spacing:0.08em; text-transform:uppercase; margin-bottom:0.75rem;">
          Select attack type
        </div>
        """, unsafe_allow_html=True)

        attack_type = st.selectbox(
            "Attack Type",
            get_attack_types(),
            index=None,
            placeholder="Choose an attack...",
            label_visibility="collapsed",
        )

        duration = st.slider("Duration (seconds)", min_value=5, max_value=60, value=10)
        intensity = st.slider("Intensity (flows/sec)", min_value=1, max_value=100, value=20)

        col_btn1, col_btn2 = st.columns(2)
        with col_btn1:
            if st.button("▶ Start Attack", use_container_width=True, disabled=sim_status["status"] == "running"):
                if attack_type:
                    result = start_simulation(attack_type, duration, intensity)
                    if result["status"] == "started":
                        st.rerun()
                    else:
                        st.error("Failed to start simulation")
                else:
                    st.warning("Select an attack type")

        with col_btn2:
            if st.button("⏹ Stop", use_container_width=True, disabled=sim_status["status"] == "idle"):
                result = stop_simulation()
                time.sleep(1)
                st.rerun()

    with col_sim2:
        st.markdown("""
        <div style="font-family:'JetBrains Mono',monospace; font-size:11px; color:#7d8590;
             letter-spacing:0.08em; text-transform:uppercase; margin-bottom:0.75rem;">
          Attack profiles
        </div>
        """, unsafe_allow_html=True)

        attack_info = {
            "SYN Flood": "Classic DoS attack - floods target with TCP SYN packets",
            "UDP Flood": "Sends large volumes of UDP packets to overwhelm target",
            "DNS Amplification": "Exploits DNS servers to amplify attack traffic",
            "LDAP Flood": "LDAP server amplification attack",
            "NTP Amplification": "NTP server reflection attack",
            "MSSQL Flood": "Microsoft SQL server amplification",
            "TFTP Flood": "TFTP amplification attack",
            "SNMP Flood": "SNMP amplification attack",
            "Benign Traffic": "Normal legitimate HTTP traffic",
        }

        if attack_type:
            st.markdown(f"""
            <div style="padding:12px; background:#161b22; border:1px solid #30363d; border-radius:8px;">
              <div style="font-family:'JetBrains Mono',monospace; font-size:13px; color:#e6edf3; font-weight:600; margin-bottom:6px;">
                {attack_type}
              </div>
              <div style="font-family:'JetBrains Mono',monospace; font-size:11px; color:#7d8590;">
                {attack_info.get(attack_type, "Unknown attack type")}
              </div>
            </div>
            """, unsafe_allow_html=True)

        st.markdown("""
        <div style="margin-top:1rem; padding:12px; background:#0d1117; border:1px solid #21262d; border-radius:6px;">
          <div style="font-family:'JetBrains Mono',monospace; font-size:11px; color:#7d8590; margin-bottom:6px;">
            How it works
          </div>
          <div style="font-family:'JetBrains Mono',monospace; font-size:10px; color:#484f58; line-height:1.6;">
            1. Synthetic network flows are generated<br>
            2. Features are extracted & normalized<br>
            3. ML model classifies each flow<br>
            4. Results logged to alerts.csv<br>
            5. Dashboard shows live detection
          </div>
        </div>
        """, unsafe_allow_html=True)

    if sim_status["status"] == "running":
        st.markdown("""
        <div style="margin-top:1.5rem; font-family:'JetBrains Mono',monospace; font-size:11px; color:#7d8590;
             letter-spacing:0.08em; text-transform:uppercase; margin-bottom:0.75rem;">
          Live detection feed
        </div>
        """, unsafe_allow_html=True)

        recent_alerts = load_alerts().tail(10)
        if not recent_alerts.empty:
            display_cols = [c for c in ["timestamp", "src_ip", "dst_ip", "predicted_class", "confidence"] if c in recent_alerts.columns]
            st.dataframe(recent_alerts[display_cols][::-1], use_container_width=True, hide_index=True, height=300)
        else:
            st.info("Waiting for detection results...")

# ── Tab 5: System ─────────────────────────────────────────────────────────────
with tab5:
    col_s1, col_s2 = st.columns(2)

    with col_s1:
        st.markdown("""
        <div style="font-family:'JetBrains Mono',monospace; font-size:11px; color:#7d8590;
             letter-spacing:0.08em; text-transform:uppercase; margin-bottom:0.75rem;">
          Controller status
        </div>
        """, unsafe_allow_html=True)

        stats = {
            "Active Flow Rules": "N/A",
            "Session FPR": "N/A",
            "Model": MODELS_DIR.name if MODELS_DIR.exists() else "Not loaded",
            "Alerts log": "Found" if ALERTS_PATH.exists() else "Missing",
            "Overrides log": "Found" if OVERRIDES_PATH.exists() else "Missing",
            "Last refresh": datetime.now().strftime("%H:%M:%S"),
        }
        for label, value in stats.items():
            color = "#f85149" if "Missing" in str(value) else "#3fb950" if "Found" in str(value) else "#e6edf3"
            st.markdown(f"""
            <div style="display:flex; justify-content:space-between; align-items:center;
                 padding:8px 0; border-bottom:1px solid #21262d;">
              <span style="font-family:'JetBrains Mono',monospace; font-size:12px; color:#7d8590;">{label}</span>
              <span style="font-family:'JetBrains Mono',monospace; font-size:12px; font-weight:600; color:{color};">{value}</span>
            </div>
            """, unsafe_allow_html=True)

    with col_s2:
        st.markdown("""
        <div style="font-family:'JetBrains Mono',monospace; font-size:11px; color:#7d8590;
             letter-spacing:0.08em; text-transform:uppercase; margin-bottom:0.75rem;">
          Raw flow statistics
        </div>
        """, unsafe_allow_html=True)
        if FLOWS_PATH.exists():
            try:
                flows_df = pd.read_csv(FLOWS_PATH)
                st.dataframe(flows_df, use_container_width=True, height=340)
            except Exception as e:
                st.error(f"Error loading flow data: {e}")
        else:
            st.info("No flow stats file found. Run the SDN controller to generate data.")

# ── Footer ────────────────────────────────────────────────────────────────────
st.markdown("""
<div style="margin-top:2.5rem; padding-top:1rem; border-top:1px solid #21262d;
     display:flex; justify-content:space-between; align-items:center;">
  <span style="font-family:'JetBrains Mono',monospace; font-size:11px; color:#484f58; letter-spacing:0.05em;">
    DDoS Shield · Veritas University · B.Sc. Software Engineering
  </span>
  <span style="font-family:'JetBrains Mono',monospace; font-size:11px; color:#484f58; letter-spacing:0.05em;">
    v1.0.0
  </span>
</div>
""", unsafe_allow_html=True)