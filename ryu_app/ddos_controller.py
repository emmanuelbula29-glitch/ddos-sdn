"""
Phase 6 — Ryu SDN Controller Application
=========================================
DDoS detection controller that monitors flow statistics, classifies traffic
using the ML ensemble, and installs DROP rules for detected attacks.

Author: B.Sc. Software Engineering Project
Project: Adaptive ML-based DDoS Detection and Mitigation System with SDN
"""

import json
import logging
import os
import threading
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from queue import Queue

import joblib
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import ethernet, ipv4, tcp, udp
from ryu.ofproto import ofproto_v1_3

PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOG_DIR = PROJECT_ROOT / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "ddos_controller.log", mode="a"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)

MODELS_DIR = PROJECT_ROOT / "models"
DATA_DIR = PROJECT_ROOT / "data"
ALERTS_PATH = LOG_DIR / "alerts.csv"

FEATURE_JSON = MODELS_DIR / "selected_features.json"
SCALER_PATH = MODELS_DIR / "scaler.joblib"
MODEL_PATH = MODELS_DIR / "ensemble_model.joblib"

alert_queue = Queue()
flow_stats_history = defaultdict(list)


class DDoSController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DDoSController, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.mac_to_port = {}
        self.feature_names = []
        self.scaler = None
        self.model = None
        self.label_encoder = None
        self._load_models()
        self._init_alerts_file()
        self._start_flow_monitoring()

    def _load_models(self):
        """Load ML models at startup."""
        logger.info("Loading ML models...")
        with open(FEATURE_JSON, "r") as f:
            self.feature_names = json.load(f)
        logger.info(f"Loaded {len(self.feature_names)} features: {self.feature_names[:5]}...")

        self.scaler = joblib.load(SCALER_PATH)
        logger.info(f"Scaler loaded from {SCALER_PATH}")

        self.model = joblib.load(MODEL_PATH)
        logger.info(f"Model loaded from {MODEL_PATH}")

        try:
            self.label_encoder = joblib.load(MODELS_DIR / "label_encoder.joblib")
            logger.info(f"Label encoder classes: {list(self.label_encoder.classes_)}")
        except Exception as e:
            logger.warning(f"Could not load label encoder: {e}")
            self.label_encoder = None

    def _init_alerts_file(self):
        """Initialize alerts CSV file with headers."""
        if not ALERTS_PATH.exists():
            with open(ALERTS_PATH, "w") as f:
                f.write("timestamp,src_ip,dst_ip,src_port,dst_port,protocol,predicted_class,confidence\n")
            logger.info(f"Initialized alerts file at {ALERTS_PATH}")

    def _start_flow_monitoring(self):
        """Start background thread for periodic flow stats polling."""
        self.monitor_thread = hub.spawn(self._flow_monitor_loop)
        logger.info("Flow monitoring thread started")

    def _flow_monitor_loop(self):
        """Poll flow stats from all switches every 5 seconds."""
        while True:
            for dp in self.datapaths.values():
                self._send_flow_stats_request(dp)
            hub.sleep(5)

    def _send_flow_stats_request(self, datapath):
        """Send OFP Flow Stats Request to a datapath."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, MAIN_DISPATCHER)
    def switch_features_handler(self, ev):
        """Handle switch connection and install table-miss entry."""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.datapaths[datapath.id] = datapath
        logger.info(f"Switch {datapath.id} connected")

        # Install table-miss entry (send to controller)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, 0, match, actions, priority=0)

    def _add_flow(self, datapath, hard_timeout, match, actions, priority=100):
        """Add a flow entry to the switch."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            hard_timeout=hard_timeout,
            priority=priority,
            match=match,
            instructions=inst,
        )
        datapath.send_msg(mod)

    @set_ev_cls(ofdp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        """Handle flow stats replies and perform detection."""
        body = ev.msg.body
        datapath = ev.msg.datapath

        for stat in body:
            if stat.priority <= 0:
                continue

            features = self._extract_features(stat)
            if features is None:
                continue

            prediction = self._classify_flow(features)
            predicted_class = prediction[0]
            confidence = prediction[1]

            if predicted_class != "Benign":
                logger.warning(
                    f"Attack detected! {predicted_class} (confidence: {confidence:.3f}) "
                    f"from {stat.match.get('ipv4_src', 'unknown')}"
                )
                self._install_drop_rule(datapath, stat.match, predicted_class, confidence)
                self._log_alert(stat.match, predicted_class, confidence)

    def _extract_features(self, stat):
        """Extract 25 features from flow stats matching selected_features.json."""
        try:
            match = stat.match
            packet_count = stat.packet_count
            byte_count = stat.byte_count
            duration = stat.duration_sec + stat.duration_nsec / 1e9

            features = {
                "Flow Duration": duration,
                "Total Fwd Packets": packet_count,
                "Total Backward Packets": 0,
                "Total Length of Fwd Packets": byte_count,
                "Total Length of Bwd Packets": 0,
                "Fwd Packet Length Max": byte_count // max(packet_count, 1),
                "Fwd Packet Length Min": byte_count // max(packet_count, 1),
                "Fwd Packet Length Mean": byte_count / max(packet_count, 1),
                "Fwd Packet Length Std": 0,
                "Bwd Packet Length Max": 0,
                "Bwd Packet Length Min": 0,
                "Bwd Packet Length Mean": 0,
                "Bwd Packet Length Std": 0,
                "Flow Bytes/s": byte_count / max(duration, 0.001),
                "Flow Packets/s": packet_count / max(duration, 0.001),
                "Flow IAT Mean": duration / max(packet_count, 1),
                "Flow IAT Std": 0,
                "Flow IAT Max": duration / max(packet_count, 1),
                "Flow IAT Min": duration / max(packet_count, 1),
                "Fwd IAT Total": duration,
                "Fwd IAT Mean": duration / max(packet_count, 1),
                "Fwd IAT Std": 0,
                "Fwd IAT Max": duration,
                "Fwd IAT Min": duration,
                "Bwd IAT Total": 0,
            }

            feature_vector = [features.get(fn, 0) for fn in self.feature_names]
            return feature_vector

        except Exception as e:
            logger.debug(f"Feature extraction error: {e}")
            return None

    def _classify_flow(self, feature_vector):
        """Classify a flow using the ensemble model."""
        try:
            X = [feature_vector]
            X_scaled = self.scaler.transform(X)
            prediction = self.model.predict(X_scaled)[0]

            if self.label_encoder:
                predicted_class = self.label_encoder.inverse_transform([prediction])[0]
            else:
                predicted_class = str(prediction)

            try:
                proba = self.model.predict_proba(X_scaled)[0]
                confidence = max(proba)
            except Exception:
                confidence = 1.0

            return predicted_class, confidence

        except Exception as e:
            logger.error(f"Classification error: {e}")
            return "Unknown", 0.0

    def _install_drop_rule(self, datapath, match, attack_type, confidence):
        """Install a DROP flow rule for detected attack."""
        parser = datapath.ofproto_parser
        actions = []
        match_dict = parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=match.get("ipv4_src", "0.0.0.0"),
            ipv4_dst=match.get("ipv4_dst", "0.0.0.0"),
        )
        self._add_flow(datapath, hard_timeout=60, match=match_dict, actions=actions, priority=100)
        logger.info(f"Installed DROP rule for {attack_type}")

    def _log_alert(self, match, predicted_class, confidence):
        """Log alert to alerts.csv and push to queue."""
        timestamp = datetime.now().isoformat()
        src_ip = match.get("ipv4_src", "unknown")
        dst_ip = match.get("ipv4_dst", "unknown")
        src_port = match.get("tcp_src", 0)
        dst_port = match.get("tcp_dst", 0)
        protocol = "TCP" if match.get("tcp_src") else "UDP"

        alert_line = f"{timestamp},{src_ip},{dst_ip},{src_port},{dst_port},{protocol},{predicted_class},{confidence:.4f}\n"

        with open(ALERTS_PATH, "a") as f:
            f.write(alert_line)

        alert_queue.put({
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "predicted_class": predicted_class,
            "confidence": confidence,
        })

        logger.info(f"Alert logged: {predicted_class} from {src_ip}")


from ryu.controller import ofp_event

from ryu.lib.packet import packet