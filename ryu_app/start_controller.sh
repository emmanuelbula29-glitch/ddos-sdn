#!/bin/bash
# Ryu SDN Controller Startup Script
# Launches the DDoS detection controller application

cd "$(dirname "$0")"

echo "Starting Ryu SDN Controller with DDoS detection..."
ryu-manager --verbose ryu_app/ddos_controller.py

echo "Ryu controller terminated"