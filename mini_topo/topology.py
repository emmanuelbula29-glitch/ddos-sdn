"""
Phase 7 — Mininet Topology
===========================
Creates a network topology with Ryu SDN controller, switches, legitimate
hosts, and attacker nodes for DDoS testing scenarios.

Author: B.Sc. Software Engineering Project
Project: Adaptive ML-based DDoS Detection and Mitigation System with SDN
"""

import logging
import os
import sys
import time
from pathlib import Path

from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import Controller, Host, OVSBridge, Switch
from mininet.topo import Topo

PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOG_DIR = PROJECT_ROOT / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "mininet.log", mode="w"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger(__name__)


class DDoSTopo(Topo):
    """Custom topology for DDoS testing with SDN."""

    def __init__(self):
        """Create topology: 3 switches, 6 hosts, 2 attackers."""
        super(DDoSTopo, self).__init__()

        logger.info("Building topology...")

        # Add controller
        c0 = self.addController(
            "c0",
            controller=Controller,
            ip="127.0.0.1",
            port=6633,
            protocol="tcp",
        )

        # Add switches
        s1 = self.addSwitch("s1", protocols="OpenFlow13")
        s2 = self.addSwitch("s2", protocols="OpenFlow13")
        s3 = self.addSwitch("s3", protocols="OpenFlow13")

        # Add legitimate hosts (h1-h6)
        hosts = []
        for i in range(1, 7):
            h = self.addHost(
                f"h{i}",
                ip=f"10.0.0.{i}/24",
                mac=f"00:00:00:00:00:{i:02x}",
                defaultRoute="gw=10.0.0.254",
            )
            hosts.append(h)

        # Add attacker nodes (a1, a2)
        a1 = self.addHost(
            "a1",
            ip="10.0.1.1/24",
            mac="00:00:00:00:01:01",
            defaultRoute="gw=10.0.1.254",
        )
        a2 = self.addHost(
            "a2",
            ip="10.0.1.2/24",
            mac="00:00:00:00:01:02",
            defaultRoute="gw=10.0.1.254",
        )

        # Add links with bandwidth and delay constraints
        link_opts = dict(bw=100, delay="5ms", loss=0, max_queue_size=1000)

        # Connect h1-h2 to s1
        self.addLink(hosts[0], s1, **link_opts)
        self.addLink(hosts[1], s1, **link_opts)

        # Connect h3-h4 to s2
        self.addLink(hosts[2], s2, **link_opts)
        self.addLink(hosts[3], s2, **link_opts)

        # Connect h5-h6 to s3
        self.addLink(hosts[4], s3, **link_opts)
        self.addLink(hosts[5], s3, **link_opts)

        # Connect attackers to s1
        self.addLink(a1, s1, **link_opts)
        self.addLink(a2, s1, **link_opts)

        # Connect switches together
        self.addLink(s1, s2, **link_opts)
        self.addLink(s2, s3, **link_opts)

        logger.info("Topology built: 3 switches, 6 hosts, 2 attackers")


def start_http_servers(net):
    """Start simple HTTP servers on all legitimate hosts."""
    logger.info("Starting HTTP servers on legitimate hosts...")
    for i in range(1, 7):
        h = net.get(f"h{i}")
        h.cmd("cd /tmp && nohup python3 -m http.server 80 &")
    logger.info("HTTP servers started on h1-h6")


def run_scenario(net, scenario_num):
    """Run a specific DDoS scenario."""
    logger.info(f"=== Running Scenario {scenario_num} ===")

    if scenario_num == 1:
        # Scenario 1: SYN flood, 10000 pps, single attacker
        logger.info("Scenario 1: SYN flood from a1")
        a1 = net.get("a1")
        target = net.get("h1")
        a1.cmd(f"hping3 -c 10000 -i u100 -S {target.IP()} &")
        logger.info("SYN flood started from a1 -> h1")

    elif scenario_num == 2:
        # Scenario 2: UDP flood, two simultaneous attackers
        logger.info("Scenario 2: UDP flood from a1 and a2")
        a1 = net.get("a1")
        a2 = net.get("a2")
        target = net.get("h1")
        a1.cmd(f"hping3 --udp -c 5000 -i u100 {target.IP()} &")
        a2.cmd(f"hping3 --udp -c 5000 -i u100 {target.IP()} &")
        logger.info("UDP flood started from a1, a2 -> h1")

    elif scenario_num == 3:
        # Scenario 3: DNS amplification
        logger.info("Scenario 3: DNS amplification attack")
        a1 = net.get("a1")
        dns_server = "8.8.8.8"
        a1.cmd(f"hping3 --udp -c 3000 -p 53 -a {dns_server} 10.0.0.1 &")
        logger.info("DNS amplification started")

    elif scenario_num == 4:
        # Scenario 4: Mixed SYN + UDP flood simultaneously
        logger.info("Scenario 4: Mixed SYN + UDP flood")
        a1 = net.get("a1")
        a2 = net.get("a2")
        target = net.get("h1")
        a1.cmd(f"hping3 -c 5000 -i u100 -S {target.IP()} &")
        a2.cmd(f"hping3 --udp -c 5000 -i u100 {target.IP()} &")
        logger.info("Mixed attack started")

    elif scenario_num == 5:
        # Scenario 5: High-volume legitimate HTTP (no attack)
        logger.info("Scenario 5: Legitimate HTTP traffic")
        h1 = net.get("h1")
        h2 = net.get("h2")
        h2.cmd("wget -O- -q http://10.0.0.1/ &")
        logger.info("Legitimate HTTP traffic started")

    else:
        logger.warning(f"Unknown scenario: {scenario_num}")


def main():
    """Main entry point for Mininet topology."""
    setLogLevel("info")
    logger.info("=" * 70)
    logger.info("PHASE 7 — Mininet Topology")
    logger.info("=" * 70)

    # Build topology
    topo = DDoSTopo()
    net = Mininet(topo=topo, controller=Controller, link=TCLink, switch=OVSBridge)

    # Start network
    logger.info("Starting network...")
    net.build()

    # Start controller
    c0 = net.get("c0")
    c0.start()
    logger.info("Controller c0 started at 127.0.0.1:6633")

    # Start switches
    for sw in ["s1", "s2", "s3"]:
        s = net.get(sw)
        s.start([c0])
        logger.info(f"Switch {sw} started")

    # Start HTTP servers on legitimate hosts
    start_http_servers(net)

    logger.info("Network ready!")
    logger.info("""

===========================================
AVAILABLE TEST SCENARIOS
===========================================

To run a scenario, use the following commands in the Mininet CLI:

Scenario 1 (SYN flood - single attacker):
  a1 hping3 -c 10000 -i u100 -S 10.0.0.1

Scenario 2 (UDP flood - two attackers):
  a1 hping3 --udp -c 5000 -i u100 10.0.0.1 &
  a2 hping3 --udp -c 5000 -i u100 10.0.0.1 &

Scenario 3 (DNS amplification):
  a1 hping3 --udp -c 3000 -p 53 -a 8.8.8.8 10.0.0.1

Scenario 4 (Mixed SYN + UDP):
  a1 hping3 -c 5000 -i u100 -S 10.0.0.1 &
  a2 hping3 --udp -c 5000 -i u100 10.0.0.1 &

Scenario 5 (Legitimate HTTP - no attack):
  h2 wget -O- -q http://10.0.0.1/

===========================================
    """)

    # Drop into CLI
    CLI(net)

    # Cleanup
    logger.info("Stopping network...")
    net.stop()
    logger.info("PHASE 7 COMPLETE")


if __name__ == "__main__":
    main()