#!/usr/bin/env python3
"""
ARP Spoofing Detection Tool
----------------------------
Detects ARP spoofing attacks on a LAN using two active detection techniques:

1. ARP Request Probing  – Sends ARP who-has requests to each host and checks
   whether multiple IP addresses claim the same MAC address (or a single IP
   returns different MAC addresses on successive probes).

2. TCP SYN Injection    – Sends a TCP SYN to a well-known open port and
   compares the source MAC in the IP/Ethernet response with the MAC
   previously returned by ARP.  A mismatch is a strong indicator of an
   on-path MITM / ARP spoofer.

Usage (requires root/CAP_NET_RAW):
    sudo python3 arp_spoof_detector.py --interface eth0 --network 192.168.1.0/24
"""

import argparse
import ipaddress
import logging
import socket
import sys
import time
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

try:
    from scapy.all import (
        ARP,
        Ether,
        IP,
        TCP,
        conf,
        get_if_hwaddr,
        srp,
        sr1,
    )
except ImportError:
    sys.exit(
        "Scapy is not installed. Install it with:  pip install scapy"
    )

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# Ports to probe during TCP SYN detection (tried in order, first open one is used)
TCP_PROBE_PORTS = [80, 443, 22, 8080]

# Seconds to wait for each probe response
ARP_TIMEOUT = 2
TCP_TIMEOUT = 2


# ---------------------------------------------------------------------------
# ARP Request Probing
# ---------------------------------------------------------------------------

def arp_scan(interface: str, network: str, timeout: int = ARP_TIMEOUT) -> Dict[str, List[str]]:
    """
    Send ARP who-has requests to every host in *network* and return a mapping
    of ``{ ip_address: [mac_address, ...] }``.

    Running the scan twice and merging results helps surface transient
    spoofing responses that may not appear in a single pass.
    """
    ip_to_macs: Dict[str, List[str]] = defaultdict(list)

    logger.info("ARP scan: probing %s on interface %s", network, interface)

    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network)
    answered, _ = srp(pkt, iface=interface, timeout=timeout, verbose=False)

    for _, rcv in answered:
        ip = rcv[ARP].psrc
        mac = rcv[ARP].hwsrc.lower()
        if mac not in ip_to_macs[ip]:
            ip_to_macs[ip].append(mac)

    return dict(ip_to_macs)


def detect_arp_conflicts(ip_to_macs: Dict[str, List[str]]) -> List[Tuple[str, List[str]]]:
    """
    Return a list of ``(ip, [mac1, mac2, ...])``) entries where more than one
    MAC address responded for the same IP – a classic ARP poisoning symptom.
    """
    conflicts = [
        (ip, macs)
        for ip, macs in ip_to_macs.items()
        if len(macs) > 1
    ]
    return conflicts


def build_mac_to_ips(ip_to_macs: Dict[str, List[str]]) -> Dict[str, List[str]]:
    """Invert the ip→macs mapping to mac→[ips] for gratuitous-ARP detection."""
    mac_to_ips: Dict[str, List[str]] = defaultdict(list)
    for ip, macs in ip_to_macs.items():
        for mac in macs:
            if ip not in mac_to_ips[mac]:
                mac_to_ips[mac].append(ip)
    return dict(mac_to_ips)


# ---------------------------------------------------------------------------
# TCP SYN Injection
# ---------------------------------------------------------------------------

def resolve_arp(interface: str, target_ip: str, timeout: int = ARP_TIMEOUT) -> Optional[str]:
    """
    Return the MAC address for *target_ip* via a unicast ARP request,
    or ``None`` if no reply is received.
    """
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip)
    answered, _ = srp(pkt, iface=interface, timeout=timeout, verbose=False)
    if answered:
        return answered[0][1][ARP].hwsrc.lower()
    return None


def tcp_syn_probe(
    interface: str,
    target_ip: str,
    ports: List[int] = TCP_PROBE_PORTS,
    timeout: int = TCP_TIMEOUT,
) -> Optional[Tuple[str, int]]:
    """
    Send a TCP SYN to each port in *ports* and return
    ``(src_mac_of_reply, port)`` for the first SYN-ACK/RST received, or
    ``None`` if all ports are unreachable / filtered.

    The source MAC in the Ethernet frame of the reply must belong to the
    genuine target host.  If a MITM is intercepting traffic the reply's
    Ethernet source will be the attacker's MAC instead.
    """
    my_mac = get_if_hwaddr(interface)

    for port in ports:
        pkt = (
            Ether(src=my_mac)
            / IP(dst=target_ip)
            / TCP(dport=port, flags="S", seq=12345)
        )
        reply = sr1(pkt, iface=interface, timeout=timeout, verbose=False)
        if reply is not None and TCP in reply:
            tcp_flags = reply[TCP].flags
            # Accept SYN-ACK (0x12) or RST (0x04) – both prove connectivity
            if tcp_flags & 0x12 or tcp_flags & 0x04:
                src_mac = reply[Ether].src.lower()
                return src_mac, port

    return None


def tcp_syn_detection(
    interface: str,
    ip_to_macs: Dict[str, List[str]],
    ports: List[int] = TCP_PROBE_PORTS,
    timeout: int = TCP_TIMEOUT,
) -> List[Tuple[str, str, str]]:
    """
    For every live host discovered via ARP, inject a TCP SYN and compare the
    Ethernet source MAC of the reply to the ARP-reported MAC.

    Returns a list of ``(ip, arp_mac, tcp_reply_mac)`` tuples where a mismatch
    was observed.
    """
    mismatches: List[Tuple[str, str, str]] = []

    for ip, macs in ip_to_macs.items():
        arp_mac = macs[0]  # use first (or only) ARP-reported MAC
        result = tcp_syn_probe(interface, ip, ports=ports, timeout=timeout)
        if result is None:
            logger.debug("TCP SYN probe to %s: no response on any port", ip)
            continue

        tcp_mac, port = result
        logger.debug(
            "TCP SYN probe %s port %d: ARP MAC=%s  TCP reply MAC=%s",
            ip, port, arp_mac, tcp_mac,
        )

        if tcp_mac != arp_mac:
            mismatches.append((ip, arp_mac, tcp_mac))

    return mismatches


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_report(
    ip_to_macs: Dict[str, List[str]],
    arp_conflicts: List[Tuple[str, List[str]]],
    mac_to_ips: Dict[str, List[str]],
    tcp_mismatches: List[Tuple[str, str, str]],
) -> None:
    """Print a human-readable detection report to stdout."""
    divider = "=" * 65

    print(f"\n{divider}")
    print("  ARP SPOOFING DETECTION REPORT")
    print(divider)

    # Summary table of discovered hosts
    print("\n[*] Discovered hosts (ARP scan):")
    if ip_to_macs:
        print(f"    {'IP Address':<20} {'MAC Address(es)'}")
        print(f"    {'-'*20} {'-'*40}")
        for ip, macs in sorted(ip_to_macs.items(), key=lambda x: socket.inet_aton(x[0])):
            print(f"    {ip:<20} {', '.join(macs)}")
    else:
        print("    No hosts found.")

    # ARP conflict detection
    print(f"\n[*] ARP conflict check  (multiple MACs for same IP):")
    if arp_conflicts:
        for ip, macs in arp_conflicts:
            print(f"    [!] ALERT  {ip} -> {', '.join(macs)}")
    else:
        print("    No conflicts detected.")

    # One MAC claiming multiple IPs (possible gateway impersonation)
    print(f"\n[*] MAC-to-IP check  (one MAC claiming multiple IPs):")
    suspicious_macs = {mac: ips for mac, ips in mac_to_ips.items() if len(ips) > 1}
    if suspicious_macs:
        for mac, ips in suspicious_macs.items():
            print(f"    [!] ALERT  {mac} claims IPs: {', '.join(ips)}")
    else:
        print("    No suspicious entries detected.")

    # TCP SYN mismatch detection
    print(f"\n[*] TCP SYN injection check  (ARP MAC vs TCP-reply MAC):")
    if tcp_mismatches:
        for ip, arp_mac, tcp_mac in tcp_mismatches:
            print(
                f"    [!] ALERT  {ip}  ARP says {arp_mac}  "
                f"but TCP reply came from {tcp_mac}"
            )
    else:
        print("    No mismatches detected.")

    # Overall verdict
    total_alerts = len(arp_conflicts) + len(suspicious_macs) + len(tcp_mismatches)
    print(f"\n{divider}")
    if total_alerts:
        print(f"  RESULT: {total_alerts} suspicious indicator(s) found – possible ARP spoofing!")
    else:
        print("  RESULT: No ARP spoofing indicators detected.")
    print(f"{divider}\n")


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Detect ARP spoofing using ARP request probing and TCP SYN injection.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--interface", "-i",
        required=True,
        help="Network interface to use (e.g. eth0, wlan0)",
    )
    parser.add_argument(
        "--network", "-n",
        required=True,
        help="Target network in CIDR notation (e.g. 192.168.1.0/24)",
    )
    parser.add_argument(
        "--arp-timeout",
        type=int,
        default=ARP_TIMEOUT,
        help="Seconds to wait for ARP replies",
    )
    parser.add_argument(
        "--tcp-timeout",
        type=int,
        default=TCP_TIMEOUT,
        help="Seconds to wait for TCP SYN replies",
    )
    parser.add_argument(
        "--tcp-ports",
        default=",".join(map(str, TCP_PROBE_PORTS)),
        help="Comma-separated TCP ports to probe (e.g. 80,443,22)",
    )
    parser.add_argument(
        "--no-tcp",
        action="store_true",
        help="Skip TCP SYN injection (ARP probing only)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose / debug output",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        conf.verb = 1
    else:
        conf.verb = 0

    # Validate network
    try:
        ipaddress.ip_network(args.network, strict=False)
    except ValueError as exc:
        sys.exit(f"Invalid network: {exc}")

    # Parse TCP ports
    try:
        tcp_ports = [int(p.strip()) for p in args.tcp_ports.split(",")]
    except ValueError:
        sys.exit("--tcp-ports must be a comma-separated list of integers")

    # --- Step 1: ARP scan ------------------------------------------------
    ip_to_macs = arp_scan(args.interface, args.network, timeout=args.arp_timeout)

    # Run a second pass and merge to catch intermittent spoof replies
    logger.info("ARP scan: running second pass to catch intermittent replies ...")
    time.sleep(1)
    ip_to_macs2 = arp_scan(args.interface, args.network, timeout=args.arp_timeout)
    for ip, macs in ip_to_macs2.items():
        for mac in macs:
            if mac not in ip_to_macs.get(ip, []):
                ip_to_macs.setdefault(ip, []).append(mac)

    arp_conflicts = detect_arp_conflicts(ip_to_macs)
    mac_to_ips = build_mac_to_ips(ip_to_macs)

    # --- Step 2: TCP SYN injection ---------------------------------------
    tcp_mismatches: List[Tuple[str, str, str]] = []
    if not args.no_tcp:
        logger.info("TCP SYN injection: probing %d live host(s) ...", len(ip_to_macs))
        tcp_mismatches = tcp_syn_detection(
            args.interface,
            ip_to_macs,
            ports=tcp_ports,
            timeout=args.tcp_timeout,
        )
    else:
        logger.info("TCP SYN injection skipped (--no-tcp).")

    # --- Step 3: Report --------------------------------------------------
    print_report(ip_to_macs, arp_conflicts, mac_to_ips, tcp_mismatches)


if __name__ == "__main__":
    main()
