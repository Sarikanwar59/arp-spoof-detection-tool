from __future__ import annotations

import subprocess
from dataclasses import dataclass
from ipaddress import ip_address
from typing import Iterable

from .models import ProbeObservation


class NetworkError(RuntimeError):
    pass


@dataclass(frozen=True)
class GatewayInfo:
    address: str
    interface: str | None = None


def _load_scapy():
    try:
        from scapy.all import ARP, Ether, IP, TCP, conf, getmacbyip, sr1, srp  # type: ignore
    except Exception as exc:  # pragma: no cover - import path depends on environment
        raise NetworkError(
            "scapy is required for active probes; install it or run in dry-run mode"
        ) from exc
    return ARP, Ether, IP, TCP, conf, getmacbyip, sr1, srp


def default_gateway() -> GatewayInfo:
    try:
        output = subprocess.check_output(["ip", "route", "show", "default"], text=True)
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        raise NetworkError("unable to determine the default gateway") from exc

    for line in output.splitlines():
        parts = line.split()
        if "default" not in parts or "via" not in parts:
            continue
        via_index = parts.index("via") + 1
        gateway = parts[via_index]
        interface = None
        if "dev" in parts:
            interface = parts[parts.index("dev") + 1]
        return GatewayInfo(address=gateway, interface=interface)

    raise NetworkError("no default gateway could be parsed")


def arp_cache() -> list[ProbeObservation]:
    try:
        output = subprocess.check_output(["ip", "neigh", "show"], text=True)
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        raise NetworkError("unable to read ARP cache") from exc

    observations: list[ProbeObservation] = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        ip = parts[0]
        if _is_ip_address(ip) and "lladdr" in parts:
            mac = parts[parts.index("lladdr") + 1]
            observations.append(ProbeObservation(ip=ip, mac=mac, source="arp-cache"))
    return observations


def probe_arp(ip: str, timeout: int = 2) -> list[ProbeObservation]:
    if not _is_ip_address(ip):
        raise NetworkError(f"invalid IP address: {ip}")

    ARP, Ether, *_rest, srp = _load_scapy()
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)

    try:
        answered, _ = srp(packet, timeout=timeout, verbose=False)
    except Exception as exc:  # pragma: no cover - scapy runtime behavior depends on privileges
        raise NetworkError(f"ARP probe failed for {ip}") from exc

    observations: list[ProbeObservation] = []
    for _, response in answered:
        response_ip = getattr(response, "psrc", ip)
        response_mac = getattr(response, "hwsrc", "unknown")
        observations.append(ProbeObservation(ip=response_ip, mac=response_mac, source="arp"))
    return observations


def probe_tcp_syn(ip: str, ports: Iterable[int], timeout: int = 2) -> list[ProbeObservation]:
    if not _is_ip_address(ip):
        raise NetworkError(f"invalid IP address: {ip}")

    ARP, Ether, IP, TCP, conf, getmacbyip, sr1, srp = _load_scapy()
    conf.verb = 0

    observations: list[ProbeObservation] = []
    destination_mac = getmacbyip(ip) or "ff:ff:ff:ff:ff:ff"

    for port in ports:
        packet = Ether(dst=destination_mac) / IP(dst=ip) / TCP(dport=port, flags="S")
        try:
            answered, _ = srp(packet, timeout=timeout, verbose=False)
        except Exception as exc:  # pragma: no cover - depends on local network permissions
            raise NetworkError(f"TCP SYN probe failed for {ip}:{port}") from exc

        for _, response in answered:
            ether_layer = response.getlayer(Ether)
            ip_layer = response.getlayer(IP)
            response_mac = getattr(ether_layer, "src", destination_mac)
            response_ip = getattr(ip_layer, "src", ip)
            observations.append(
                ProbeObservation(ip=response_ip, mac=response_mac, source="tcp-syn", port=port)
            )

    return observations


def _is_ip_address(value: str) -> bool:
    try:
        ip_address(value)
    except ValueError:
        return False
    return True
