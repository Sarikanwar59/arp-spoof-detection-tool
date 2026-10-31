from __future__ import annotations

import subprocess
import platform
import re
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
    if platform.system() == "Windows":
        try:
            output = subprocess.check_output(
                ["route", "print", "-4"],
                text=True,
                timeout=5,
                errors="replace",
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise NetworkError(
                "unable to determine the default gateway"
            ) from exc

        for line in output.splitlines():
            parts = line.split()
            if (
                len(parts) >= 4
                and parts[0] == "0.0.0.0"
                and parts[1] == "0.0.0.0"
                and _is_ip_address(parts[2])
                and parts[2] != "0.0.0.0"
            ):
                return GatewayInfo(
                    address=parts[2],
                    interface=parts[3],
                )
        raise NetworkError("no Windows default gateway could be parsed")

    try:
        output = subprocess.check_output(
            ["ip", "route", "show", "default"],
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise NetworkError("unable to determine the default gateway") from exc

    for line in output.splitlines():
        parts = line.split()
        if "default" not in parts or "via" not in parts:
            continue
        gateway = parts[parts.index("via") + 1]
        interface = None
        if "dev" in parts:
            interface = parts[parts.index("dev") + 1]
        return GatewayInfo(address=gateway, interface=interface)

    raise NetworkError("no default gateway could be parsed")





def arp_cache() -> list[ProbeObservation]:
    system = platform.system()

    if system == "Windows":
        try:
            gateway = default_gateway()
            interface_ip = gateway.interface
        except NetworkError:
            interface_ip = None

        try:
            output = subprocess.check_output(
                ["arp", "-a"],
                text=True,
                timeout=5,
                errors="replace",
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise NetworkError("unable to read ARP cache") from exc

        observations = []
        selected_interface = False

        for line in output.splitlines():
            parts = line.split()

            if not parts:
                continue

            if parts[0] == "Interface:":
                current_ip = parts[1] if len(parts) > 1 else None
                selected_interface = current_ip == interface_ip
                continue

            if not selected_interface or not _is_ip_address(parts[0]):
                continue

            address = ip_address(parts[0])

            if address.version != 4 or not address.is_private:
                continue

            if len(parts) < 3:
                continue

            mac = parts[1].replace("-", ":").lower()

            if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
                continue

            if mac == "00:00:00:00:00:00":
                continue

            if int(mac[:2], 16) & 1:
                continue

            observations.append(
                ProbeObservation(
                    ip=str(address),
                    mac=mac,
                    source="arp-cache",
                )
            )

        return observations

    if system == "Linux":
        command = ["ip", "neigh", "show"]
    elif system == "Darwin":
        command = ["arp", "-a"]
    else:
        raise NetworkError(f"unsupported operating system: {system}")

    try:
        output = subprocess.check_output(
            command,
            text=True,
            timeout=5,
            errors="replace",
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise NetworkError("unable to read ARP cache") from exc

    observations = []

    for line in output.splitlines():
        parts = line.split()

        if not parts or not _is_ip_address(parts[0]):
            continue

        mac = None

        if system == "Linux" and "lladdr" in parts:
            index = parts.index("lladdr")
            if index + 1 < len(parts):
                mac = parts[index + 1]

        if mac:
            observations.append(
                ProbeObservation(
                    ip=parts[0],
                    mac=mac.lower(),
                    source="arp-cache",
                )
            )

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
