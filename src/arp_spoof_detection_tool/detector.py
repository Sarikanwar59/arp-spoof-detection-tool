from __future__ import annotations

import os
from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable

from .models import DetectionReport, Finding, ProbeObservation
from .network import NetworkError, arp_cache, default_gateway, probe_arp, probe_tcp_syn


@dataclass(frozen=True)
class DetectionConfig:
    target_ip: str | None = None
    tcp_ports: tuple[int, ...] = (80, 443)
    include_arp_cache: bool = True
    include_tcp_syn: bool = True
    active_timeout: int = 2


class Detector:
    def __init__(self, config: DetectionConfig | None = None):
        self.config = config or DetectionConfig()

    def run(self) -> DetectionReport:
        if self.config.target_ip is None:
            gateway = default_gateway().address
            target = gateway
        else:
            target = self.config.target_ip

        observations: list[ProbeObservation] = []
        probe_warnings: list[str] = []
        can_send_raw = _has_raw_socket_permissions()

        if self.config.include_arp_cache:
            try:
                observations.extend(arp_cache())
            except NetworkError as exc:
                probe_warnings.append(f"ARP cache unavailable: {exc}")

        if can_send_raw:
            try:
                observations.extend(probe_arp(target, timeout=self.config.active_timeout))
            except NetworkError as exc:
                if "invalid IP address" in str(exc):
                    raise
                probe_warnings.append(f"ARP probe unavailable: {exc}")
        else:
            probe_warnings.append("ARP probe unavailable: raw-socket privileges are required")

        if self.config.include_tcp_syn:
            if can_send_raw:
                try:
                    observations.extend(
                        probe_tcp_syn(target, self.config.tcp_ports, timeout=self.config.active_timeout)
                    )
                except NetworkError as exc:
                    if "invalid IP address" in str(exc):
                        raise
                    probe_warnings.append(f"TCP SYN probe unavailable: {exc}")
            else:
                probe_warnings.append(
                    "TCP SYN probe unavailable: raw-socket privileges are required"
                )

        findings = analyze_observations(target, observations)

        for warning in probe_warnings:
            findings.append(
                Finding(
                    severity="info",
                    title="Probe step unavailable",
                    details=warning,
                    ip=target,
                )
            )

        return DetectionReport(target=target, observations=tuple(observations), findings=tuple(findings))


def analyze_observations(target: str, observations: Iterable[ProbeObservation]) -> list[Finding]:
    by_ip: dict[str, set[str]] = defaultdict(set)
    by_source: dict[str, set[str]] = defaultdict(set)
    ordered_observations = list(observations)

    for observation in ordered_observations:
        by_ip[observation.ip].add(observation.mac.lower())
        by_source[observation.source].add(observation.mac.lower())

    findings: list[Finding] = []

    target_macs = sorted(by_ip.get(target, set()))
    if len(target_macs) > 1:
        findings.append(
            Finding(
                severity="critical",
                title="Multiple MAC addresses seen for target",
                details=f"The target {target} replied with more than one MAC address: {', '.join(target_macs)}.",
                ip=target,
                macs=tuple(target_macs),
            )
        )
    elif len(target_macs) == 1:
        mac = target_macs[0]
        source_mac_sets = {frozenset(macs) for macs in by_source.values() if macs}
        if len(source_mac_sets) > 1:
            findings.append(
                Finding(
                    severity="warning",
                    title="Target MAC differs across probe methods",
                    details=f"The target {target} consistently replied as {mac}, but different probe methods observed different MAC sets.",
                    ip=target,
                    macs=(mac,),
                )
            )

    for ip, macs in sorted(by_ip.items()):
        if len(macs) > 1:
            findings.append(
                Finding(
                    severity="critical",
                    title="Conflicting MAC addresses detected",
                    details=f"IP {ip} replied with multiple MAC addresses: {', '.join(sorted(macs))}.",
                    ip=ip,
                    macs=tuple(sorted(macs)),
                )
            )

    if not findings:
        findings.append(
            Finding(
                severity="info",
                title="No obvious spoofing indicators",
                details=f"Observed replies for {target} were internally consistent.",
                ip=target,
            )
        )

    return findings


def _has_raw_socket_permissions() -> bool:
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None:
        return True
    return geteuid() == 0
