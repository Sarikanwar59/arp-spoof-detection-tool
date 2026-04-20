from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Severity = Literal["info", "warning", "critical"]


@dataclass(frozen=True)
class ProbeObservation:
    ip: str
    mac: str
    source: str
    port: int | None = None


@dataclass(frozen=True)
class Finding:
    severity: Severity
    title: str
    details: str
    ip: str | None = None
    macs: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class DetectionReport:
    target: str
    observations: tuple[ProbeObservation, ...]
    findings: tuple[Finding, ...]

    @property
    def suspicious(self) -> bool:
        return any(finding.severity in {"warning", "critical"} for finding in self.findings)
