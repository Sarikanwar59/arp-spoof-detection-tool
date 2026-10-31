
from __future__ import annotations

from dataclasses import asdict
from datetime import timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .detector import DetectionConfig, Detector
from .network import NetworkError
from .database import (
    SessionLocal,
    ScanHistory,
    DeviceHistory,
    initialize_database,
)

STATIC_DIR = Path(__file__).parent / "static"

initialize_database()

app = FastAPI(
    title="ARP Spoof Detection API",
    description="HTTP API and web interface for LAN ARP spoofing detection.",
    version="0.2.0",
)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


class ScanRequest(BaseModel):
    target: str | None = Field(
        default=None,
        description="IPv4 or IPv6 target to scan",
    )
    ports: list[int] = Field(default_factory=lambda: [80, 443])
    include_arp_cache: bool = True
    include_tcp_syn: bool = True
    timeout: int = Field(default=2, ge=1, le=30)


def _report_payload(report) -> dict:
    return {
        "target": report.target,
        "suspicious": report.suspicious,
        "findings": [asdict(finding) for finding in report.findings],
        "observations": [
            asdict(observation)
            for observation in report.observations
        ],
    }


@app.get("/", include_in_schema=False)
def frontend() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/scans")
def scan(request: ScanRequest) -> dict:
    config = DetectionConfig(
        target_ip=request.target,
        tcp_ports=tuple(request.ports),
        include_arp_cache=request.include_arp_cache,
        include_tcp_syn=request.include_tcp_syn,
        active_timeout=request.timeout,
    )

    try:
        report = Detector(config).run()
    except NetworkError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    payload = _report_payload(report)

    db = SessionLocal()

    try:
        history = ScanHistory(
            target=report.target,
            suspicious=report.suspicious,
        )

        db.add(history)

        for observation in report.observations:
            db.add(
                DeviceHistory(
                    ip=observation.ip,
                    mac=observation.mac.lower(),
                    source=observation.source,
                )
            )

        db.commit()

        payload["scan_id"] = history.id

    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Unable to save scan history",
        )

    finally:
        db.close()

    return payload


@app.get("/api/history")
def get_scan_history() -> list[dict]:
    db = SessionLocal()

    try:
        records = (
            db.query(ScanHistory)
            .order_by(ScanHistory.id.desc())
            .limit(100)
            .all()
        )

        return [
            {
                "id": record.id,
                "target": record.target,
                "suspicious": record.suspicious,
                "timestamp": record.timestamp.isoformat()
                if record.timestamp else None,
            }
            for record in records
        ]

    finally:
        db.close()



@app.get("/api/devices/mac-changes")
def get_mac_changes() -> list[dict]:
    db = SessionLocal()

    try:
        records = (
            db.query(DeviceHistory)
            .order_by(DeviceHistory.id.asc())
            .all()
        )

        previous_macs = {}
        changes = []

        for record in records:
            ip = record.ip
            mac = record.mac.lower()

            if ip in previous_macs:
                previous_mac = previous_macs[ip]

                if mac != previous_mac:
                    changes.append({
                        "ip": ip,
                        "previous_mac": previous_mac,
                        "current_mac": mac,
                        "source": record.source,
                        "timestamp": (
                            record.timestamp.isoformat()
                            if record.timestamp else None
                        ),
                        "status": "MAC_CHANGE_DETECTED",
                    })

            previous_macs[ip] = mac

        return changes

    finally:
        db.close()