import pytest

from arp_spoof_detection_tool.detector import analyze_observations
from arp_spoof_detection_tool.detector import DetectionConfig, Detector
from arp_spoof_detection_tool.models import ProbeObservation
from arp_spoof_detection_tool.network import NetworkError


def test_analyze_observations_flags_conflicting_macs():
    report = analyze_observations(
        "192.168.1.1",
        [
            ProbeObservation(ip="192.168.1.1", mac="aa:bb:cc:dd:ee:ff", source="arp"),
            ProbeObservation(ip="192.168.1.1", mac="11:22:33:44:55:66", source="tcp-syn"),
        ],
    )

    assert any(finding.severity == "critical" for finding in report)


def test_analyze_observations_returns_info_for_consistent_data():
    report = analyze_observations(
        "192.168.1.1",
        [ProbeObservation(ip="192.168.1.1", mac="aa:bb:cc:dd:ee:ff", source="arp")],
    )

    assert len(report) == 1
    assert report[0].severity == "info"


def test_detector_adds_warning_when_active_probe_unavailable(monkeypatch):
    monkeypatch.setattr("arp_spoof_detection_tool.detector._has_raw_socket_permissions", lambda: True)
    monkeypatch.setattr("arp_spoof_detection_tool.detector.arp_cache", lambda: [])
    monkeypatch.setattr(
        "arp_spoof_detection_tool.detector.probe_arp",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(NetworkError("permission denied")),
    )
    monkeypatch.setattr(
        "arp_spoof_detection_tool.detector.probe_tcp_syn",
        lambda *_args, **_kwargs: [],
    )

    report = Detector(DetectionConfig(target_ip="192.168.1.1")).run()

    assert any(f.severity == "info" and "Probe step unavailable" in f.title for f in report.findings)


def test_detector_raises_for_invalid_ip(monkeypatch):
    monkeypatch.setattr("arp_spoof_detection_tool.detector._has_raw_socket_permissions", lambda: True)
    monkeypatch.setattr("arp_spoof_detection_tool.detector.arp_cache", lambda: [])
    monkeypatch.setattr(
        "arp_spoof_detection_tool.detector.probe_arp",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(NetworkError("invalid IP address: bad")),
    )

    with pytest.raises(NetworkError):
        Detector(DetectionConfig(target_ip="bad")).run()


def test_detector_skips_raw_probes_without_privileges(monkeypatch):
    monkeypatch.setattr("arp_spoof_detection_tool.detector._has_raw_socket_permissions", lambda: False)
    monkeypatch.setattr("arp_spoof_detection_tool.detector.arp_cache", lambda: [])

    report = Detector(DetectionConfig(target_ip="192.168.1.1", include_tcp_syn=True)).run()

    probe_unavailable = [f for f in report.findings if f.title == "Probe step unavailable"]
    assert len(probe_unavailable) == 2
    assert all(f.severity == "info" for f in probe_unavailable)
