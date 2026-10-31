from arp_spoof_detection_tool.cli import render_text
from arp_spoof_detection_tool.models import DetectionReport, Finding, ProbeObservation


def test_render_text_includes_findings_and_observations():
    report = DetectionReport(
        target="192.168.1.1",
        observations=(ProbeObservation(ip="192.168.1.1", mac="aa:bb:cc:dd:ee:ff", source="arp"),),
        findings=(Finding(severity="warning", title="Example", details="Something changed"),),
    )

    output = render_text(report)

    assert "Target: 192.168.1.1" in output
    assert "[warning] Example" in output
    assert "arp -> 192.168.1.1 via aa:bb:cc:dd:ee:ff" in output
