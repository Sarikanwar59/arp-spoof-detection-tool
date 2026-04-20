from __future__ import annotations

import argparse
import json

from .detector import DetectionConfig, Detector
from .network import NetworkError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="arp-spoof-detection-tool",
        description="Active ARP spoofing detection for LAN hosts",
    )
    parser.add_argument("--target", help="Target IP to probe. Defaults to the default gateway.")
    parser.add_argument(
        "--ports",
        metavar="PORT",
        type=int,
        nargs="*",
        default=(80, 443),
        help="TCP ports to probe as part of the active detection pass.",
    )
    parser.add_argument(
        "--no-arp-cache",
        action="store_true",
        help="Skip reading the local ARP cache before probing.",
    )
    parser.add_argument(
        "--no-tcp-syn",
        action="store_true",
        help="Skip TCP SYN probing and only perform ARP-based checks.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=2,
        help="Probe timeout in seconds.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit the final report as JSON.",
    )
    return parser


def render_text(report) -> str:
    lines = [f"Target: {report.target}", f"Suspicious: {'yes' if report.suspicious else 'no'}", ""]
    lines.append("Findings:")
    for finding in report.findings:
        lines.append(f"- [{finding.severity}] {finding.title}")
        lines.append(f"  {finding.details}")
    if not report.findings:
        lines.append("- none")
    lines.append("")
    lines.append("Observations:")
    for observation in report.observations:
        suffix = f":{observation.port}" if observation.port is not None else ""
        lines.append(f"- {observation.source} -> {observation.ip}{suffix} via {observation.mac}")
    if not report.observations:
        lines.append("- none")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    config = DetectionConfig(
        target_ip=args.target,
        tcp_ports=tuple(args.ports),
        include_arp_cache=not args.no_arp_cache,
        include_tcp_syn=not args.no_tcp_syn,
        active_timeout=args.timeout,
    )

    try:
        report = Detector(config).run()
    except NetworkError as exc:
        parser.error(str(exc))
        return 2

    if args.json:
        payload = {
            "target": report.target,
            "suspicious": report.suspicious,
            "findings": [finding.__dict__ for finding in report.findings],
            "observations": [observation.__dict__ for observation in report.observations],
        }
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(render_text(report))

    return 1 if report.suspicious else 0


if __name__ == "__main__":
    raise SystemExit(main())
