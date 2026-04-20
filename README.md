# arp-spoof-detection-tool

Active ARP spoofing detection for LAN environments. The tool combines ARP cache inspection with active ARP and TCP SYN probes to look for inconsistent MAC address responses that often indicate spoofing or MITM activity.

## Features

- Reads the local ARP cache for quick baseline signals
- Sends active ARP requests to a chosen target or the default gateway
- Sends TCP SYN probes on configurable ports
- Reports findings as text or JSON
- Returns a non-zero exit code when suspicious indicators are detected

## Install

```bash
python -m pip install -e .
```

For test tooling:

```bash
python -m pip install -e .[test]
```

Scapy is required for active probing. On Linux, raw packet probes typically need elevated privileges.

## Usage

Scan the default gateway:

```bash
arp-spoof-detection-tool
```

Scan a specific host:

```bash
arp-spoof-detection-tool --target 192.168.1.10 --ports 22 80 443
```

Emit JSON:

```bash
arp-spoof-detection-tool --json
```

## Notes

The detection rules are intentionally compact and testable offline. The network probe layer is isolated so it can be extended later with additional packet checks or platform-specific fallbacks.

When raw-socket privileges are not available, the tool still runs and reports informational findings for skipped active probe steps instead of exiting with an error.
