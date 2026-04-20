# ARP Spoofing Detection Tool

A lightweight Python security tool that **actively detects ARP spoofing / ARP
poisoning attacks** on a local area network (LAN) using two complementary
techniques:

1. **ARP Request Probing** – broadcasts ARP *who-has* packets and cross-checks
   whether multiple MAC addresses answer for the same IP, or a single MAC
   claims ownership of several IP addresses.
2. **TCP SYN Packet Injection** – sends a TCP SYN to each live host and
   compares the Ethernet source MAC of the TCP reply against the MAC returned
   by ARP.  A mismatch reveals an on-path attacker intercepting traffic.

---

## How It Works

### ARP Request Probing

The Address Resolution Protocol (ARP) maps IP addresses to MAC addresses on a
LAN.  Because ARP has no authentication, an attacker can broadcast forged ARP
replies that associate their own MAC with a legitimate IP (typically the default
gateway).  This causes victim hosts to send traffic through the attacker's
machine — a classic Man-in-the-Middle (MITM) attack.

The tool sends ARP *who-has* requests to every host in the specified CIDR range
and records all replies.  It runs **two passes** (with a short delay) to catch
intermittent or race-condition spoofing responses, then flags:

* **IP conflict** – the same IP answered with more than one MAC address.
* **MAC conflict** – the same MAC address claimed ownership of more than one IP.

### TCP SYN Injection

Even when an attacker sends only *gratuitous* ARP replies (which do not appear
in response to a broadcast), the TCP path may still betray them.  The tool
sends a TCP SYN frame directly addressed to the target IP and inspects the
**Ethernet source MAC** of the incoming SYN-ACK or RST response.

Under normal conditions the Ethernet source MAC of the response matches the MAC
returned by ARP.  If a MITM is present, the TCP reply travels through the
attacker's NIC, so its Ethernet source is the **attacker's MAC** — not the
genuine target MAC reported by ARP.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Python 3.8+ | Tested with 3.9 and 3.11 |
| [Scapy](https://scapy.net/) | Packet crafting / capture library |
| Root / `CAP_NET_RAW` | Required for raw socket access |
| Linux / macOS | Windows support is limited by Scapy's WinPcap/Npcap driver |

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/Sarikanwar59/arp-spoof-detection-tool.git
cd arp-spoof-detection-tool

# 2. (Recommended) Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt
```

---

## Usage

```
sudo python3 arp_spoof_detector.py --interface <IFACE> --network <CIDR> [OPTIONS]
```

### Required Arguments

| Flag | Description |
|---|---|
| `-i / --interface` | Network interface to use (e.g. `eth0`, `wlan0`) |
| `-n / --network` | Target network in CIDR notation (e.g. `192.168.1.0/24`) |

### Optional Arguments

| Flag | Default | Description |
|---|---|---|
| `--arp-timeout` | `2` | Seconds to wait for ARP replies |
| `--tcp-timeout` | `2` | Seconds to wait for TCP SYN replies |
| `--tcp-ports` | `80,443,22,8080` | Comma-separated TCP ports to probe |
| `--no-tcp` | — | Skip TCP SYN injection (ARP probing only) |
| `-v / --verbose` | — | Enable debug-level output |

### Examples

```bash
# Full scan (ARP + TCP) on eth0
sudo python3 arp_spoof_detector.py -i eth0 -n 192.168.1.0/24

# ARP-only scan (no TCP SYN injection)
sudo python3 arp_spoof_detector.py -i eth0 -n 192.168.1.0/24 --no-tcp

# Custom probe ports and verbose output
sudo python3 arp_spoof_detector.py -i wlan0 -n 10.0.0.0/24 \
    --tcp-ports 22,80 --arp-timeout 3 -v
```

---

## Sample Output

```
2026-04-20 08:00:01  INFO      ARP scan: probing 192.168.1.0/24 on interface eth0
2026-04-20 08:00:05  INFO      ARP scan: running second pass to catch intermittent replies …
2026-04-20 08:00:09  INFO      TCP SYN injection: probing 5 live host(s) …

=================================================================
  ARP SPOOFING DETECTION REPORT
=================================================================

[*] Discovered hosts (ARP scan):
    IP Address           MAC Address(es)
    -------------------- ----------------------------------------
    192.168.1.1          aa:bb:cc:dd:ee:ff
    192.168.1.10         11:22:33:44:55:66
    192.168.1.20         aa:bb:cc:dd:ee:ff, 77:88:99:aa:bb:cc

[*] ARP conflict check  (multiple MACs for same IP):
    [!] ALERT  192.168.1.20 -> aa:bb:cc:dd:ee:ff, 77:88:99:aa:bb:cc

[*] MAC-to-IP check  (one MAC claiming multiple IPs):
    [!] ALERT  aa:bb:cc:dd:ee:ff claims IPs: 192.168.1.1, 192.168.1.20

[*] TCP SYN injection check  (ARP MAC vs TCP-reply MAC):
    [!] ALERT  192.168.1.1  ARP says aa:bb:cc:dd:ee:ff  but TCP reply came from 77:88:99:aa:bb:cc

=================================================================
  RESULT: 3 suspicious indicator(s) found – possible ARP spoofing!
=================================================================
```

---

## Project Structure

```
arp-spoof-detection-tool/
├── arp_spoof_detector.py   # Main detection script
├── requirements.txt        # Python dependencies
└── README.md               # This file
```

---

## Limitations & Notes

* **Active probing** generates network traffic; use only on networks you own or
  have explicit permission to test.
* TCP SYN injection requires at least one open (or RST-returning) port on the
  target host.  Hosts behind a stateful firewall that drops all inbound SYNs
  will not be checked by the TCP path.
* The tool is designed for **detection**, not prevention.  Use it alongside
  dynamic ARP inspection (DAI) on managed switches for defence-in-depth.
* Scapy requires raw socket privileges (`sudo` / `CAP_NET_RAW`).

---

## License

This project is released for educational and authorised security-testing
purposes only.  The author assumes no liability for misuse.
