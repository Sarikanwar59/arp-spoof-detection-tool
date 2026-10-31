# ARP Shield Project Report

## 1. Project Overview

ARP Shield is a Python-based network security tool for detecting possible ARP spoofing and man-in-the-middle activity on a local area network. It compares ARP cache entries and active probe responses to identify inconsistent IP-to-MAC address mappings.

The project now includes:

- A reusable detection engine.
- A command-line interface.
- A FastAPI backend.
- A browser-based frontend.
- Automated tests for the core detection and CLI behavior.

## 2. Objectives

The project was designed to:

1. Inspect the local ARP cache for IP-to-MAC mappings.
2. Probe a selected host, or the default gateway, using ARP requests.
3. Optionally send TCP SYN probes to configured ports.
4. Detect conflicting MAC addresses associated with the same IP address.
5. Report results in text, JSON, or through a web dashboard.
6. Continue operating when active probing is unavailable, while reporting the limitation.

## 3. Technology Stack

| Layer | Technology |
|---|---|
| Language | Python 3.10+ |
| Packet/network probing | Scapy |
| Backend API | FastAPI |
| Web server | Uvicorn |
| Frontend | HTML, CSS, vanilla JavaScript |
| Testing | pytest |
| Packaging | setuptools with `pyproject.toml` |

## 4. System Architecture

```text
Browser
   |
   | HTTP
   v
FastAPI API
   |
   v
Detector
   |
   +--> ARP cache reader
   +--> Active ARP probe
   +--> TCP SYN probe
   |
   v
Observation analysis
   |
   v
Detection report
```

### Main components

- `network.py`: Network discovery, ARP cache access, ARP probing, and TCP SYN probing.
- `detector.py`: Coordinates probes and analyzes observations.
- `models.py`: Defines reports, findings, and observations.
- `cli.py`: Provides the command-line interface.
- `api.py`: Provides the FastAPI backend and serves the frontend.
- `static/index.html`: Browser dashboard markup.
- `static/app.js`: Scan form submission and result rendering.
- `static/styles.css`: Dashboard styling and responsive layout.

## 5. Detection Logic

The detector groups observations by IP address and records all MAC addresses observed for each IP.

### Finding severity

- **Critical**: More than one MAC address is observed for the same IP.
- **Warning**: Probe methods produce different MAC address sets.
- **Info**: Observations are internally consistent or a probe step is unavailable.

The report is marked suspicious when it contains a warning or critical finding.

## 6. Backend API

The backend is implemented in [api.py](src/arp_spoof_detection_tool/api.py).

### Health check

```http
GET /health
```

Example response:

```json
{
  "status": "ok"
}
```

### Run a scan

```http
POST /api/scans
Content-Type: application/json
```

Example request:

```json
{
  "target": "192.168.1.1",
  "ports": [80, 443],
  "include_arp_cache": true,
  "include_tcp_syn": true,
  "timeout": 2
}
```

The `target` field may be omitted or set to `null` to request default-gateway detection.

Example response shape:

```json
{
  "target": "192.168.1.1",
  "suspicious": false,
  "findings": [],
  "observations": []
}
```

Interactive API documentation is available at `/docs`, and the OpenAPI schema is available at `/openapi.json`.

## 7. Frontend

The frontend is served from the FastAPI application at:

```text
http://127.0.0.1:8000/
```

The dashboard provides:

- Target IP input.
- TCP port configuration.
- Probe timeout configuration.
- ARP cache enable/disable control.
- TCP SYN probe enable/disable control.
- Scan progress and error status.
- Suspicious/no-threat result badge.
- Findings list with severity highlighting.
- Network observation list.

The frontend uses the Fetch API to call `POST /api/scans` and renders the returned JSON report without requiring a frontend build system.

## 8. Command-Line Interface

Install the package in editable mode:

```powershell
python -m pip install -e .
```

Run a scan:

```powershell
arp-spoof-detection-tool --target 192.168.1.1
```

Emit JSON:

```powershell
arp-spoof-detection-tool --target 192.168.1.1 --json
```

Run without active TCP probing:

```powershell
arp-spoof-detection-tool --target 192.168.1.1 --no-tcp-syn
```

## 9. Running the Web Application

Install web dependencies:

```powershell
python -m pip install -e ".[web]"
```

Start the backend and frontend:

```powershell
python -m uvicorn arp_spoof_detection_tool.api:app --host 127.0.0.1 --port 8000
```

Then open:

```text
http://127.0.0.1:8000/
```

## 10. Testing and Verification

The existing automated test suite was executed successfully:

```text
6 passed
```

The web application was also verified with:

- `GET /health` returning HTTP `200`.
- `GET /` returning the ARP Shield frontend.
- `GET /openapi.json` returning HTTP `200`.
- `POST /api/scans` returning a valid detection report.

## 11. Current Platform Limitations

### Windows gateway discovery

The current default-gateway implementation uses the Linux command:

```text
ip route show default
```

Therefore, automatic gateway discovery does not work on a standard Windows installation. On Windows, provide an explicit `--target` value or enter a target in the web interface.

### Packet-capture support

Scapy active probing may require a packet-capture provider and elevated privileges. On Windows, a provider such as Npcap may be required for reliable ARP and TCP packet operations.

When raw probing is unavailable, the application reports an informational finding instead of silently treating the probe as successful.

### Security deployment considerations

The current server is intended for local development and trusted LAN use. Before production deployment, add:

- Authentication and authorization.
- HTTPS or a reverse proxy with TLS.
- Request rate limiting.
- Audit logging.
- Access-control restrictions.
- Background job handling for long-running scans.

## 12. Future Improvements

Recommended next steps are:

1. Add Windows-native default-gateway discovery using the Windows routing table.
2. Add platform detection and clearer packet-capture setup guidance.
3. Add scan history and export functionality.
4. Add authenticated users and role-based access.
5. Move long-running scans to background tasks.
6. Add integration tests for the API endpoints.
7. Add configurable interfaces and IPv6-specific checks.
8. Add baseline learning to distinguish expected MAC changes from suspicious changes.

## 13. Conclusion

ARP Shield has a complete working detection core, CLI, HTTP backend, and browser frontend. The application is packaged as a Python project, can be launched locally with Uvicorn, and has passed its current automated test suite. Its primary remaining work is platform hardening, especially Windows gateway discovery and packet-capture configuration, followed by production security features.
