# 🛡️ NetScope

### Network Security Monitoring & SOC Platform

NetScope is a Python-based network security monitoring and Security Operations Center (SOC) platform that captures network traffic, detects suspicious activity, correlates security events, assesses risk, tracks incidents, and presents live telemetry through a web dashboard.

> **Project status:** Release-ready local SOC platform • 131 automated tests passing

---

## ✨ Highlights

- 📡 Live packet capture and traffic analysis with Scapy
- 🔍 Port-scan, SYN-scan, high-activity, DNS-burst, connection-rate and traffic-burst detection
- 🧠 Risk scoring with severity and confidence assessment
- 🌐 Threat-intelligence matching and IOC extraction
- 🚨 Alert deduplication, cooldowns and escalation
- 🔗 Alert correlation into security incidents
- 🕒 Attack-stage timeline and attacker/victim profiling
- 🕵️ Investigation, evidence and response workflows
- 📊 Live SOC dashboard with packet, flow, protocol and alert telemetry
- 📈 Risk-trend and SOC metrics support
- 💾 Persistent SOC/incident storage
- 🧪 Comprehensive automated regression test suite

## 🏗️ Architecture

```text
Network Interface
       │
       ▼
  Scapy Capture
       │
       ▼
┌─────────────────────┐
│ Packet Processing   │
└──────────┬──────────┘
           │
     ┌─────▼─────┐
     │ Detection │
     └─────┬─────┘
           │
   ┌───────▼────────┐
   │ Threat Intel   │
   │ + Risk Engine  │
   └───────┬────────┘
           │
   ┌───────▼────────┐
   │ Correlation    │
   │ + Incidents    │
   └───────┬────────┘
           │
   ┌───────▼──────────────┐
   │ Investigation / SOC  │
   └───────┬──────────────┘
           │
     ┌─────▼─────┐
     │ FastAPI   │
     └─────┬─────┘
           │
     ┌─────▼──────────────┐
     │ Web SOC Dashboard  │
     └────────────────────┘
```

## 🧰 Tech Stack

| Layer | Technology |
|---|---|
| Language | Python |
| Packet capture | Scapy |
| API | FastAPI / Uvicorn |
| Dashboard | HTML, CSS, JavaScript |
| Testing | Pytest |
| Persistence | JSON-based SOC storage |
| Environment | Windows / Linux compatible design |

## 🔐 Detection Pipeline

NetScope combines multiple detection layers:

| Rule | Capability |
|---|---|
| NS-1001 | Port Scan |
| NS-1002 | SYN Scan |
| NS-1003 | High Activity |
| NS-1004 | DNS Request Burst |
| NS-1005 | High Connection Rate |
| NS-1006 | Risk Assessment |
| NS-1007 | Traffic Burst |
| NS-1008 | Threat Intelligence Match |

Alerts are enriched with severity, confidence, evidence, timestamps and rule identifiers before being correlated into SOC incidents.

## 🖥️ Dashboard

The web dashboard provides:

- Network overview
- Live packet table
- Network-flow view
- Security incident queue
- Threat-intelligence workspace
- Attack timeline
- Protocol distribution
- Live packet-rate telemetry
- Search and monitoring controls

Start the API with:

```powershell
python -m uvicorn src.api:app --reload
```

Then open:

```text
http://127.0.0.1:8000/ui
```

## 🚀 Installation

Clone the repository:

```powershell
git clone https://github.com/MAfshaan17/NetScope.git
cd NetScope
```

Create and activate a virtual environment:

```powershell
python -m venv venv
.env\Scripts\Activate.ps1
```

Install dependencies:

```powershell
pip install -r requirements.txt
```

Run the analyzer:

```powershell
python -m src.analyzer
```

Example capture:

```powershell
python -m src.analyzer --count 50
```

Use a specific interface when required:

```powershell
python -m src.analyzer --iface "Ethernet" --count 100
```

## 🧪 Testing

Run the complete regression suite:

```powershell
python -m pytest -q
```

Current release baseline:

```text
131 passed
```

## 📁 Project Structure

```text
NetScope/
├── dashboard/          # Web SOC dashboard
├── src/                # Detection, risk, SOC and API modules
├── tests/              # Automated regression tests
├── requirements.txt    # Python dependencies
├── .gitignore
└── README.md
```

## ⚠️ Operational Notes

NetScope is intended for **authorized networks and systems**. Packet capture may require administrator/root privileges depending on the operating system and capture interface.

The dashboard/API can be hosted remotely, but the packet-capture engine must run where the network traffic is actually observable. A hosted dashboard alone cannot capture traffic from an unrelated local network.

## 🛣️ Roadmap

- Production authentication and role-based access
- Containerized deployment
- PostgreSQL/Redis-backed production storage
- WebSocket-based live telemetry
- Additional threat-intelligence feeds
- PCAP upload and offline investigation workflows
- CI/CD and automated release builds

## 👨‍💻 Author

**MAfshaan17**

GitHub: https://github.com/MAfshaan17

## 📄 License

This project is currently published without a license file. Add a license before distributing or reusing the code under explicit open-source terms.
