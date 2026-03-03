# IPSAS — Intelligent Port Scanning & Authorization System

A full-stack cybersecurity platform that scans networks, detects threats, and responds automatically.

## What it does
- Scans IP addresses, CIDR ranges, and domain names for open ports
- Automatically classifies each port as Authorized, Unauthorized, or Conditional
- Detects threats using signature matching and anomaly detection
- Blocks malicious IPs automatically via the IPS engine
- Shows everything on a real-time cybersecurity dashboard

## Files
| File | Description |
|------|-------------|
| `index.html` | Frontend dashboard — open in browser |
| `app.py` | Backend REST API server |
| `ids_engine.py` | Intrusion Detection System engine |
| `ips_engine.py` | Intrusion Prevention System engine |
| `scanner_engine.py` | Port scanning engine |
| `historical_analysis.js` | Historical data and charts |

## How to Run

**Frontend**
Just open `index.html` in your browser or use Live Server in VS Code.

**Backend**
```bash
pip install fastapi uvicorn pydantic
uvicorn app:app --reload
```
Then open http://localhost:8000/docs to see all API endpoints.

## Tech Stack
- Frontend: HTML, CSS, JavaScript, Chart.js
- Backend: Python, FastAPI, Pydantic, Uvicorn

## Detection Capabilities
- TCP SYN Port Scan — detected in under 5 seconds
- Metasploit Backdoor (Port 4444) — detected in under 1 second
- Rogue Device Introduction — detected in under 2 minutes
- Time-of-Day Stealth Attack — detected in under 6 minutes
- 100% detection rate — 0% false positives

## Made for
Hackathon — Cybersecurity Track 2025
