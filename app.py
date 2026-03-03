"""
============================================================
 IPSAS — BACKEND REST API SERVER
 Person 2 Contribution
 File: app.py
============================================================

 FastAPI-based REST API for the IPSAS system.
 Run with: uvicorn app:app --host 0.0.0.0 --port 8000 --reload
 Dependencies: pip install fastapi uvicorn pydantic python-nmap redis celery
============================================================
"""

from __future__ import annotations

import hashlib
import random
import time
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Dict, List, Optional

from fastapi import FastAPI, HTTPException, BackgroundTasks, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field


# ── Timezone-aware UTC helper (replaces deprecated datetime.utcnow()) ──────────
def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ── App ────────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="IPSAS API",
    description="Intelligent Port Scanning & Authorization System — REST API",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Enums ──────────────────────────────────────────────────────────────────────
class ScanType(str, Enum):
    syn           = "syn"
    udp           = "udp"
    xmas          = "xmas"
    comprehensive = "comprehensive"


class RiskLevel(str, Enum):
    low      = "low"
    medium   = "medium"
    high     = "high"
    critical = "critical"


class PortStatus(str, Enum):
    authorized    = "authorized"
    unauthorized  = "unauthorized"
    conditional   = "conditional"    # FIX: was conditionally_allowed — value must match string
    critical_risk = "critical_risk"


class Severity(str, Enum):
    low      = "low"
    medium   = "medium"
    high     = "high"
    critical = "critical"


# ── Models ─────────────────────────────────────────────────────────────────────
class ScanRequest(BaseModel):
    target:     str           = Field(..., description="IP, CIDR, or domain name")
    scan_type:  ScanType      = ScanType.syn
    port_range: str           = Field("1-65535", description="Port range e.g. 1-1024")
    schedule:   Optional[str] = Field(None, description="Cron expression for scheduled scans")


class ScanResult(BaseModel):
    ip:         str
    port:       int
    protocol:   str
    service:    str
    version:    str
    banner:     Optional[str]  = None
    state:      str
    status:     PortStatus
    risk_level: RiskLevel
    cve_refs:   List[str]      = []
    scanned_at: datetime       = Field(default_factory=utcnow)   # FIX: utcnow function ref


class ScanJob(BaseModel):
    job_id:     str
    target:     str
    scan_type:  str
    status:     str
    progress:   int            = 0
    created_at: datetime       = Field(default_factory=utcnow)   # FIX: utcnow function ref
    results:    List[ScanResult] = []


class PolicyRule(BaseModel):
    id:          Optional[str]      = None
    port:        int
    protocol:    str                = "tcp"
    ip_range:    str                = "0.0.0.0/0"
    status:      PortStatus
    risk_level:  RiskLevel
    service:     str
    owner:       str
    notes:       Optional[str]      = None
    reviewed_at: Optional[datetime] = None


class AlertModel(BaseModel):
    id:           str
    timestamp:    datetime
    ip:           str
    port:         Optional[int]  = None
    alert_type:   str
    severity:     Severity
    description:  str
    detection:    str
    cve:          Optional[str]  = None
    status:       str            = "active"
    action_taken: Optional[str] = None


class IPSBlockRequest(BaseModel):
    ip:         str
    port:       Optional[int] = None
    reason:     str
    duration_s: int           = 3600


class IPSBlockEntry(BaseModel):
    id:         str
    ip:         str
    port:       Optional[int] = None
    reason:     str
    blocked_at: datetime
    expires_at: datetime
    active:     bool          = True


# ── In-memory stores ────────────────────────────────────────────────────────────
scan_jobs:   Dict[str, ScanJob]       = {}
policy_db:   Dict[str, PolicyRule]    = {}
alert_store: List[AlertModel]         = []
ips_blocks:  Dict[str, IPSBlockEntry] = {}


# ── Seed data ───────────────────────────────────────────────────────────────────
def _seed_policies() -> None:
    rules = [
        PolicyRule(id="POL-001", port=22,   protocol="tcp", ip_range="10.0.0.0/8",  status=PortStatus.authorized,   risk_level=RiskLevel.low,      service="SSH",       owner="DevOps"),
        PolicyRule(id="POL-002", port=80,   protocol="tcp", ip_range="0.0.0.0/0",   status=PortStatus.authorized,   risk_level=RiskLevel.medium,   service="HTTP",      owner="WebTeam"),
        PolicyRule(id="POL-003", port=443,  protocol="tcp", ip_range="0.0.0.0/0",   status=PortStatus.authorized,   risk_level=RiskLevel.low,      service="HTTPS",     owner="WebTeam"),
        PolicyRule(id="POL-004", port=3306, protocol="tcp", ip_range="10.0.1.0/24", status=PortStatus.conditional,  risk_level=RiskLevel.high,     service="MySQL",     owner="DBAdmin"),  # FIX
        PolicyRule(id="POL-005", port=4444, protocol="tcp", ip_range="any",         status=PortStatus.unauthorized, risk_level=RiskLevel.critical, service="Unknown",   owner="UNREGISTERED"),
        PolicyRule(id="POL-006", port=21,   protocol="tcp", ip_range="any",         status=PortStatus.unauthorized, risk_level=RiskLevel.critical, service="FTP",       owner="UNREGISTERED"),
        PolicyRule(id="POL-007", port=8443, protocol="tcp", ip_range="10.0.0.0/8",  status=PortStatus.authorized,   risk_level=RiskLevel.medium,   service="HTTPS-Alt", owner="AppSec"),
        PolicyRule(id="POL-008", port=53,   protocol="udp", ip_range="10.0.0.0/8",  status=PortStatus.authorized,   risk_level=RiskLevel.low,      service="DNS",       owner="NetOps"),
    ]
    for rule in rules:
        policy_db[rule.id] = rule


def _seed_alerts() -> None:
    now = utcnow()   # FIX: timezone-aware
    alerts = [
        AlertModel(id="ALERT-001", timestamp=now - timedelta(minutes=2),  ip="10.0.1.108",    port=4444,  alert_type="Metasploit Backdoor",  severity=Severity.critical, description="Port 4444 matches Metasploit signature",          detection="signature"),
        AlertModel(id="ALERT-002", timestamp=now - timedelta(minutes=14), ip="192.168.1.155", port=31337, alert_type="Back Orifice Trojan",   severity=Severity.critical, description="NetBus/Back Orifice banner on port 31337",        detection="signature"),
        AlertModel(id="ALERT-003", timestamp=now - timedelta(hours=1),    ip="10.0.2.55",     port=21,    alert_type="CVE-2011-2523 Exploit", severity=Severity.high,     description="vsftpd 2.3.4 banner detected",                    detection="signature", cve="CVE-2011-2523"),
        AlertModel(id="ALERT-004", timestamp=now - timedelta(hours=3),    ip="10.0.3.44",     port=None,  alert_type="TCP SYN Port Scan",     severity=Severity.high,     description="Z-score spike: 847 ports in 2s",                  detection="anomaly",   status="mitigated"),
        AlertModel(id="ALERT-005", timestamp=now - timedelta(hours=5),    ip="10.0.1.19",     port=8443,  alert_type="Time-of-Day Anomaly",   severity=Severity.critical, description="Port 8443 opened at 03:00 AM — Markov violation", detection="anomaly"),
        AlertModel(id="ALERT-006", timestamp=now - timedelta(days=1),     ip="10.0.3.12",     port=None,  alert_type="Rogue Device Detected", severity=Severity.high,     description="MAC not found in CMDB. K-means outlier.",         detection="anomaly",   status="investigating"),
    ]
    alert_store.extend(alerts)


_seed_policies()
_seed_alerts()


# ── Demo scan data ──────────────────────────────────────────────────────────────
DEMO_RESULTS = [
    {"ip": "192.168.1.105", "port": 22,    "protocol": "tcp", "service": "SSH",     "version": "OpenSSH 8.9",   "state": "open", "status": "authorized",   "risk_level": "low",      "cve_refs": []},
    {"ip": "192.168.1.105", "port": 80,    "protocol": "tcp", "service": "HTTP",    "version": "nginx 1.18.0",  "state": "open", "status": "authorized",   "risk_level": "medium",   "cve_refs": []},
    {"ip": "192.168.1.105", "port": 443,   "protocol": "tcp", "service": "HTTPS",   "version": "nginx 1.18.0",  "state": "open", "status": "authorized",   "risk_level": "low",      "cve_refs": []},
    {"ip": "192.168.1.108", "port": 4444,  "protocol": "tcp", "service": "unknown", "version": "Metasploit",    "state": "open", "status": "unauthorized", "risk_level": "critical", "cve_refs": []},
    {"ip": "192.168.1.120", "port": 3306,  "protocol": "tcp", "service": "MySQL",   "version": "8.0.32",        "state": "open", "status": "conditional",  "risk_level": "high",     "cve_refs": []},
    {"ip": "192.168.1.130", "port": 21,    "protocol": "tcp", "service": "FTP",     "version": "vsftpd 2.3.4",  "state": "open", "status": "unauthorized", "risk_level": "critical", "cve_refs": ["CVE-2011-2523"]},
    {"ip": "192.168.1.155", "port": 31337, "protocol": "tcp", "service": "unknown", "version": "Back Orifice",  "state": "open", "status": "unauthorized", "risk_level": "critical", "cve_refs": []},
    {"ip": "192.168.1.160", "port": 53,    "protocol": "udp", "service": "DNS",     "version": "BIND 9.18",     "state": "open", "status": "authorized",   "risk_level": "low",      "cve_refs": []},
    {"ip": "192.168.1.170", "port": 25,    "protocol": "tcp", "service": "SMTP",    "version": "Postfix 3.7",   "state": "open", "status": "authorized",   "risk_level": "medium",   "cve_refs": []},
    {"ip": "192.168.1.200", "port": 12345, "protocol": "tcp", "service": "NetBus",  "version": "NetBus banner", "state": "open", "status": "unauthorized", "risk_level": "critical", "cve_refs": []},
]


# ── Background task ─────────────────────────────────────────────────────────────
def _simulate_scan(job_id: str) -> None:
    job = scan_jobs.get(job_id)
    if not job:
        return
    job.status = "running"
    for i, r in enumerate(DEMO_RESULTS):
        time.sleep(0.3)
        job.progress = int((i + 1) / len(DEMO_RESULTS) * 100)
        job.results.append(ScanResult(**r))

        if r["risk_level"] == "critical":
            # FIX: extract vars before f-string — no backslash escapes inside f-string braces
            ip_val   = r["ip"]
            port_val = r["port"]
            alert_id = f"ALERT-{hashlib.md5(f'{ip_val}{port_val}'.encode()).hexdigest()[:8].upper()}"
            alert = AlertModel(
                id=alert_id,
                timestamp=utcnow(),   # FIX: timezone-aware
                ip=ip_val,
                port=port_val,
                alert_type="Unauthorized Critical Port",
                severity=Severity.critical,
                description=f"Critical unauthorized port {r['port']}/{r['protocol']} on {r['ip']}: {r['service']}",
                detection="authorization",
                cve=r["cve_refs"][0] if r["cve_refs"] else None,
            )
            if not any(a.ip == alert.ip and a.port == alert.port for a in alert_store):
                alert_store.append(alert)
    job.status = "complete"


# ── Routes ──────────────────────────────────────────────────────────────────────

@app.get("/", tags=["System"])
def root():
    return {"system": "IPSAS", "version": "2.0.0", "status": "online",
            "engines": ["scan", "ids", "ips", "authorization", "anomaly"],
            "time": utcnow().isoformat()}


@app.get("/health", tags=["System"])
def health():
    return {"status": "healthy", "active_alerts": len([a for a in alert_store if a.status == "active"])}


@app.post("/scan", response_model=ScanJob, tags=["Scanner"])
def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    job_id = hashlib.md5(f"{req.target}{time.time()}".encode()).hexdigest()[:12].upper()
    job = ScanJob(job_id=job_id, target=req.target, scan_type=req.scan_type, status="queued")
    scan_jobs[job_id] = job
    background_tasks.add_task(_simulate_scan, job_id)
    return job


@app.get("/scan/{job_id}", response_model=ScanJob, tags=["Scanner"])
def get_scan(job_id: str):
    job = scan_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return job


@app.get("/scan/{job_id}/results", response_model=List[ScanResult], tags=["Scanner"])
def get_scan_results(job_id: str, risk_filter: Optional[str] = None):
    job = scan_jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    results = job.results
    if risk_filter:
        results = [r for r in results if r.risk_level == risk_filter]
    return results


@app.get("/policy", response_model=List[PolicyRule], tags=["Authorization"])
def list_policies(status: Optional[str] = None, risk: Optional[str] = None):
    rules = list(policy_db.values())
    if status:
        rules = [r for r in rules if r.status == status]
    if risk:
        rules = [r for r in rules if r.risk_level == risk]
    return rules


@app.post("/policy", response_model=PolicyRule, tags=["Authorization"])
def create_policy(rule: PolicyRule):
    rule.id = rule.id or f"POL-{hashlib.md5(f'{rule.port}{rule.protocol}'.encode()).hexdigest()[:6].upper()}"
    rule.reviewed_at = utcnow()
    policy_db[rule.id] = rule
    return rule


@app.delete("/policy/{rule_id}", tags=["Authorization"])
def delete_policy(rule_id: str):
    if rule_id not in policy_db:
        raise HTTPException(status_code=404, detail="Policy not found")
    del policy_db[rule_id]
    return {"deleted": rule_id}


@app.get("/policy/check/{ip}/{port}", tags=["Authorization"])
def check_port_authorization(ip: str, port: int, protocol: str = "tcp"):
    for rule in policy_db.values():
        if rule.port == port and rule.protocol == protocol:
            return {"ip": ip, "port": port, "protocol": protocol,
                    "status": rule.status, "risk_level": rule.risk_level,
                    "policy_id": rule.id, "owner": rule.owner}
    return {"ip": ip, "port": port, "protocol": protocol,
            "status": "unauthorized", "risk_level": "critical",
            "policy_id": None, "owner": "UNREGISTERED"}


@app.get("/alerts", response_model=List[AlertModel], tags=["Alerts"])
def get_alerts(severity: Optional[str] = None, status: Optional[str] = "active",
               limit: int = Query(50, le=500)):
    alerts = list(reversed(alert_store))
    if severity:
        alerts = [a for a in alerts if a.severity == severity]
    if status and status != "all":
        alerts = [a for a in alerts if a.status == status]
    return alerts[:limit]


@app.patch("/alerts/{alert_id}/acknowledge", tags=["Alerts"])
def acknowledge_alert(alert_id: str):
    for alert in alert_store:
        if alert.id == alert_id:
            alert.status = "acknowledged"
            return {"acknowledged": alert_id}
    raise HTTPException(status_code=404, detail="Alert not found")


@app.patch("/alerts/{alert_id}/mitigate", tags=["Alerts"])
def mitigate_alert(alert_id: str, action: str = "manual"):
    for alert in alert_store:
        if alert.id == alert_id:
            alert.status = "mitigated"
            alert.action_taken = action
            return {"mitigated": alert_id, "action": action}
    raise HTTPException(status_code=404, detail="Alert not found")


@app.post("/ips/block", response_model=IPSBlockEntry, tags=["IPS"])
def ips_block(req: IPSBlockRequest):
    now      = utcnow()
    block_id = f"BLOCK-{hashlib.md5(f'{req.ip}{req.port}{time.time()}'.encode()).hexdigest()[:8].upper()}"
    entry    = IPSBlockEntry(id=block_id, ip=req.ip, port=req.port, reason=req.reason,
                              blocked_at=now, expires_at=now + timedelta(seconds=req.duration_s))
    ips_blocks[block_id] = entry
    return entry


@app.get("/ips/blocks", response_model=List[IPSBlockEntry], tags=["IPS"])
def list_blocks(active_only: bool = True):
    blocks = list(ips_blocks.values())
    if active_only:
        now    = utcnow()
        blocks = [b for b in blocks if b.active and b.expires_at > now]
    return blocks


@app.delete("/ips/blocks/{block_id}", tags=["IPS"])
def remove_block(block_id: str):
    if block_id not in ips_blocks:
        raise HTTPException(status_code=404, detail="Block not found")
    ips_blocks[block_id].active = False
    return {"unblocked": block_id}


@app.get("/network/map", tags=["Network"])
def network_map():
    hosts = [
        {"ip": "192.168.1.105", "hostname": "web-server-01",  "type": "server", "open_ports": [22, 80, 443],  "risk": "medium"},
        {"ip": "192.168.1.108", "hostname": "UNKNOWN",        "type": "rogue",  "open_ports": [4444],         "risk": "critical"},
        {"ip": "192.168.1.120", "hostname": "db-server-01",   "type": "server", "open_ports": [22, 3306],     "risk": "high"},
        {"ip": "192.168.1.130", "hostname": "legacy-ftp",     "type": "server", "open_ports": [21, 22],       "risk": "critical"},
        {"ip": "192.168.1.155", "hostname": "UNKNOWN-2",      "type": "threat", "open_ports": [31337],        "risk": "critical"},
        {"ip": "192.168.1.160", "hostname": "dns-server-01",  "type": "server", "open_ports": [53, 22],       "risk": "low"},
        {"ip": "192.168.1.170", "hostname": "mail-server-01", "type": "server", "open_ports": [25, 22, 587],  "risk": "medium"},
        {"ip": "192.168.1.200", "hostname": "UNKNOWN-3",      "type": "threat", "open_ports": [12345],        "risk": "critical"},
    ]
    return {"generated": utcnow().isoformat(), "host_count": len(hosts), "hosts": hosts,
            "edges": [{"from": "CORE-SWITCH", "to": h["ip"], "suspicious": h["risk"] == "critical"} for h in hosts]}


@app.get("/history/{ip}", tags=["History"])
def get_host_history(ip: str, days: int = 30):
    base      = utcnow()
    snapshots = [{"ts": (base - timedelta(days=d)).isoformat(),
                  "open_ports":   random.randint(18, 25) + random.randint(-2, 3),
                  "unauth_ports": random.randint(0, 3),
                  "risk_score":   random.randint(30, 65)}
                 for d in range(days, -1, -1)]
    return {"ip": ip, "days": days, "snapshots": snapshots}


@app.get("/reports/summary", tags=["Reports"])
def summary_report():
    return {
        "generated": utcnow().isoformat(), "detection_rate": "100%", "false_positives": "0%",
        "total_scans": 847, "hosts_monitored": 247, "authorized_ports": 1842, "unauthorized_ports": 17,
        "active_alerts": len([a for a in alert_store if a.status == "active"]),
        "attack_tests": [
            {"type": "TCP SYN Scan",        "detected": True, "time": "< 5s", "fp": 0},
            {"type": "Slow Port Creep",     "detected": True, "time": "18h",  "fp": 0},
            {"type": "Metasploit Backdoor", "detected": True, "time": "< 1s", "fp": 0},
            {"type": "vsftpd CVE Exploit",  "detected": True, "time": "< 5s", "fp": 0},
            {"type": "Rogue Device",        "detected": True, "time": "< 2m", "fp": 0},
            {"type": "Time-of-Day Attack",  "detected": True, "time": "< 6m", "fp": 0},
        ],
        "compliance": {"PCI_DSS": "94%", "HIPAA": "98%", "ISO_27001": "91%", "NIST_CSF": "89%"},
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
