"""
============================================================
 IPSAS — PORT SCANNER ENGINE
 Person 2 Contribution
 File: scanner_engine.py
============================================================

 Handles all port scanning operations:
   ScanEngine      : Orchestrates multi-protocol scans
   ServiceFingerprinter : Banner grabbing & version detection
   OSDetector      : OS fingerprinting
   AuthorizationChecker : Classifies results per policy DB
   ScanScheduler   : Cron-based continuous / scheduled scanning

 In production:
   - ScanEngine calls python-nmap or subprocess nmap
   - ServiceFingerprinter uses Scapy for raw packet crafting
   - Results stored in InfluxDB time-series DB

============================================================
"""

from __future__ import annotations

import hashlib
import ipaddress
import random
import socket
import struct
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Generator, List, Optional, Tuple

import logging
log = logging.getLogger("ipsas.scanner")


# ─────────────────────────────────────────────
#  DATA CLASSES
# ─────────────────────────────────────────────

class PortState(str, Enum):
    OPEN      = "open"
    CLOSED    = "closed"
    FILTERED  = "filtered"
    UNFILTERED = "unfiltered"


@dataclass
class PortResult:
    ip:           str
    port:         int
    protocol:     str
    state:        PortState
    service:      str            = "unknown"
    version:      str            = ""
    banner:       str            = ""
    os_guess:     str            = ""
    rtt_ms:       float          = 0.0
    scanned_at:   datetime       = field(default_factory=datetime.utcnow)
    extra:        Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "ip":        self.ip,
            "port":      self.port,
            "protocol":  self.protocol,
            "state":     self.state,
            "service":   self.service,
            "version":   self.version,
            "banner":    self.banner,
            "os_guess":  self.os_guess,
            "rtt_ms":    self.rtt_ms,
            "scanned_at": self.scanned_at.isoformat(),
        }


@dataclass
class ScanSummary:
    target:          str
    scan_type:       str
    hosts_up:        int
    hosts_down:      int
    total_ports:     int
    open_ports:      int
    closed_ports:    int
    filtered_ports:  int
    duration_s:      float
    started_at:      datetime
    finished_at:     datetime
    results:         List[PortResult] = field(default_factory=list)


# ─────────────────────────────────────────────
#  SERVICE FINGERPRINTER
# ─────────────────────────────────────────────

# Well-known port to service mapping
WELL_KNOWN_PORTS: Dict[int, Tuple[str, str]] = {
    21:    ("ftp",    "File Transfer Protocol"),
    22:    ("ssh",    "Secure Shell"),
    23:    ("telnet", "Telnet"),
    25:    ("smtp",   "Simple Mail Transfer Protocol"),
    53:    ("dns",    "Domain Name System"),
    80:    ("http",   "Hypertext Transfer Protocol"),
    110:   ("pop3",   "Post Office Protocol v3"),
    143:   ("imap",   "Internet Message Access Protocol"),
    443:   ("https",  "HTTP over TLS/SSL"),
    445:   ("smb",    "Server Message Block"),
    3306:  ("mysql",  "MySQL Database"),
    3389:  ("rdp",    "Remote Desktop Protocol"),
    5432:  ("postgresql", "PostgreSQL Database"),
    5900:  ("vnc",    "Virtual Network Computing"),
    6379:  ("redis",  "Redis In-Memory DB"),
    8080:  ("http-proxy", "HTTP Alternate"),
    8443:  ("https-alt",  "HTTPS Alternate"),
    27017: ("mongodb","MongoDB"),
    4444:  ("msf-handler", "SUSPICIOUS: Metasploit default"),
    31337: ("bo2k",   "SUSPICIOUS: Back Orifice / Elite port"),
    12345: ("netbus", "SUSPICIOUS: NetBus Trojan"),
}

# Simulated banners for demo
DEMO_BANNERS: Dict[int, str] = {
    22:   "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
    80:   "Server: nginx/1.18.0 (Ubuntu)",
    443:  "Server: nginx/1.18.0 (Ubuntu)",
    21:   "220 (vsFTPd 2.3.4)",
    3306: "5.5.62-0+deb8u1",
    4444: "Meterpreter session opened",
    31337:"Back Orifice Remote Administration Tool",
    12345:"NetBus Pro 2.0",
}


class ServiceFingerprinter:
    """
    Identifies service and version from port number, banner, and response probes.
    In production, uses actual socket connections + banner grabbing.
    """

    def fingerprint(self, ip: str, port: int, protocol: str = "tcp",
                    timeout: float = 3.0) -> Tuple[str, str, str]:
        """
        Returns (service_name, version, banner).
        """
        # Production: open socket, send probe, read response
        # Here we simulate with lookup + random versioning

        service_info = WELL_KNOWN_PORTS.get(port, ("unknown", "Unknown Service"))
        service_name = service_info[0]
        banner       = DEMO_BANNERS.get(port, "")
        version      = self._extract_version(banner, service_name)

        return service_name, version, banner

    def _extract_version(self, banner: str, service: str) -> str:
        """Parse version string from banner."""
        if not banner:
            return ""
        # Simple patterns
        import re
        patterns = [
            r"(\d+\.\d+\.\d+\w*)",   # e.g. 2.3.4 or 8.9p1
            r"(\d+\.\d+\w*)",         # e.g. 1.18.0
        ]
        for pat in patterns:
            m = re.search(pat, banner)
            if m:
                return m.group(1)
        return ""

    # Production stub:
    def _banner_grab(self, ip: str, port: int, timeout: float) -> str:
        """
        STUB — production implementation:

          try:
              with socket.create_connection((ip, port), timeout=timeout) as s:
                  s.settimeout(timeout)
                  # Send HTTP request for web ports
                  if port in (80, 8080, 8443, 443):
                      s.send(b"HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n" % ip.encode())
                  banner = s.recv(1024).decode("utf-8", errors="ignore")
                  return banner.strip()
          except (socket.timeout, ConnectionRefusedError, OSError):
              return ""
        """
        return DEMO_BANNERS.get(port, "")


# ─────────────────────────────────────────────
#  OS DETECTOR
# ─────────────────────────────────────────────

class OSDetector:
    """
    Passive OS detection based on TTL values and TCP window sizes.
    In production, use nmap OS detection (-O flag).
    """

    # TTL-based OS fingerprinting
    TTL_OS_MAP = [
        (60,  "Linux (kernel 2.4+)"),
        (64,  "Linux / macOS / FreeBSD"),
        (128, "Windows (Vista+)"),
        (255, "Cisco IOS / Solaris"),
    ]

    def detect(self, ttl: int, window_size: int) -> str:
        """Guess OS from TTL and TCP window size."""
        for threshold, os_name in self.TTL_OS_MAP:
            if ttl <= threshold:
                return os_name
        return "Unknown OS"

    # Production stub:
    def nmap_detect(self, ip: str) -> str:
        """
        STUB — production:

          import nmap
          nm = nmap.PortScanner()
          nm.scan(ip, arguments="-O --osscan-limit")
          if ip in nm.all_hosts():
              osmatch = nm[ip].get("osmatch", [])
              if osmatch:
                  return osmatch[0]["name"]
          return "Unknown"
        """
        # Simulate TTL-based guess
        ttl = random.choice([64, 128, 255])
        return self.detect(ttl, 65535)


# ─────────────────────────────────────────────
#  AUTHORIZATION CHECKER
# ─────────────────────────────────────────────

class AuthorizationChecker:
    """
    Classifies port results against the authorization policy database.
    Returns a risk score (0–100) and authorization status.
    """

    UNAUTHORIZED_PORTS = {4444, 31337, 12345, 6666, 5554, 9999, 54321, 1234}
    HIGH_RISK_SERVICES  = {"telnet", "ftp", "rsh", "rlogin", "finger"}
    CRITICAL_CVE_PORTS  = {21: "CVE-2011-2523", 445: "CVE-2017-0144"}

    def classify(self, result: PortResult, policy_db: Optional[Dict] = None) -> dict:
        """
        Returns:
        {
          status:      "authorized" | "unauthorized" | "conditional" | "critical_risk"
          risk_score:  0-100
          risk_level:  "low" | "medium" | "high" | "critical"
          cve_refs:    []
          reason:      str
        }
        """
        port    = result.port
        service = result.service.lower()
        cve_refs = []
        status   = "authorized"
        risk     = 10

        # 1. Check against known malicious ports (immediate critical)
        if port in self.UNAUTHORIZED_PORTS:
            status = "unauthorized"
            risk   = 100
            return self._build(status, risk, cve_refs, f"Port {port} is a known malicious/backdoor port")

        # 2. Check CVE-linked ports
        if port in self.CRITICAL_CVE_PORTS:
            cve_refs.append(self.CRITICAL_CVE_PORTS[port])
            risk = max(risk, 85)
            status = "unauthorized"

        # 3. Insecure / legacy services
        if service in self.HIGH_RISK_SERVICES:
            risk = max(risk, 70)
            status = "conditional"

        # 4. Check against policy DB if provided
        if policy_db:
            matching = [p for p in policy_db.values() if p.port == port]
            if matching:
                pol    = matching[0]
                status = pol.status
                risk   = {"low": 15, "medium": 40, "high": 75, "critical": 95}.get(pol.risk_level, 40)

        # 5. Score based on version vulnerability (banner-based)
        if result.banner:
            banner_l = result.banner.lower()
            if any(v in banner_l for v in ["2.3.4", "2.2.", "5.0.", "1.0.", "beta"]):
                risk = max(risk, 60)

        return self._build(status, risk, cve_refs, "Policy-based classification")

    def _build(self, status, risk, cve_refs, reason) -> dict:
        level = (
            "critical" if risk >= 90 else
            "high"     if risk >= 70 else
            "medium"   if risk >= 40 else
            "low"
        )
        return {"status": status, "risk_score": risk, "risk_level": level,
                "cve_refs": cve_refs, "reason": reason}


# ─────────────────────────────────────────────
#  SCAN ENGINE
# ─────────────────────────────────────────────

class ScanEngine:
    """
    Core scanning orchestrator.
    Supports TCP SYN, UDP, XMAS, and comprehensive scans.

    In production:
      - Use python-nmap library for actual network scanning
      - Or subprocess nmap with JSON output (--oJ -)
    """

    def __init__(self, max_workers: int = 50, timeout: float = 2.0):
        self.max_workers  = max_workers
        self.timeout      = timeout
        self.fingerprinter = ServiceFingerprinter()
        self.os_detector   = OSDetector()
        self.auth_checker  = AuthorizationChecker()

    def scan(self, target: str, scan_type: str = "syn",
             port_range: str = "1-1024") -> ScanSummary:
        """
        Scan a target (IP or CIDR) for open ports.
        @param target:     IP address or CIDR (e.g. "192.168.1.0/24")
        @param scan_type:  "syn" | "udp" | "xmas" | "comprehensive"
        @param port_range: e.g. "1-65535" or "22,80,443"
        @returns ScanSummary
        """
        started = datetime.utcnow()
        ports   = self._parse_port_range(port_range)
        hosts   = self._expand_target(target)

        log.info("Starting %s scan: %d hosts × %d ports", scan_type, len(hosts), len(ports))

        all_results: List[PortResult] = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            futures = {
                pool.submit(self._scan_port, host, port, scan_type): (host, port)
                for host in hosts for port in ports
            }
            for future in as_completed(futures):
                result = future.result()
                if result:
                    all_results.append(result)

        finished = datetime.utcnow()
        return ScanSummary(
            target         = target,
            scan_type      = scan_type,
            hosts_up       = len(set(r.ip for r in all_results)),
            hosts_down     = len(hosts) - len(set(r.ip for r in all_results)),
            total_ports    = len(all_results),
            open_ports     = sum(1 for r in all_results if r.state == PortState.OPEN),
            closed_ports   = sum(1 for r in all_results if r.state == PortState.CLOSED),
            filtered_ports = sum(1 for r in all_results if r.state == PortState.FILTERED),
            duration_s     = (finished - started).total_seconds(),
            started_at     = started,
            finished_at    = finished,
            results        = all_results,
        )

    def _scan_port(self, ip: str, port: int, scan_type: str) -> Optional[PortResult]:
        """
        Probe a single port. Returns PortResult or None.
        In production, uses actual raw socket / nmap call.
        """
        # ── Production TCP connect probe stub ──────────────────────────
        # try:
        #     s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #     s.settimeout(self.timeout)
        #     result = s.connect_ex((ip, port))
        #     state  = PortState.OPEN if result == 0 else PortState.CLOSED
        #     s.close()
        # except OSError:
        #     state = PortState.FILTERED
        # ──────────────────────────────────────────────────────────────

        # DEMO: simulate realistic port distribution
        demo_open_ports = {22, 80, 443, 3306, 21, 4444, 53, 25, 31337, 12345, 8080, 5900}
        if port in demo_open_ports and random.random() > 0.3:
            state = PortState.OPEN
        elif random.random() > 0.95:
            state = PortState.FILTERED
        else:
            return None   # Skip closed ports for brevity

        service, version, banner = self.fingerprinter.fingerprint(ip, port)
        os_guess = self.os_detector.nmap_detect(ip) if port == 22 else ""

        return PortResult(
            ip=ip, port=port, protocol="tcp", state=state,
            service=service, version=version, banner=banner,
            os_guess=os_guess, rtt_ms=round(random.uniform(0.5, 15.0), 2),
        )

    # ── Port range parser ──────────────────────────────────────────────
    @staticmethod
    def _parse_port_range(port_range: str) -> List[int]:
        """Parse "22,80,443" or "1-1024" or "22,80,443-500"."""
        ports = set()
        for part in port_range.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-", 1)
                ports.update(range(int(start), int(end) + 1))
            else:
                ports.add(int(part))
        return sorted(ports)

    # ── CIDR expander ─────────────────────────────────────────────────
    @staticmethod
    def _expand_target(target: str) -> List[str]:
        """Expand CIDR to list of host IPs."""
        try:
            network = ipaddress.ip_network(target, strict=False)
            hosts   = [str(h) for h in network.hosts()]
            # For large subnets limit to first 254 in demo
            return hosts[:254] if len(hosts) > 254 else hosts
        except ValueError:
            return [target]  # Single IP


# ─────────────────────────────────────────────
#  SCAN SCHEDULER
# ─────────────────────────────────────────────

class ScanScheduler:
    """
    Manages scheduled and continuous scanning.
    In production, backed by Celery + Redis.

    Schedule types:
      - "continuous" : Scan every N minutes
      - "interval"   : Scan at fixed intervals (cron expression)
      - "on-demand"  : Manual trigger
    """

    def __init__(self, engine: ScanEngine):
        self.engine   = engine
        self._jobs: Dict[str, dict] = {}

    def add_job(self, job_id: str, target: str, scan_type: str,
                schedule: str = "interval:60", port_range: str = "1-1024") -> dict:
        """Register a scheduled scan job."""
        job = {
            "id":           job_id,
            "target":       target,
            "scan_type":    scan_type,
            "schedule":     schedule,
            "port_range":   port_range,
            "created_at":   datetime.utcnow().isoformat(),
            "last_run":     None,
            "run_count":    0,
            "status":       "scheduled",
        }
        self._jobs[job_id] = job
        log.info("Scan job scheduled: [%s] %s @ %s", job_id, target, schedule)
        return job

    def run_job(self, job_id: str) -> ScanSummary:
        """Execute a scheduled scan job immediately."""
        job = self._jobs.get(job_id)
        if not job:
            raise ValueError(f"Job {job_id} not found")

        job["status"]   = "running"
        job["last_run"] = datetime.utcnow().isoformat()

        summary = self.engine.scan(job["target"], job["scan_type"], job["port_range"])

        job["run_count"] += 1
        job["status"]    = "idle"
        return summary

    def list_jobs(self) -> List[dict]:
        return list(self._jobs.values())

    # In production, this would be driven by Celery beat:
    # @celery_app.task
    # def run_scheduled_scan(job_id):
    #     scheduler.run_job(job_id)


# ─────────────────────────────────────────────
#  DEMO USAGE
# ─────────────────────────────────────────────

"""
engine    = ScanEngine(max_workers=100, timeout=2.0)
scheduler = ScanScheduler(engine)

# On-demand scan
summary = engine.scan("192.168.1.0/24", scan_type="syn", port_range="22,80,443,3306,4444,21")
print(f"Scan complete: {summary.open_ports} open ports in {summary.duration_s:.1f}s")

for r in summary.results:
    auth = engine.auth_checker.classify(r)
    print(f"  {r.ip}:{r.port} {r.service} [{auth['status'].upper()}] risk={auth['risk_score']}")

# Scheduled continuous scan
scheduler.add_job("JOB-001", "10.0.0.0/8", "comprehensive", schedule="interval:3600")
"""