"""
============================================================
 IPSAS — IPS ENGINE (Intrusion Prevention System)
 Person 2 Contribution
 File: ips_engine.py
============================================================

 Active defense component. When the IDS Engine raises an alert,
 the IPS Engine takes automated preventive action:

   BlockEngine      : Manages firewall-level IP/port blocks
   PacketInspector  : Deep-packet inspection for protocol anomalies
   QuarantineManager: VLAN isolation for rogue devices
   RemediationEngine: Auto-generates Jira/ServiceNow tickets & patches
   IPSOrchestrator  : Ties all components together with policy hooks

 How it works with IDS:
   IDS detects → IPS receives finding → IPS evaluates action policy
   → blocks / quarantines / patches based on severity

 In a real deployment:
   - BlockEngine calls iptables / nftables / cloud security-group API
   - QuarantineManager sends VLAN reassignment to managed switch API
   - RemediationEngine calls Jira REST API to open P1/P2 tickets

============================================================
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
log = logging.getLogger("ipsas.ips")


# ─────────────────────────────────────────────
#  ENUMS / CONSTANTS
# ─────────────────────────────────────────────

class IPSAction(str, Enum):
    ALLOW           = "allow"
    LOG_ONLY        = "log_only"
    BLOCK_IP        = "block_ip"
    BLOCK_PORT      = "block_port"
    QUARANTINE      = "quarantine"
    RATE_LIMIT      = "rate_limit"
    CHALLENGE       = "challenge"
    TERMINATE       = "terminate_session"


class BlockState(str, Enum):
    PENDING   = "pending"
    ACTIVE    = "active"
    EXPIRED   = "expired"
    REVOKED   = "revoked"


# Default auto-response policy per severity
DEFAULT_ACTION_POLICY: Dict[str, IPSAction] = {
    "critical": IPSAction.BLOCK_IP,
    "high":     IPSAction.BLOCK_PORT,
    "medium":   IPSAction.RATE_LIMIT,
    "low":      IPSAction.LOG_ONLY,
}

# Default block durations (seconds)
DEFAULT_BLOCK_DURATIONS: Dict[str, int] = {
    "critical": 86_400,   # 24 hours
    "high":      3_600,   # 1 hour
    "medium":      600,   # 10 minutes
    "low":           0,   # No block
}

# Known malicious port profiles (immediate block)
INSTANT_BLOCK_PORTS = {4444, 31337, 12345, 1234, 6666, 9999, 54321}


# ─────────────────────────────────────────────
#  BLOCK ENGINE
# ─────────────────────────────────────────────

class BlockEntry:
    __slots__ = ("id", "ip", "port", "reason", "action", "severity",
                 "state", "blocked_at", "expires_at", "rule_ref")

    def __init__(self, ip: str, port: Optional[int], reason: str,
                 action: IPSAction, severity: str, duration_s: int = 3600):
        self.id         = self._gen_id(ip, port)
        self.ip         = ip
        self.port       = port
        self.reason     = reason
        self.action     = action
        self.severity   = severity
        self.state      = BlockState.PENDING
        self.blocked_at = datetime.utcnow()
        self.expires_at = datetime.utcnow() + timedelta(seconds=duration_s)
        self.rule_ref   = None   # Stores iptables rule handle / cloud rule ID

    @staticmethod
    def _gen_id(ip, port):
        raw = f"{ip}:{port}:{time.time()}"
        return "BLK-" + hashlib.md5(raw.encode()).hexdigest()[:8].upper()

    def is_active(self) -> bool:
        return self.state == BlockState.ACTIVE and datetime.utcnow() < self.expires_at

    def to_dict(self) -> dict:
        return {
            "id":         self.id,
            "ip":         self.ip,
            "port":       self.port,
            "reason":     self.reason,
            "action":     self.action,
            "severity":   self.severity,
            "state":      self.state,
            "blocked_at": self.blocked_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
        }


class BlockEngine:
    """
    Manages IP/port blocking via firewall rules.
    In production, replace _apply_block / _remove_block with:
      - iptables: subprocess.run(["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"])
      - nftables: subprocess.run(["nft", "add", "rule", ...])
      - AWS SG: boto3.client("ec2").revoke_security_group_ingress(...)
      - GCP FW: google.cloud.compute.FirewallsClient().insert(...)
    """

    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self._blocks: Dict[str, BlockEntry] = {}

    def block(self, ip: str, port: Optional[int], reason: str,
              severity: str, duration_s: Optional[int] = None) -> BlockEntry:
        """
        Apply a block rule for the given IP (and optionally port).
        Returns the BlockEntry.
        """
        # Determine action type
        action = IPSAction.BLOCK_PORT if port else IPSAction.BLOCK_IP
        dur    = duration_s or DEFAULT_BLOCK_DURATIONS.get(severity, 3600)

        entry = BlockEntry(ip, port, reason, action, severity, dur)
        self._blocks[entry.id] = entry

        if not self.dry_run:
            rule_ref = self._apply_block(ip, port)
            entry.rule_ref = rule_ref

        entry.state = BlockState.ACTIVE
        log.warning("BLOCK APPLIED [%s] %s%s — %s (expires: %s)",
                    entry.id, ip, f":{port}" if port else "", reason,
                    entry.expires_at.strftime("%H:%M:%S"))
        return entry

    def unblock(self, block_id: str) -> bool:
        """Revoke a block by ID."""
        entry = self._blocks.get(block_id)
        if not entry:
            log.error("Block ID %s not found", block_id)
            return False

        if not self.dry_run and entry.rule_ref:
            self._remove_block(entry.ip, entry.port, entry.rule_ref)

        entry.state = BlockState.REVOKED
        log.info("BLOCK REVOKED [%s] %s", block_id, entry.ip)
        return True

    def sweep_expired(self):
        """Remove all expired block rules — call periodically."""
        now = datetime.utcnow()
        for entry in list(self._blocks.values()):
            if entry.state == BlockState.ACTIVE and entry.expires_at <= now:
                self.unblock(entry.id)
                entry.state = BlockState.EXPIRED

    def get_active_blocks(self) -> List[BlockEntry]:
        return [e for e in self._blocks.values() if e.is_active()]

    def is_blocked(self, ip: str, port: Optional[int] = None) -> bool:
        return any(
            e.ip == ip and (e.port is None or e.port == port) and e.is_active()
            for e in self._blocks.values()
        )

    # ── Firewall integration stubs ────────────────────────────────────
    def _apply_block(self, ip: str, port: Optional[int]) -> str:
        """
        Apply firewall rule. Returns rule reference/handle.
        STUB — replace with real implementation:

          import subprocess
          if port:
              cmd = f"iptables -I INPUT -s {ip} -p tcp --dport {port} -j DROP"
          else:
              cmd = f"iptables -I INPUT -s {ip} -j DROP"
          subprocess.run(cmd.split(), check=True)
        """
        rule_ref = f"iptables-rule-{ip.replace('.','_')}-{port or 'all'}"
        log.info("[STUB] iptables DROP applied: %s → port %s (ref: %s)", ip, port, rule_ref)
        return rule_ref

    def _remove_block(self, ip: str, port: Optional[int], rule_ref: str):
        """
        Remove firewall rule.
        STUB — replace with real implementation:

          subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        """
        log.info("[STUB] iptables rule removed: %s (ref: %s)", ip, rule_ref)


# ─────────────────────────────────────────────
#  PACKET INSPECTOR
# ─────────────────────────────────────────────

class PacketInspector:
    """
    Stateless deep-packet inspection rules.
    Receives a packet-like dict and returns inspection results.

    In production, integrate with:
      - Scapy: from scapy.all import sniff, IP, TCP
      - Suricata EVE JSON log stream
      - libpcap via python-libpcap
    """

    MALFORMED_THRESHOLD = 3   # Malformed packets before flagging

    def __init__(self):
        self._malformed_counts: Dict[str, int] = {}

    def inspect(self, packet: dict) -> dict:
        """
        Inspect a packet dict.
        Expected keys: src_ip, dst_ip, dst_port, protocol, flags, payload, length

        Returns: { passed, violations: [{ rule, description, severity }] }
        """
        violations = []
        src = packet.get("src_ip", "")

        # Rule 1: XMAS scan detection (FIN+URG+PSH all set)
        flags = packet.get("flags", "")
        if "FIN" in flags and "URG" in flags and "PSH" in flags:
            violations.append({
                "rule": "TCP-XMAS-SCAN",
                "description": f"XMAS scan detected from {src}",
                "severity": "high",
            })

        # Rule 2: NULL scan (no flags set)
        if flags == "" and packet.get("protocol") == "tcp":
            violations.append({
                "rule": "TCP-NULL-SCAN",
                "description": f"NULL scan (no TCP flags) from {src}",
                "severity": "high",
            })

        # Rule 3: Malformed packet (length inconsistency)
        length = packet.get("length", 0)
        payload_len = len(packet.get("payload", ""))
        if length > 0 and abs(length - payload_len) > length * 0.5:
            self._malformed_counts[src] = self._malformed_counts.get(src, 0) + 1
            if self._malformed_counts[src] >= self.MALFORMED_THRESHOLD:
                violations.append({
                    "rule": "MALFORMED-PACKET-FLOOD",
                    "description": f"{self._malformed_counts[src]} malformed packets from {src}",
                    "severity": "medium",
                })

        # Rule 4: Port scan detection (many distinct ports in one payload stream)
        dst_port = packet.get("dst_port", 0)
        if dst_port in INSTANT_BLOCK_PORTS:
            violations.append({
                "rule": "MALICIOUS-PORT-TRAFFIC",
                "description": f"Traffic to known malicious port {dst_port} from {src}",
                "severity": "critical",
            })

        # Rule 5: Suspicious banner in payload
        payload = packet.get("payload", "")
        if any(keyword in payload.lower() for keyword in ["meterpreter", "netbus", "back orifice", "metasploit"]):
            violations.append({
                "rule": "MALICIOUS-BANNER",
                "description": "Known malicious service banner detected in payload",
                "severity": "critical",
            })

        return {
            "passed":     len(violations) == 0,
            "violations": violations,
            "src_ip":     src,
        }


# ─────────────────────────────────────────────
#  QUARANTINE MANAGER
# ─────────────────────────────────────────────

class QuarantineManager:
    """
    Isolates compromised or rogue hosts by moving them to a quarantine VLAN.

    In production, integrate with:
      - Cisco DNA Center API: PUT /api/v1/network-device/...
      - Aruba Central API
      - Juniper Mist API
      - VMware NSX-T REST API
    """

    QUARANTINE_VLAN = 999   # Dedicated quarantine VLAN

    def __init__(self):
        self._quarantined: Dict[str, dict] = {}

    def quarantine(self, ip: str, mac: Optional[str], reason: str) -> dict:
        """Move host to quarantine VLAN and block all non-management traffic."""
        entry = {
            "ip":             ip,
            "mac":            mac,
            "reason":         reason,
            "quarantine_vlan": self.QUARANTINE_VLAN,
            "quarantined_at": datetime.utcnow().isoformat(),
            "state":          "active",
        }
        self._quarantined[ip] = entry
        self._apply_quarantine_vlan(ip, mac, self.QUARANTINE_VLAN)
        log.warning("QUARANTINE [%s] MAC:%s — %s → VLAN %d", ip, mac, reason, self.QUARANTINE_VLAN)
        return entry

    def release(self, ip: str, restore_vlan: int) -> bool:
        """Release host from quarantine."""
        if ip not in self._quarantined:
            return False
        self._quarantined[ip]["state"] = "released"
        self._restore_vlan(ip, restore_vlan)
        log.info("QUARANTINE RELEASED [%s] → VLAN %d", ip, restore_vlan)
        return True

    def is_quarantined(self, ip: str) -> bool:
        entry = self._quarantined.get(ip)
        return entry is not None and entry["state"] == "active"

    def get_quarantined(self) -> List[dict]:
        return [e for e in self._quarantined.values() if e["state"] == "active"]

    # ── Switch API stubs ────────────────────────────────────────────
    def _apply_quarantine_vlan(self, ip: str, mac: Optional[str], vlan: int):
        """
        STUB — replace with real switch API:

          # Cisco DNA Center example
          import requests
          headers = {"x-auth-token": TOKEN}
          requests.put(f"{DNAC_URL}/api/v1/network-device/{device_id}/vlan",
                       json={"vlanId": vlan, "mac": mac}, headers=headers)
        """
        log.info("[STUB] VLAN reassignment: %s → VLAN %d", ip, vlan)

    def _restore_vlan(self, ip: str, vlan: int):
        log.info("[STUB] VLAN restored: %s → VLAN %d", ip, vlan)


# ─────────────────────────────────────────────
#  REMEDIATION ENGINE
# ─────────────────────────────────────────────

class RemediationEngine:
    """
    Automated remediation workflows.
    - Creates Jira/ServiceNow incident tickets
    - Sends notifications (email, Slack, PagerDuty)
    - Issues patch recommendations
    """

    def __init__(self, jira_url: str = "", slack_webhook: str = ""):
        self.jira_url      = jira_url
        self.slack_webhook = slack_webhook
        self._tickets: List[dict] = []

    def create_ticket(self, alert: dict, priority: str = "P1") -> dict:
        """
        Create an incident ticket.
        In production, replace stub with:

          import requests
          resp = requests.post(f"{self.jira_url}/rest/api/2/issue", json={
              "fields": {
                  "project": {"key": "SEC"},
                  "summary": f"[IPSAS] {alert['type']} on {alert['ip']}",
                  "description": alert['description'],
                  "issuetype": {"name": "Bug"},
                  "priority": {"name": priority},
              }
          }, auth=("user", "token"))
        """
        ticket_id = f"SEC-{1000 + len(self._tickets) + 1}"
        ticket = {
            "id":          ticket_id,
            "priority":    priority,
            "summary":     f"[IPSAS] {alert.get('type', 'Security Alert')} on {alert.get('ip')}",
            "description": alert.get("description"),
            "ip":          alert.get("ip"),
            "created_at":  datetime.utcnow().isoformat(),
            "status":      "open",
        }
        self._tickets.append(ticket)
        log.info("TICKET CREATED [%s] %s — %s", ticket_id, priority, ticket["summary"])
        return ticket

    def patch_recommendation(self, ip: str, service: str, version: str, cve: Optional[str]) -> dict:
        """Generate a patch recommendation."""
        rec = {
            "ip":          ip,
            "service":     service,
            "version":     version,
            "cve":         cve,
            "recommendation": f"Upgrade {service} from {version} to latest stable version",
            "urgency":     "critical" if cve else "high",
            "generated_at": datetime.utcnow().isoformat(),
        }
        log.info("PATCH REC: %s on %s — %s", service, ip, cve or "no CVE")
        return rec

    def notify_slack(self, message: str, severity: str = "high"):
        """
        Send Slack notification.
        STUB — replace with:

          import requests
          color = {"critical":"#ff2d55","high":"#ff9500","medium":"#ffd60a","low":"#00ff88"}.get(severity,"#888")
          requests.post(self.slack_webhook, json={"attachments":[{"color":color,"text":message}]})
        """
        log.info("[STUB] Slack notification [%s]: %s", severity, message)

    def get_tickets(self) -> List[dict]:
        return self._tickets


# ─────────────────────────────────────────────
#  IPS ORCHESTRATOR
# ─────────────────────────────────────────────

class IPSOrchestrator:
    """
    Main IPS entry point.
    Receives IDS alerts and applies automated responses
    based on severity and configured policy.

    Usage:
        ips = IPSOrchestrator()
        ips.on_ids_alert(alert_dict)
    """

    def __init__(self, action_policy: Optional[Dict[str, IPSAction]] = None,
                 dry_run: bool = False):
        self.action_policy  = action_policy or DEFAULT_ACTION_POLICY
        self.blocker        = BlockEngine(dry_run=dry_run)
        self.quarantine_mgr = QuarantineManager()
        self.inspector      = PacketInspector()
        self.remediation    = RemediationEngine()
        self._response_log: List[dict] = []
        self._handlers: Dict[str, List[Callable]] = {}

    def on_ids_alert(self, alert: dict) -> dict:
        """
        Process an IDS alert and apply the appropriate IPS response.

        @param alert: {
            ip, port, severity, type, description, detection, cve
        }
        @returns: response summary dict
        """
        severity = alert.get("severity", "medium")
        ip       = alert.get("ip")
        port     = alert.get("port")
        action   = self.action_policy.get(severity, IPSAction.LOG_ONLY)

        log.info("IPS processing alert: %s %s %s → action: %s", severity.upper(), ip, alert.get("type"), action)

        response = {
            "alert_id":   alert.get("id"),
            "ip":         ip,
            "port":       port,
            "severity":   severity,
            "action":     action,
            "timestamp":  datetime.utcnow().isoformat(),
            "results":    [],
        }

        # ── BLOCK IP ──────────────────────────────────────────────────
        if action == IPSAction.BLOCK_IP:
            block = self.blocker.block(
                ip=ip, port=None,
                reason=alert.get("description", "IDS alert auto-block"),
                severity=severity,
            )
            response["results"].append({"action": "block_ip", "block_id": block.id, "expires": block.expires_at.isoformat()})

            # Create P1 ticket for critical
            if severity == "critical":
                ticket = self.remediation.create_ticket(alert, priority="P1")
                response["results"].append({"action": "ticket_created", "ticket_id": ticket["id"]})
                self.remediation.notify_slack(
                    f"🚨 CRITICAL: {alert.get('type')} on {ip} — auto-blocked. Ticket: {ticket['id']}",
                    severity="critical"
                )

        # ── BLOCK PORT ────────────────────────────────────────────────
        elif action == IPSAction.BLOCK_PORT and port:
            block = self.blocker.block(
                ip=ip, port=port,
                reason=alert.get("description"),
                severity=severity,
            )
            response["results"].append({"action": "block_port", "block_id": block.id})
            ticket = self.remediation.create_ticket(alert, priority="P2")
            response["results"].append({"action": "ticket_created", "ticket_id": ticket["id"]})

        # ── QUARANTINE ────────────────────────────────────────────────
        elif action == IPSAction.QUARANTINE:
            entry = self.quarantine_mgr.quarantine(ip, mac=None, reason=alert.get("description"))
            response["results"].append({"action": "quarantined", "vlan": entry["quarantine_vlan"]})

        # ── RATE LIMIT ────────────────────────────────────────────────
        elif action == IPSAction.RATE_LIMIT:
            log.info("[STUB] Rate limit applied: %s", ip)
            response["results"].append({"action": "rate_limited", "limit": "100pps"})

        # ── LOG ONLY ─────────────────────────────────────────────────
        elif action == IPSAction.LOG_ONLY:
            response["results"].append({"action": "logged"})

        # Patch recommendation if CVE linked
        if alert.get("cve"):
            rec = self.remediation.patch_recommendation(
                ip=ip, service=alert.get("type", "service"),
                version="unknown", cve=alert.get("cve")
            )
            response["results"].append({"action": "patch_recommended", "cve": rec["cve"], "urgency": rec["urgency"]})

        self._response_log.append(response)
        self._fire("response", response)
        return response

    def inspect_packet(self, packet: dict) -> dict:
        """Pass a packet through the DPI engine. Auto-blocks on violations."""
        result = self.inspector.inspect(packet)

        for violation in result["violations"]:
            sev = violation["severity"]
            if sev in ("critical", "high"):
                self.blocker.block(
                    ip=packet.get("src_ip", ""),
                    port=packet.get("dst_port"),
                    reason=violation["description"],
                    severity=sev,
                )

        return result

    def status(self) -> dict:
        return {
            "active_blocks":      len(self.blocker.get_active_blocks()),
            "quarantined_hosts":  len(self.quarantine_mgr.get_quarantined()),
            "open_tickets":       len([t for t in self.remediation.get_tickets() if t["status"] == "open"]),
            "total_responses":    len(self._response_log),
        }

    def on(self, event: str, handler: Callable):
        self._handlers.setdefault(event, []).append(handler)
        return self

    def _fire(self, event: str, data: Any):
        for handler in self._handlers.get(event, []):
            handler(data)


# ─────────────────────────────────────────────
#  DEMO USAGE
# ─────────────────────────────────────────────

"""
# Instantiate IPS (dry_run=True means no real firewall calls)
ips = IPSOrchestrator(dry_run=True)

# Listen for IPS responses
ips.on("response", lambda r: print(f"[IPS RESPONSE] {r['action']} → {r['ip']}"))

# Simulate IDS feeding an alert
ips.on_ids_alert({
    "id":          "ALERT-001",
    "ip":          "10.0.1.108",
    "port":        4444,
    "severity":    "critical",
    "type":        "Metasploit Backdoor",
    "description": "Port 4444 matches Metasploit reverse handler signature",
    "cve":         None,
})

ips.on_ids_alert({
    "id":          "ALERT-002",
    "ip":          "10.0.1.130",
    "port":        21,
    "severity":    "high",
    "type":        "CVE-2011-2523 vsftpd Exploit",
    "description": "vsftpd 2.3.4 banner matched — CVSS 10.0",
    "cve":         "CVE-2011-2523",
})

# Inspect a suspicious packet
ips.inspect_packet({
    "src_ip":   "10.0.3.99",
    "dst_ip":   "10.0.1.105",
    "dst_port": 4444,
    "protocol": "tcp",
    "flags":    "SYN",
    "payload":  "meterpreter session established",
    "length":   64,
})

print(ips.status())
"""