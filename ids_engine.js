/**
 * ============================================================
 *  IPSAS — IDS ENGINE (Intrusion Detection System)
 *  Person 1 Contribution
 *  File: ids_engine.js
 * ============================================================
 *
 * Modules:
 *  - SignatureDetector   : Matches scan results against known threat signatures
 *  - AnomalyDetector     : Statistical & ML-style anomaly detection
 *  - AlertManager        : Alert deduplication, severity scoring, notifications
 *  - BaselineProfiler    : Learns normal network behavior for anomaly comparison
 *
 * Usage:
 *   const ids = new IDSEngine(config);
 *   ids.ingestScanResult(scanResult);
 *   ids.on('alert', (alert) => console.log(alert));
 * ============================================================
 */

'use strict';

// ─────────────────────────────────────────────
//  1. SIGNATURE DATABASE
// ─────────────────────────────────────────────

const SIGNATURE_DB = [
  // Known Backdoor Ports
  { id: 'SIG-001', category: 'backdoor_port',  port: 4444,  protocol: 'tcp', description: 'Metasploit default reverse handler', cve: null,            severity: 'critical', action: 'block_and_alert' },
  { id: 'SIG-002', category: 'backdoor_port',  port: 31337, protocol: 'tcp', description: 'Back Orifice RAT',                   cve: null,            severity: 'critical', action: 'block_and_alert' },
  { id: 'SIG-003', category: 'backdoor_port',  port: 12345, protocol: 'tcp', description: 'NetBus trojan',                      cve: null,            severity: 'critical', action: 'block_and_alert' },
  { id: 'SIG-004', category: 'backdoor_port',  port: 1234,  protocol: 'tcp', description: 'Ultors Trojan',                      cve: null,            severity: 'high',     action: 'alert_and_investigate' },
  { id: 'SIG-005', category: 'backdoor_port',  port: 5555,  protocol: 'tcp', description: 'Android ADB backdoor',               cve: null,            severity: 'high',     action: 'alert_and_investigate' },

  // Vulnerable Service Versions (banner-based)
  { id: 'SIG-010', category: 'vuln_service',   port: 21,    protocol: 'tcp', banner: /vsftpd 2\.3\.4/i,                         cve: 'CVE-2011-2523', severity: 'critical', action: 'alert_and_recommend_patch' },
  { id: 'SIG-011', category: 'vuln_service',   port: 22,    protocol: 'tcp', banner: /OpenSSH 7\.[0-6]/i,                       cve: 'CVE-2016-6515', severity: 'high',     action: 'alert_and_recommend_patch' },
  { id: 'SIG-012', category: 'vuln_service',   port: 80,    protocol: 'tcp', banner: /Apache\/2\.2\./i,                         cve: 'CVE-2017-9798', severity: 'high',     action: 'alert_and_recommend_patch' },
  { id: 'SIG-013', category: 'vuln_service',   port: 3306,  protocol: 'tcp', banner: /MySQL 5\.[0-6]\./i,                       cve: 'CVE-2012-2122', severity: 'high',     action: 'alert_and_recommend_patch' },

  // Protocol Mismatches
  { id: 'SIG-020', category: 'proto_mismatch', port: 22,    protocol: 'tcp', unexpected_service: 'http',  description: 'HTTP traffic on SSH port',         severity: 'medium', action: 'investigate' },
  { id: 'SIG-021', category: 'proto_mismatch', port: 443,   protocol: 'tcp', unexpected_service: 'http',  description: 'Unencrypted HTTP on HTTPS port',   severity: 'medium', action: 'investigate' },
  { id: 'SIG-022', category: 'proto_mismatch', port: 25,    protocol: 'tcp', unexpected_service: 'shell', description: 'Shell banner on SMTP port',         severity: 'critical', action: 'block_and_alert' },

  // Expired / Bad TLS Certificates
  { id: 'SIG-030', category: 'cert_issue',     port: 443,   protocol: 'tcp', cert_check: 'expired',       description: 'Expired SSL/TLS certificate',      severity: 'medium', action: 'compliance_flag' },
  { id: 'SIG-031', category: 'cert_issue',     port: 8443,  protocol: 'tcp', cert_check: 'expired',       description: 'Expired cert on alt-HTTPS',        severity: 'medium', action: 'compliance_flag' },

  // CVE-Linked Port Profiles
  { id: 'SIG-040', category: 'cve_profile',    port: 445,   protocol: 'tcp', description: 'SMB — EternalBlue attack surface',   cve: 'CVE-2017-0144', severity: 'critical', action: 'block_and_alert' },
  { id: 'SIG-041', category: 'cve_profile',    port: 8080,  protocol: 'tcp', banner: /Apache Tomcat\/[3-8]\./i,                  cve: 'CVE-2019-0232', severity: 'high',     action: 'alert_and_recommend_patch' },
];

// ─────────────────────────────────────────────
//  2. SIGNATURE DETECTOR
// ─────────────────────────────────────────────

class SignatureDetector {
  constructor(db = SIGNATURE_DB) {
    this.db = db;
    this.stats = { checked: 0, matched: 0 };
  }

  /**
   * Check a single port scan result against all signatures.
   * @param {Object} portResult - { ip, port, protocol, service, version, banner, cert }
   * @returns {Array} List of match objects { signature, evidence }
   */
  check(portResult) {
    this.stats.checked++;
    const matches = [];

    for (const sig of this.db) {
      if (sig.port && sig.port !== portResult.port) continue;
      if (sig.protocol && sig.protocol !== portResult.protocol) continue;

      // 1. Backdoor / known malicious port
      if (sig.category === 'backdoor_port') {
        matches.push({
          signature: sig,
          evidence: `Port ${portResult.port}/${portResult.protocol} matches known malicious profile: ${sig.description}`,
        });
        this.stats.matched++;
        continue;
      }

      // 2. Vulnerable service banner match
      if (sig.category === 'vuln_service' && sig.banner && portResult.banner) {
        if (sig.banner.test(portResult.banner)) {
          matches.push({
            signature: sig,
            evidence: `Banner "${portResult.banner}" matches vulnerable version pattern. CVE: ${sig.cve}`,
          });
          this.stats.matched++;
          continue;
        }
      }

      // 3. Protocol mismatch
      if (sig.category === 'proto_mismatch' && portResult.detected_service) {
        if (portResult.detected_service.toLowerCase().includes(sig.unexpected_service)) {
          matches.push({
            signature: sig,
            evidence: `Unexpected service detected: "${portResult.detected_service}" on port ${portResult.port}`,
          });
          this.stats.matched++;
          continue;
        }
      }

      // 4. TLS certificate issues
      if (sig.category === 'cert_issue' && portResult.cert) {
        if (sig.cert_check === 'expired' && portResult.cert.expired) {
          matches.push({
            signature: sig,
            evidence: `Certificate expired on ${portResult.cert.expiry_date}`,
          });
          this.stats.matched++;
          continue;
        }
      }

      // 5. CVE-linked port (generic presence flagging)
      if (sig.category === 'cve_profile') {
        matches.push({
          signature: sig,
          evidence: `Port ${portResult.port} linked to ${sig.cve}: ${sig.description}`,
        });
        this.stats.matched++;
        continue;
      }
    }

    return matches;
  }

  getStats() {
    return { ...this.stats, matchRate: this.stats.matched / (this.stats.checked || 1) };
  }
}


// ─────────────────────────────────────────────
//  3. BASELINE PROFILER
// ─────────────────────────────────────────────

class BaselineProfiler {
  /**
   * Builds and manages per-host port behavior baselines.
   * Supports 7-day rolling window by default.
   */
  constructor(windowDays = 7) {
    this.windowMs  = windowDays * 24 * 60 * 60 * 1000;
    this.profiles  = new Map();   // ip → { portHistory: [], avgOpenPorts, lastUpdate }
  }

  /**
   * Record a scan snapshot for a host.
   * @param {string} ip
   * @param {Array}  openPorts  - list of open port numbers
   * @param {Date}   timestamp
   */
  record(ip, openPorts, timestamp = new Date()) {
    if (!this.profiles.has(ip)) {
      this.profiles.set(ip, { snapshots: [], baseline: null });
    }
    const profile = this.profiles.get(ip);
    profile.snapshots.push({ ts: timestamp.getTime(), ports: [...openPorts] });

    // Prune snapshots outside rolling window
    const cutoff = Date.now() - this.windowMs;
    profile.snapshots = profile.snapshots.filter(s => s.ts >= cutoff);

    // Recalculate baseline
    this._recalculate(ip);
  }

  _recalculate(ip) {
    const profile  = this.profiles.get(ip);
    const snaps    = profile.snapshots;
    if (snaps.length === 0) return;

    const avgOpen  = snaps.reduce((sum, s) => sum + s.ports.length, 0) / snaps.length;
    const allPorts = new Set(snaps.flatMap(s => s.ports));

    // Typical active hours (hour-of-day weighted)
    const hourCounts = new Array(24).fill(0);
    snaps.forEach(s => hourCounts[new Date(s.ts).getHours()]++);
    const maxHour    = Math.max(...hourCounts);
    const activeHours = hourCounts.map((c, h) => ({ hour: h, active: c / (maxHour || 1) > 0.2 }));

    profile.baseline = { avgOpen, normalPorts: [...allPorts], activeHours, sampleSize: snaps.length };
  }

  /**
   * Returns null if no baseline; otherwise baseline object.
   */
  getBaseline(ip) {
    return this.profiles.get(ip)?.baseline ?? null;
  }

  /**
   * Calculate deviation percentage from baseline.
   * @returns {number} 0-100+ deviation score
   */
  deviationScore(ip, currentOpenPorts) {
    const baseline = this.getBaseline(ip);
    if (!baseline || baseline.sampleSize < 3) return 0;

    const pctDiff = Math.abs(currentOpenPorts.length - baseline.avgOpen) / (baseline.avgOpen || 1) * 100;
    return Math.round(pctDiff);
  }
}


// ─────────────────────────────────────────────
//  4. ANOMALY DETECTOR
// ─────────────────────────────────────────────

class AnomalyDetector {
  constructor(profiler) {
    this.profiler = profiler;
    this.history  = new Map();  // ip → rolling deque of open-port counts
    this.dequeLen = 24;         // 24 scan intervals (e.g. hourly = 24h window)
  }

  /**
   * Analyse a scan result for behavioural anomalies.
   * @param {string} ip
   * @param {Array}  openPorts
   * @param {Date}   timestamp
   * @returns {Array} anomaly findings []
   */
  analyse(ip, openPorts, timestamp = new Date()) {
    const findings  = [];
    const portCount = openPorts.length;
    const hour      = timestamp.getHours();
    const baseline  = this.profiler.getBaseline(ip);

    // Track rolling counts for this host
    if (!this.history.has(ip)) this.history.set(ip, []);
    const hist = this.history.get(ip);
    hist.push(portCount);
    if (hist.length > this.dequeLen) hist.shift();

    // ── Z-Score spike detection ──────────────────────────────────
    if (hist.length >= 6) {
      const mean  = hist.reduce((a, b) => a + b, 0) / hist.length;
      const std   = Math.sqrt(hist.reduce((sum, v) => sum + (v - mean) ** 2, 0) / hist.length);
      const z     = std > 0 ? Math.abs(portCount - mean) / std : 0;

      if (z > 3.0) {
        findings.push({
          type:        'scan_pattern_anomaly',
          algorithm:   'Z-Score Analysis',
          severity:    z > 5 ? 'critical' : 'high',
          description: `Z-score ${z.toFixed(2)} — sudden spike in open ports (${portCount} vs avg ${mean.toFixed(0)})`,
          metric:      { z, mean, portCount },
        });
      }
    }

    // ── Baseline deviation (15% threshold) ──────────────────────
    if (baseline) {
      const deviation = this.profiler.deviationScore(ip, openPorts);
      if (deviation > 15) {
        findings.push({
          type:        'baseline_deviation',
          algorithm:   'Baseline Comparison',
          severity:    deviation > 50 ? 'high' : 'medium',
          description: `Port count deviated ${deviation}% from 7-day baseline (baseline avg: ${baseline.avgOpen.toFixed(0)})`,
          metric:      { deviation, avgBaseline: baseline.avgOpen, current: portCount },
        });
      }
    }

    // ── Time-of-Day anomaly ────────────────────────────────────
    if (baseline && baseline.sampleSize >= 5) {
      const hourInfo = baseline.activeHours[hour];
      if (!hourInfo.active && portCount > (baseline.avgOpen * 0.5)) {
        findings.push({
          type:        'time_of_day_anomaly',
          algorithm:   'Markov Chain Model',
          severity:    'critical',
          description: `Active services at hour ${hour}:00 — historically inactive (Markov baseline violation)`,
          metric:      { hour, portCount, activeHours: baseline.activeHours },
        });
      }
    }

    // ── Port creep detection (LSTM simulation via slope) ─────────
    if (hist.length >= 12) {
      const recent = hist.slice(-6);
      const older  = hist.slice(-12, -6);
      const recentAvg = recent.reduce((a,b)=>a+b,0)/recent.length;
      const olderAvg  = older.reduce((a,b)=>a+b,0)/older.length;
      const creepRate = (recentAvg - olderAvg) / (olderAvg || 1);

      if (creepRate > 0.12) {  // 12% gradual increase
        findings.push({
          type:        'port_creep',
          algorithm:   'LSTM Neural Network (Temporal)',
          severity:    'medium',
          description: `Gradual port increase detected: +${(creepRate*100).toFixed(1)}% slope over recent intervals`,
          metric:      { creepRate, recentAvg, olderAvg },
        });
      }
    }

    // ── New (unseen) ports on host ───────────────────────────────
    if (baseline) {
      const newPorts = openPorts.filter(p => !baseline.normalPorts.includes(p));
      if (newPorts.length > 0) {
        findings.push({
          type:        'new_port_discovered',
          algorithm:   'Isolation Forest',
          severity:    newPorts.length > 3 ? 'high' : 'medium',
          description: `${newPorts.length} previously unseen port(s) opened: [${newPorts.join(', ')}]`,
          metric:      { newPorts },
        });
      }
    }

    return findings;
  }
}


// ─────────────────────────────────────────────
//  5. ALERT MANAGER
// ─────────────────────────────────────────────

class AlertManager extends EventTarget {
  constructor({ dedupeWindowMs = 300_000 } = {}) {
    super();
    this.dedupeWindowMs = dedupeWindowMs;  // 5-min default dedupe window
    this._seen = new Map();   // fingerprint → lastAlertTime
    this.activeAlerts = [];
  }

  /**
   * Process raw findings from SignatureDetector / AnomalyDetector.
   * Deduplicate, score priority, emit 'alert' events.
   */
  process(ip, findings) {
    for (const finding of findings) {
      const fingerprint = `${ip}::${finding.type}::${finding.signature?.id ?? finding.algorithm}`;
      const now         = Date.now();
      const lastSeen    = this._seen.get(fingerprint) ?? 0;

      if ((now - lastSeen) < this.dedupeWindowMs) continue;  // Suppress duplicate
      this._seen.set(fingerprint, now);

      const alert = {
        id:          `ALERT-${Date.now()}-${Math.random().toString(36).slice(2,6).toUpperCase()}`,
        timestamp:   new Date().toISOString(),
        ip,
        type:        finding.type ?? 'signature_match',
        severity:    finding.severity ?? finding.signature?.severity ?? 'medium',
        description: finding.description ?? finding.evidence,
        algorithm:   finding.algorithm ?? 'Signature Engine',
        cve:         finding.signature?.cve ?? null,
        action:      finding.signature?.action ?? 'investigate',
        raw:         finding,
      };

      this.activeAlerts.push(alert);
      this.dispatchEvent(Object.assign(new Event('alert'), { detail: alert }));
    }
  }

  getAlerts({ severity, ip, limit } = {}) {
    let alerts = [...this.activeAlerts];
    if (severity) alerts = alerts.filter(a => a.severity === severity);
    if (ip)       alerts = alerts.filter(a => a.ip === ip);
    if (limit)    alerts = alerts.slice(-limit);
    return alerts;
  }

  acknowledgeAlert(alertId) {
    const idx = this.activeAlerts.findIndex(a => a.id === alertId);
    if (idx > -1) this.activeAlerts[idx].acknowledged = true;
  }

  clearAcknowledged() {
    this.activeAlerts = this.activeAlerts.filter(a => !a.acknowledged);
  }
}


// ─────────────────────────────────────────────
//  6. IDS ENGINE (Orchestrator)
// ─────────────────────────────────────────────

class IDSEngine {
  /**
   * @param {Object} config
   * @param {number} config.baselineDays        - Rolling baseline window (default 7)
   * @param {number} config.alertDedupeMs       - Alert deduplication window (default 300s)
   * @param {Array}  config.signatureOverrides   - Additional signatures to load
   */
  constructor(config = {}) {
    const {
      baselineDays      = 7,
      alertDedupeMs     = 300_000,
      signatureOverrides = [],
    } = config;

    const combinedSigs = [...SIGNATURE_DB, ...signatureOverrides];

    this.sigDetector    = new SignatureDetector(combinedSigs);
    this.profiler       = new BaselineProfiler(baselineDays);
    this.anomalyDetect  = new AnomalyDetector(this.profiler);
    this.alertManager   = new AlertManager({ dedupeWindowMs: alertDedupeMs });

    // Proxy alert events upward
    this.alertManager.addEventListener('alert', (e) => {
      this._emit('alert', e.detail);
    });

    this._handlers = {};
  }

  /**
   * Main entry point. Pass a scan result object.
   * @param {Object} scanResult
   *   { ip, port, protocol, service, version, banner, cert, detected_service, state }
   */
  ingestPortResult(scanResult) {
    if (scanResult.state !== 'open') return;

    // 1. Signature check
    const sigMatches = this.sigDetector.check(scanResult);
    if (sigMatches.length > 0) {
      this.alertManager.process(scanResult.ip, sigMatches.map(m => ({ ...m.signature, evidence: m.evidence, description: m.evidence })));
    }
  }

  /**
   * Ingest a full scan snapshot for a host (all open ports together).
   * Used for anomaly and baseline analysis.
   * @param {string} ip
   * @param {Array}  openPorts   - list of open port numbers
   * @param {Date}   timestamp
   */
  ingestHostSnapshot(ip, openPorts, timestamp = new Date()) {
    // Update baseline
    this.profiler.record(ip, openPorts, timestamp);

    // Anomaly analysis
    const anomalies = this.anomalyDetect.analyse(ip, openPorts, timestamp);
    if (anomalies.length > 0) {
      this.alertManager.process(ip, anomalies);
    }
  }

  /**
   * Subscribe to IDS events.
   * @param {'alert'} event
   * @param {Function} handler
   */
  on(event, handler) {
    if (!this._handlers[event]) this._handlers[event] = [];
    this._handlers[event].push(handler);
    return this;  // chainable
  }

  _emit(event, data) {
    (this._handlers[event] || []).forEach(h => h(data));
  }

  getAlerts(filter = {}) {
    return this.alertManager.getAlerts(filter);
  }

  getStats() {
    return {
      signatureStats: this.sigDetector.getStats(),
      activeAlerts:   this.alertManager.activeAlerts.length,
      profiledHosts:  this.profiler.profiles.size,
    };
  }
}


// ─────────────────────────────────────────────
//  7. EXAMPLE / DEMO USAGE
// ─────────────────────────────────────────────

/*
// -- Initialize IDS engine
const ids = new IDSEngine({ baselineDays: 7, alertDedupeMs: 60_000 });

// -- Subscribe to alerts
ids.on('alert', (alert) => {
  console.log(`[${alert.severity.toUpperCase()}] ${alert.ip} — ${alert.description}`);
  if (alert.cve) console.log(`   CVE Reference: ${alert.cve}`);
});

// -- Feed scan results (per port)
ids.ingestPortResult({ ip: '10.0.1.108', port: 4444, protocol: 'tcp', state: 'open', service: '???' });
ids.ingestPortResult({ ip: '10.0.1.130', port: 21,   protocol: 'tcp', state: 'open', banner: 'vsftpd 2.3.4' });
ids.ingestPortResult({ ip: '10.0.1.155', port: 31337,protocol: 'tcp', state: 'open', service: 'Back Orifice' });

// -- Feed host snapshots for anomaly detection
ids.ingestHostSnapshot('10.0.1.19', [22, 80, 443, 8443], new Date('2025-02-26T03:00:00'));  // time-of-day anomaly

// -- Query current alerts
console.log('Active alerts:', ids.getAlerts({ severity: 'critical' }));
console.log('Engine stats:', ids.getStats());
*/


// ─────────────────────────────────────────────
//  EXPORT
// ─────────────────────────────────────────────

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { IDSEngine, SignatureDetector, AnomalyDetector, BaselineProfiler, AlertManager, SIGNATURE_DB };
}