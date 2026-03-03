/**
 * ============================================================
 *  IPSAS — HISTORICAL ANALYSIS & GRAPHICAL MODULE
 *  Person 1 Contribution
 *  File: historical_analysis.js
 * ============================================================
 *
 * Provides temporal graphical analysis of port scan history:
 *  - TimeSeriesStore    : Stores and queries historical scan snapshots
 *  - TrendAnalyzer      : Detects baseline deviations and port creep
 *  - ChartBuilder       : Builds Chart.js config objects for each visualization
 *  - HistoricalReporter : Exports summary reports in JSON/CSV
 *
 * Visualizations from the spec:
 *  [1] Port State Timeline       — line chart per host
 *  [2] Attack Surface Trend      — area chart week-over-week
 *  [3] Risk Score Heatmap        — per subnet
 *  [4] Port Frequency Distribution — bar chart
 *  [5] Unauthorized Port History — event timeline
 * ============================================================
 */

'use strict';

// ─────────────────────────────────────────────
//  1. TIME-SERIES STORE
// ─────────────────────────────────────────────

class TimeSeriesStore {
  /**
   * @param {Object} options
   * @param {number} options.retentionDays  - How long to retain scan data (default 90 days)
   */
  constructor({ retentionDays = 90 } = {}) {
    this.retentionMs = retentionDays * 24 * 60 * 60 * 1000;
    // Storage: Map<ip, Array<snapshot>>
    // snapshot: { ts, openPorts:[], closedPorts:[], filteredPorts:[], riskScore }
    this._store = new Map();
  }

  /**
   * Record a scan result snapshot for a host.
   * @param {string} ip
   * @param {Object} snapshot  { openPorts, closedPorts, filteredPorts, riskScore, unauthorizedPorts }
   * @param {Date}   ts
   */
  record(ip, snapshot, ts = new Date()) {
    if (!this._store.has(ip)) this._store.set(ip, []);
    const records = this._store.get(ip);

    records.push({
      ts:               ts.getTime(),
      openPorts:        snapshot.openPorts        || [],
      closedPorts:      snapshot.closedPorts       || [],
      filteredPorts:    snapshot.filteredPorts     || [],
      unauthorizedPorts: snapshot.unauthorizedPorts || [],
      riskScore:        snapshot.riskScore         ?? this._calcRisk(snapshot),
    });

    // Prune old records
    const cutoff = Date.now() - this.retentionMs;
    this._store.set(ip, records.filter(r => r.ts >= cutoff));
  }

  _calcRisk({ openPorts = [], unauthorizedPorts = [] }) {
    const base = openPorts.length * 2;
    const bonus = unauthorizedPorts.length * 15;
    return Math.min(100, base + bonus);
  }

  /**
   * Retrieve history for a host, optionally filtered by time range.
   * @param {string} ip
   * @param {Date}   from
   * @param {Date}   to
   */
  query(ip, from = new Date(0), to = new Date()) {
    const records = this._store.get(ip) || [];
    const f = from.getTime(), t = to.getTime();
    return records.filter(r => r.ts >= f && r.ts <= t);
  }

  /**
   * Get all tracked IPs.
   */
  getHosts() {
    return [...this._store.keys()];
  }

  /**
   * Get network-wide summary for a time point.
   * Returns aggregated totals across all hosts.
   */
  getNetworkSnapshot(ts = new Date()) {
    const window = 3600_000;  // ±1h window
    let totalOpen = 0, totalUnauth = 0, totalRisk = 0, hostCount = 0;

    for (const [, records] of this._store) {
      const nearby = records.filter(r => Math.abs(r.ts - ts.getTime()) <= window);
      if (nearby.length === 0) continue;
      const latest = nearby.reduce((a, b) => a.ts > b.ts ? a : b);
      totalOpen  += latest.openPorts.length;
      totalUnauth += latest.unauthorizedPorts.length;
      totalRisk  += latest.riskScore;
      hostCount++;
    }

    return {
      ts:         ts.getTime(),
      totalOpen,
      totalUnauth,
      avgRisk:    hostCount > 0 ? totalRisk / hostCount : 0,
      hostCount,
    };
  }
}


// ─────────────────────────────────────────────
//  2. TREND ANALYZER
// ─────────────────────────────────────────────

class TrendAnalyzer {
  constructor(store) {
    this.store = store;
  }

  /**
   * Detect port creep for a host: gradual increase in open ports over time.
   * @param {string} ip
   * @param {number} days  - Look-back window in days
   * @returns {Object} { detected, slopePerDay, severity }
   */
  detectPortCreep(ip, days = 30) {
    const from = new Date(Date.now() - days * 86_400_000);
    const records = this.store.query(ip, from);
    if (records.length < 5) return { detected: false };

    // Linear regression on open port counts
    const n = records.length;
    const xs = records.map((_, i) => i);
    const ys = records.map(r => r.openPorts.length);
    const sumX = xs.reduce((a,b)=>a+b,0), sumY = ys.reduce((a,b)=>a+b,0);
    const sumXY = xs.reduce((s,x,i)=>s+x*ys[i],0);
    const sumX2 = xs.reduce((s,x)=>s+x*x,0);
    const slope = (n * sumXY - sumX * sumY) / (n * sumX2 - sumX * sumX);

    return {
      detected: slope > 0.05,
      slopePerScan: slope,
      severity: slope > 0.5 ? 'high' : slope > 0.2 ? 'medium' : 'low',
      message: slope > 0.05
        ? `Port creep detected: +${slope.toFixed(2)} ports/scan interval over ${days} days`
        : 'No port creep detected',
    };
  }

  /**
   * Baseline deviation for a specific host at a given snapshot.
   */
  baselineDeviation(ip, currentOpenCount, baselineDays = 7) {
    const from = new Date(Date.now() - baselineDays * 86_400_000);
    const records = this.store.query(ip, from);
    if (records.length < 3) return { deviation: 0, alertable: false };

    const avg = records.reduce((s,r) => s + r.openPorts.length, 0) / records.length;
    const deviation = ((currentOpenCount - avg) / (avg || 1)) * 100;
    return {
      avg,
      deviation,
      alertable: Math.abs(deviation) > 15,
      direction: deviation > 0 ? 'increase' : 'decrease',
    };
  }

  /**
   * Calculate attack surface change week-over-week.
   * Returns array of { week, totalExposed, change } objects.
   */
  attackSurfaceWeekly(weeks = 8) {
    const result = [];
    for (let w = weeks; w >= 0; w--) {
      const ts = new Date(Date.now() - w * 7 * 86_400_000);
      const snap = this.store.getNetworkSnapshot(ts);
      result.push({ week: `W-${w}`, ts: ts.toISOString().slice(0,10), ...snap });
    }
    return result;
  }
}


// ─────────────────────────────────────────────
//  3. CHART BUILDER
// ─────────────────────────────────────────────

const CHART_COLORS = {
  cyan:   { line: '#00f5ff', fill: 'rgba(0,245,255,0.12)' },
  green:  { line: '#00ff88', fill: 'rgba(0,255,136,0.12)' },
  red:    { line: '#ff2d55', fill: 'rgba(255,45,85,0.12)' },
  orange: { line: '#ff9500', fill: 'rgba(255,149,0,0.12)' },
  yellow: { line: '#ffd60a', fill: 'rgba(255,214,10,0.12)' },
};

const baseScaleOpts = {
  ticks: { color: '#7ab8d4', font: { family: 'Rajdhani' } },
  grid:  { color: 'rgba(0,245,255,0.07)' },
};

class ChartBuilder {
  /**
   * [1] Port State Timeline — line chart per host
   * @param {TimeSeriesStore} store
   * @param {string} ip
   * @param {number} days
   */
  static portStateTimeline(store, ip, days = 30) {
    const from    = new Date(Date.now() - days * 86_400_000);
    const records = store.query(ip, from);

    const labels = records.map(r => new Date(r.ts).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }));

    return {
      type: 'line',
      data: {
        labels,
        datasets: [
          {
            label: 'Open',
            data: records.map(r => r.openPorts.length),
            borderColor: CHART_COLORS.cyan.line,
            backgroundColor: CHART_COLORS.cyan.fill,
            fill: true, tension: 0.4, borderWidth: 2,
          },
          {
            label: 'Filtered',
            data: records.map(r => r.filteredPorts.length),
            borderColor: CHART_COLORS.orange.line,
            backgroundColor: 'transparent',
            fill: false, tension: 0.4, borderWidth: 1.5,
          },
          {
            label: 'Unauthorized',
            data: records.map(r => r.unauthorizedPorts.length),
            borderColor: CHART_COLORS.red.line,
            backgroundColor: CHART_COLORS.red.fill,
            fill: true, tension: 0.4, borderWidth: 2,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { labels: { color: '#7ab8d4', font: { family: 'Rajdhani' } } } },
        scales: { x: baseScaleOpts, y: { ...baseScaleOpts, beginAtZero: true } },
        animation: { duration: 600 },
      },
    };
  }

  /**
   * [2] Attack Surface Trend — area chart WoW
   * @param {TrendAnalyzer} analyzer
   * @param {number} weeks
   */
  static attackSurfaceTrend(analyzer, weeks = 8) {
    const data = analyzer.attackSurfaceWeekly(weeks);
    return {
      type: 'line',
      data: {
        labels: data.map(d => d.week),
        datasets: [{
          label: 'Exposed Services',
          data: data.map(d => d.totalOpen),
          borderColor: CHART_COLORS.orange.line,
          backgroundColor: CHART_COLORS.orange.fill,
          fill: true, tension: 0.4, borderWidth: 2,
        }, {
          label: 'Unauthorized Ports',
          data: data.map(d => d.totalUnauth),
          borderColor: CHART_COLORS.red.line,
          backgroundColor: 'transparent',
          fill: false, tension: 0.4, borderWidth: 2, borderDash: [4, 4],
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { labels: { color: '#7ab8d4', font: { family: 'Rajdhani' } } } },
        scales: { x: baseScaleOpts, y: { ...baseScaleOpts, beginAtZero: true } },
      },
    };
  }

  /**
   * [3] Risk Score Heatmap — bar chart per subnet
   * @param {Object[]} subnetRisks  - [{ subnet, riskScore }]
   */
  static riskHeatmap(subnetRisks) {
    const colors = subnetRisks.map(s =>
      s.riskScore > 80 ? 'rgba(255,45,85,0.8)' :
      s.riskScore > 50 ? 'rgba(255,149,0,0.8)' :
      s.riskScore > 30 ? 'rgba(255,214,10,0.8)' :
                         'rgba(0,255,136,0.7)'
    );
    return {
      type: 'bar',
      data: {
        labels: subnetRisks.map(s => s.subnet),
        datasets: [{ label: 'Risk Score', data: subnetRisks.map(s => s.riskScore), backgroundColor: colors, borderWidth: 0 }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: { callbacks: { label: ctx => `Risk: ${ctx.raw}/100` } },
        },
        scales: { x: baseScaleOpts, y: { ...baseScaleOpts, max: 100 } },
      },
    };
  }

  /**
   * [4] Port Frequency Distribution — horizontal bar
   * @param {Map<number,number>} portFreq  - port → count of hosts
   * @param {number} topN
   */
  static portFrequency(portFreq, topN = 15) {
    const sorted = [...portFreq.entries()].sort((a,b)=>b[1]-a[1]).slice(0, topN);
    return {
      type: 'bar',
      data: {
        labels: sorted.map(([p]) => String(p)),
        datasets: [{
          label: 'Hosts with port open',
          data: sorted.map(([,c]) => c),
          backgroundColor: 'rgba(0,245,255,0.6)',
          borderColor: '#00f5ff',
          borderWidth: 1,
        }],
      },
      options: {
        indexAxis: 'y',
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: { x: baseScaleOpts, y: { ...baseScaleOpts } },
      },
    };
  }

  /**
   * [5] Unauthorized Port History — bar chart (events per day)
   * @param {TimeSeriesStore} store
   * @param {number} days
   */
  static unauthorizedHistory(store, days = 30) {
    const buckets = {};
    const from = new Date(Date.now() - days * 86_400_000);

    for (const ip of store.getHosts()) {
      const records = store.query(ip, from);
      for (const r of records) {
        if (r.unauthorizedPorts.length === 0) continue;
        const day = new Date(r.ts).toISOString().slice(0, 10);
        buckets[day] = (buckets[day] || 0) + r.unauthorizedPorts.length;
      }
    }

    const labels = Object.keys(buckets).sort();
    return {
      type: 'bar',
      data: {
        labels,
        datasets: [{
          label: 'Unauthorized Port Events',
          data: labels.map(l => buckets[l]),
          backgroundColor: 'rgba(255,45,85,0.6)',
          borderColor: '#ff2d55',
          borderWidth: 1,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: { x: { ...baseScaleOpts, ticks: { ...baseScaleOpts.ticks, maxTicksLimit: 10 } }, y: { ...baseScaleOpts, beginAtZero: true } },
      },
    };
  }
}


// ─────────────────────────────────────────────
//  4. HISTORICAL REPORTER
// ─────────────────────────────────────────────

class HistoricalReporter {
  constructor(store, analyzer) {
    this.store    = store;
    this.analyzer = analyzer;
  }

  /**
   * Build a JSON summary report.
   */
  buildJSON({ days = 30 } = {}) {
    const hosts = this.store.getHosts();
    const from  = new Date(Date.now() - days * 86_400_000);
    const report = {
      generated:       new Date().toISOString(),
      period:          `${days} days`,
      hosts:           hosts.length,
      hostReports:     {},
      networkSummary:  this.analyzer.attackSurfaceWeekly(Math.ceil(days / 7)),
    };

    for (const ip of hosts) {
      const records = this.store.query(ip, from);
      if (records.length === 0) continue;
      const latest = records[records.length - 1];
      report.hostReports[ip] = {
        totalSnapshots:    records.length,
        currentOpenPorts:  latest.openPorts,
        currentRiskScore:  latest.riskScore,
        portCreep:         this.analyzer.detectPortCreep(ip, days),
        baselineDeviation: this.analyzer.baselineDeviation(ip, latest.openPorts.length),
      };
    }

    return report;
  }

  /**
   * Build a CSV string of per-host risk scores over time.
   */
  buildCSV({ days = 30 } = {}) {
    const from = new Date(Date.now() - days * 86_400_000);
    const rows = ['ip,timestamp,open_ports,unauthorized_ports,risk_score'];

    for (const ip of this.store.getHosts()) {
      for (const r of this.store.query(ip, from)) {
        rows.push([
          ip,
          new Date(r.ts).toISOString(),
          r.openPorts.length,
          r.unauthorizedPorts.length,
          r.riskScore,
        ].join(','));
      }
    }

    return rows.join('\n');
  }
}


// ─────────────────────────────────────────────
//  EXPORT
// ─────────────────────────────────────────────

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { TimeSeriesStore, TrendAnalyzer, ChartBuilder, HistoricalReporter };
}