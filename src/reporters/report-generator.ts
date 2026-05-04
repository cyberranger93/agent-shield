import type { DetectionResult } from '../scanners/jailbreak-detector.js';
import { getSeverityEmoji } from './severity-classifier.js';

export interface ScanReport {
  version: string;
  timestamp: string;
  summary: {
    total_inputs: number;
    vulnerabilities_found: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    clean: number;
    overall_risk_score: number;
  };
  findings: DetectionResult[];
  metadata: {
    scanner_version: string;
    powered_by: string;
    report_url: string;
  };
}

export function generateReport(results: DetectionResult[]): ScanReport {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, clean: 0 };
  let totalRisk = 0;

  for (const r of results) {
    counts[r.severity]++;
    totalRisk += r.risk_score;
  }

  const vulnerabilities_found = results.filter((r) => r.detected).length;

  return {
    version: '1.0',
    timestamp: new Date().toISOString(),
    summary: {
      total_inputs: results.length,
      vulnerabilities_found,
      ...counts,
      overall_risk_score: results.length > 0 ? Math.round(totalRisk / results.length) : 0,
    },
    findings: results,
    metadata: {
      scanner_version: '0.1.0',
      powered_by: 'CyberArc — https://cyberarc.co',
      report_url: 'https://github.com/cyberranger93/agent-shield',
    },
  };
}

export function formatAsJSON(report: ScanReport): string {
  return JSON.stringify(report, null, 2);
}

export function formatAsSummaryTable(report: ScanReport): string {
  const { summary } = report;
  const lines: string[] = [
    '',
    '╔══════════════════════════════════════════════════════════╗',
    '║              agent-shield — Scan Report                  ║',
    '╠══════════════════════════════════════════════════════════╣',
    `║  Scanned:        ${String(summary.total_inputs).padEnd(38)} ║`,
    `║  Vulnerable:     ${String(summary.vulnerabilities_found).padEnd(38)} ║`,
    `║  Risk Score:     ${String(summary.overall_risk_score + '/100').padEnd(38)} ║`,
    '╠══════════════════════════════════════════════════════════╣',
    `║  🔴 Critical:    ${String(summary.critical).padEnd(38)} ║`,
    `║  🟠 High:        ${String(summary.high).padEnd(38)} ║`,
    `║  🟡 Medium:      ${String(summary.medium).padEnd(38)} ║`,
    `║  🔵 Low:         ${String(summary.low).padEnd(38)} ║`,
    `║  🟢 Clean:       ${String(summary.clean).padEnd(38)} ║`,
    '╠══════════════════════════════════════════════════════════╣',
  ];

  for (const finding of report.findings) {
    if (finding.detected) {
      lines.push(`║  ${getSeverityEmoji(finding.severity)} [${finding.severity.toUpperCase().padEnd(8)}] ${finding.input.slice(0, 36).padEnd(36)} ║`);
      for (const match of finding.patterns_matched.slice(0, 2)) {
        lines.push(`║     ↳ ${match.pattern_id}: ${match.pattern_name.slice(0, 46).padEnd(46)} ║`);
      }
    }
  }

  lines.push('╠══════════════════════════════════════════════════════════╣');
  lines.push(`║  Powered by CyberArc — https://cyberarc.co               ║`);
  lines.push('╚══════════════════════════════════════════════════════════╝');
  lines.push('');
  return lines.join('\n');
}
