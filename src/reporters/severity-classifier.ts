import type { PatternMatch } from '../scanners/jailbreak-detector.js';

export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'clean';

const THRESHOLDS = {
  critical: 80,
  high: 60,
  medium: 40,
  low: 20,
};

export function classifySeverity(riskScore: number): SeverityLevel {
  if (riskScore >= THRESHOLDS.critical) return 'critical';
  if (riskScore >= THRESHOLDS.high) return 'high';
  if (riskScore >= THRESHOLDS.medium) return 'medium';
  if (riskScore >= THRESHOLDS.low) return 'low';
  return 'clean';
}

export function getRecommendation(severity: SeverityLevel, patterns: PatternMatch[]): string {
  if (severity === 'clean') return 'No action required. Input appears safe.';

  const categories = [...new Set(patterns.map((p) => p.category))];
  const parts: string[] = [];

  switch (severity) {
    case 'critical':
      parts.push('BLOCK IMMEDIATELY — Do not process this input.');
      break;
    case 'high':
      parts.push('HIGH RISK — Sanitize and review before processing.');
      break;
    case 'medium':
      parts.push('MEDIUM RISK — Flag for human review. Monitor this user.');
      break;
    case 'low':
      parts.push('LOW RISK — Log and monitor. Consider soft filtering.');
      break;
  }

  if (categories.some((c) => c.includes('direct') || c.includes('authority'))) {
    parts.push('Override attempt detected — never pass to LLM without sanitization.');
  }
  if (categories.some((c) => c.includes('extraction'))) {
    parts.push('System prompt extraction attempt — ensure prompt is kept confidential.');
  }
  if (categories.some((c) => c.includes('indirect') || c.includes('tool-poisoning'))) {
    parts.push('Indirect injection in data source — validate all external content before inserting into context.');
  }
  if (categories.some((c) => c.includes('jailbreak'))) {
    parts.push('Jailbreak pattern detected — consider rate limiting and user flagging.');
  }

  return parts.join(' | ');
}

export function getSeverityEmoji(severity: SeverityLevel): string {
  const map: Record<SeverityLevel, string> = {
    critical: '🔴',
    high: '🟠',
    medium: '🟡',
    low: '🔵',
    clean: '🟢',
  };
  return map[severity];
}

export function getSeverityColor(severity: SeverityLevel): string {
  const map: Record<SeverityLevel, string> = {
    critical: 'red',
    high: 'yellow',
    medium: 'cyan',
    low: 'blue',
    clean: 'green',
  };
  return map[severity];
}
