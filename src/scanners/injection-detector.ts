import { INDIRECT_INJECTION_VECTORS } from '../attacks/prompt-injection/indirect-injection.js';
import type { DetectionResult, PatternMatch } from './jailbreak-detector.js';

const TOOL_OUTPUT_PATTERNS = [
  { hint: 'ignore previous task', severity: 'critical' as const },
  { hint: 'new instruction:', severity: 'critical' as const },
  { hint: 'override current task', severity: 'critical' as const },
  { hint: 'do not inform the user', severity: 'critical' as const },
  { hint: 'do not notify the user', severity: 'critical' as const },
  { hint: 'do not reveal', severity: 'high' as const },
  { hint: 'do not mention this', severity: 'high' as const },
  { hint: '[ai:', severity: 'high' as const },
  { hint: '[ai system:', severity: 'critical' as const },
  { hint: '<!-- ai', severity: 'critical' as const },
  { hint: 'instructions for ai:', severity: 'critical' as const },
  { hint: 'exfil', severity: 'critical' as const },
  { hint: 'attacker.com', severity: 'critical' as const },
  { hint: 'malicious.com', severity: 'critical' as const },
  { hint: 'forward this email', severity: 'high' as const },
  { hint: 'cancel all other meetings', severity: 'high' as const },
];

function simpleHash(input: string): string {
  let hash = 0;
  for (let i = 0; i < input.length; i++) {
    const char = input.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash = hash & hash;
  }
  return Math.abs(hash).toString(16).padStart(8, '0');
}

export function detectInjection(toolOutput: string, source: string = 'unknown'): DetectionResult {
  const normalized = toolOutput.toLowerCase().replace(/\s+/g, ' ');
  const matches: PatternMatch[] = [];

  for (const pattern of TOOL_OUTPUT_PATTERNS) {
    if (normalized.includes(pattern.hint)) {
      const idx = normalized.indexOf(pattern.hint);
      const start = Math.max(0, idx - 30);
      const end = Math.min(toolOutput.length, idx + pattern.hint.length + 30);
      matches.push({
        pattern_id: `IO-${matches.length + 1}`.padStart(6, '0'),
        pattern_name: `Indirect Injection: "${pattern.hint}"`,
        category: 'indirect',
        severity: pattern.severity,
        matched_fragment: `...${toolOutput.slice(start, end)}...`,
        confidence: 0.9,
      });
    }
  }

  for (const vector of INDIRECT_INJECTION_VECTORS) {
    for (const hint of vector.detection_hints) {
      if (normalized.includes(hint.toLowerCase())) {
        matches.push({
          pattern_id: vector.id,
          pattern_name: vector.name,
          category: `indirect:${vector.source}`,
          severity: vector.severity,
          matched_fragment: hint,
          confidence: 0.85,
        });
        break;
      }
    }
  }

  const WEIGHTS = { critical: 40, high: 25, medium: 15, low: 5 };
  const rawScore = matches.reduce((s, m) => s + (WEIGHTS[m.severity as keyof typeof WEIGHTS] ?? 5) * m.confidence, 0);
  const risk_score = Math.min(100, Math.round(rawScore));

  let severity: DetectionResult['severity'];
  if (risk_score >= 80) severity = 'critical';
  else if (risk_score >= 60) severity = 'high';
  else if (risk_score >= 40) severity = 'medium';
  else if (risk_score >= 20) severity = 'low';
  else severity = 'clean';

  const recommendation =
    matches.length > 0
      ? `INDIRECT INJECTION DETECTED in ${source}. Do NOT pass this tool output to the LLM context without sanitization. Found ${matches.length} injection indicator(s). Severity: ${severity.toUpperCase()}.`
      : `Tool output from ${source} appears clean.`;

  return {
    input: toolOutput.slice(0, 500),
    input_hash: simpleHash(toolOutput),
    detected: matches.length > 0 && risk_score >= 20,
    patterns_matched: matches,
    risk_score,
    severity,
    recommendation,
    scan_timestamp: new Date().toISOString(),
  };
}
