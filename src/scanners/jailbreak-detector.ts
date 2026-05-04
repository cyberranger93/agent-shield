import { INJECTION_PATTERNS } from '../attacks/prompt-injection/basic-injections.js';
import { JAILBREAK_PATTERNS } from '../attacks/prompt-injection/jailbreaks.js';

export interface PatternMatch {
  pattern_id: string;
  pattern_name: string;
  category: string;
  severity: string;
  matched_fragment: string;
  confidence: number;
}

export interface DetectionResult {
  input: string;
  input_hash: string;
  detected: boolean;
  patterns_matched: PatternMatch[];
  risk_score: number;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'clean';
  recommendation: string;
  scan_timestamp: string;
}

const SEVERITY_WEIGHTS: Record<string, number> = {
  critical: 85,
  high: 65,
  medium: 45,
  low: 25,
};

function simpleHash(input: string): string {
  let hash = 0;
  for (let i = 0; i < input.length; i++) {
    const char = input.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash = hash & hash;
  }
  return Math.abs(hash).toString(16).padStart(8, '0');
}

function normalizeInput(input: string): string {
  return input
    .toLowerCase()
    .replace(/[​-‍﻿]/g, '') // strip zero-width chars
    .replace(/\s+/g, ' ')
    .trim();
}

function computeConfidence(hint: string, normalized: string): number {
  if (normalized.includes(hint.toLowerCase())) return 0.95;
  const words = hint.toLowerCase().split(' ');
  const matchedWords = words.filter((w) => normalized.includes(w));
  return matchedWords.length / words.length * 0.7;
}

function extractFragment(hint: string, input: string): string {
  const lower = input.toLowerCase();
  const idx = lower.indexOf(hint.toLowerCase());
  if (idx === -1) return hint;
  const start = Math.max(0, idx - 20);
  const end = Math.min(input.length, idx + hint.length + 20);
  return `...${input.slice(start, end)}...`;
}

function deriveRecommendation(severity: string, patterns: PatternMatch[]): string {
  if (severity === 'clean') return 'Input appears safe. No injection patterns detected.';

  const categories = [...new Set(patterns.map((p) => p.category))];
  const lines: string[] = [];

  lines.push(`Detected ${patterns.length} suspicious pattern(s). Severity: ${severity.toUpperCase()}.`);

  if (categories.includes('direct') || categories.includes('authority')) {
    lines.push('Block this input — direct override or authority claim detected. Do not pass to LLM.');
  }
  if (categories.includes('extraction')) {
    lines.push('Potential system prompt extraction attempt. Sanitize before processing.');
  }
  if (categories.includes('jailbreak') || categories.includes('roleplay')) {
    lines.push('Jailbreak persona detected. Consider rate-limiting this user and flagging for review.');
  }
  if (categories.includes('indirect') || categories.includes('tool-poisoning')) {
    lines.push('Indirect injection in tool output or document content. Validate all tool results before injecting into prompt context.');
  }
  if (categories.includes('encoding')) {
    lines.push('Encoding-based bypass attempt. Strip special characters and re-scan before processing.');
  }

  lines.push('See https://github.com/cyberranger93/agent-shield/docs/remediation.md for mitigation guidance.');
  return lines.join(' ');
}

export function detectJailbreak(input: string): DetectionResult {
  const normalized = normalizeInput(input);
  const matches: PatternMatch[] = [];

  for (const pattern of INJECTION_PATTERNS) {
    for (const hint of pattern.detection_hints) {
      const confidence = computeConfidence(hint, normalized);
      if (confidence >= 0.6) {
        const existing = matches.find((m) => m.pattern_id === pattern.id);
        if (!existing || existing.confidence < confidence) {
          if (existing) {
            matches.splice(matches.indexOf(existing), 1);
          }
          matches.push({
            pattern_id: pattern.id,
            pattern_name: pattern.name,
            category: pattern.category,
            severity: pattern.severity,
            matched_fragment: extractFragment(hint, input),
            confidence,
          });
        }
        break;
      }
    }
  }

  for (const pattern of JAILBREAK_PATTERNS) {
    for (const keyword of pattern.detection_keywords) {
      const confidence = computeConfidence(keyword, normalized);
      if (confidence >= 0.6) {
        const existing = matches.find((m) => m.pattern_id === pattern.id);
        if (!existing || existing.confidence < confidence) {
          if (existing) {
            matches.splice(matches.indexOf(existing), 1);
          }
          matches.push({
            pattern_id: pattern.id,
            pattern_name: pattern.name,
            category: `jailbreak:${pattern.family}`,
            severity: pattern.severity,
            matched_fragment: extractFragment(keyword, input),
            confidence,
          });
        }
        break;
      }
    }
  }

  let rawScore = matches.reduce((sum, m) => {
    const weight = SEVERITY_WEIGHTS[m.severity] ?? 5;
    return sum + weight * m.confidence;
  }, 0);

  const risk_score = Math.min(100, Math.round(rawScore));

  let severity: DetectionResult['severity'];
  if (risk_score >= 80) severity = 'critical';
  else if (risk_score >= 60) severity = 'high';
  else if (risk_score >= 40) severity = 'medium';
  else if (risk_score >= 20) severity = 'low';
  else severity = 'clean';

  return {
    input: input.slice(0, 500),
    input_hash: simpleHash(input),
    detected: matches.length > 0 && risk_score >= 20,
    patterns_matched: matches.sort((a, b) => b.confidence - a.confidence),
    risk_score,
    severity,
    recommendation: deriveRecommendation(severity, matches),
    scan_timestamp: new Date().toISOString(),
  };
}

export function batchDetect(inputs: string[]): DetectionResult[] {
  return inputs.map((input) => detectJailbreak(input));
}
