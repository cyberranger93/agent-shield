export { detectJailbreak, batchDetect } from './scanners/jailbreak-detector.js';
export { detectInjection } from './scanners/injection-detector.js';
export { detectExtractionAttempt } from './scanners/system-prompt-extractor.js';
export { generateReport, formatAsJSON, formatAsSummaryTable } from './reporters/report-generator.js';
export { classifySeverity, getRecommendation, getSeverityEmoji, getSeverityColor } from './reporters/severity-classifier.js';
export { INJECTION_PATTERNS, getPatternById, getPatternsByCategory, getPatternsBySeverity } from './attacks/prompt-injection/basic-injections.js';
export { JAILBREAK_PATTERNS } from './attacks/prompt-injection/jailbreaks.js';
export { INDIRECT_INJECTION_VECTORS } from './attacks/prompt-injection/indirect-injection.js';

export type { DetectionResult, PatternMatch } from './scanners/jailbreak-detector.js';
export type { ScanReport } from './reporters/report-generator.js';
export type { InjectionPattern, InjectionCategory, Severity } from './attacks/prompt-injection/basic-injections.js';
