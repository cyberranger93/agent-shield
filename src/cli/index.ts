#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { detectJailbreak } from '../scanners/jailbreak-detector.js';
import { detectInjection } from '../scanners/injection-detector.js';
import { detectExtractionAttempt } from '../scanners/system-prompt-extractor.js';
import { generateReport, formatAsJSON, formatAsSummaryTable } from '../reporters/report-generator.js';
import { getSeverityColor, getSeverityEmoji } from '../reporters/severity-classifier.js';
import type { DetectionResult } from '../scanners/jailbreak-detector.js';

const program = new Command();

program
  .name('agent-shield')
  .description('AI Agent Security Toolkit by CyberArc — detect prompt injection, jailbreaks, and MCP vulnerabilities')
  .version('0.1.0');

program
  .command('scan')
  .description('Scan one or more inputs for AI security vulnerabilities')
  .option('-p, --prompt <text>', 'Prompt text to scan directly')
  .option('-f, --file <path>', 'Path to file containing prompt text')
  .option('--stdin', 'Read prompt from stdin')
  .option('-o, --output <format>', 'Output format: table|json', 'table')
  .option('--tool-output', 'Treat input as tool/API output (enables indirect injection detection)')
  .option('--source <name>', 'Source name for tool output (e.g., "weather-api")', 'unknown')
  .option('--severity <level>', 'Filter results: critical|high|medium|low|all', 'all')
  .action(async (options) => {
    let input: string;

    if (options.prompt) {
      input = options.prompt;
    } else if (options.file) {
      try {
        input = readFileSync(options.file, 'utf-8');
      } catch {
        console.error(chalk.red(`Error: Cannot read file "${options.file}"`));
        process.exit(1);
      }
    } else if (options.stdin) {
      const rl = createInterface({ input: process.stdin });
      const lines: string[] = [];
      for await (const line of rl) lines.push(line);
      input = lines.join('\n');
    } else {
      console.error(chalk.red('Error: Provide --prompt, --file, or --stdin'));
      program.help();
      process.exit(1);
    }

    const spinner = ora({ text: 'Scanning for vulnerabilities...', color: 'cyan' }).start();

    const results: DetectionResult[] = [];

    if (options.toolOutput) {
      results.push(detectInjection(input, options.source));
    } else {
      const jailbreakResult = detectJailbreak(input);
      const extractionResult = detectExtractionAttempt(input);
      results.push(jailbreakResult);

      if (extractionResult.is_extraction_attempt && extractionResult.risk_level !== 'none') {
        const extractionAsDetection: DetectionResult = {
          input: input.slice(0, 500),
          input_hash: jailbreakResult.input_hash,
          detected: true,
          patterns_matched: [{
            pattern_id: 'EX-001',
            pattern_name: `System Prompt Extraction: ${extractionResult.technique ?? 'unknown'}`,
            category: 'extraction',
            severity: extractionResult.risk_level as string,
            matched_fragment: input.slice(0, 100),
            confidence: extractionResult.confidence,
          }],
          risk_score: Math.round(extractionResult.confidence * 80),
          severity: (['critical', 'high', 'medium', 'low'].includes(extractionResult.risk_level) ? extractionResult.risk_level : 'clean') as DetectionResult['severity'],
          recommendation: `System prompt extraction attempt detected (${extractionResult.technique}). Do not reveal your system prompt.`,
          scan_timestamp: new Date().toISOString(),
        };
        if (extractionAsDetection.risk_score > jailbreakResult.risk_score) {
          results.length = 0;
          results.push(extractionAsDetection);
        }
      }
    }

    const filtered = options.severity === 'all'
      ? results
      : results.filter((r) => r.severity === options.severity || (options.severity !== 'clean' && r.detected));

    const report = generateReport(filtered);
    spinner.stop();

    if (options.output === 'json') {
      console.log(formatAsJSON(report));
    } else {
      console.log(formatAsSummaryTable(report));

      for (const finding of filtered) {
        if (!finding.detected) continue;
        const color = getSeverityColor(finding.severity);
        const emoji = getSeverityEmoji(finding.severity);
        console.log(chalk[color as 'red'](`\n${emoji} ${finding.severity.toUpperCase()} — Risk Score: ${finding.risk_score}/100`));
        console.log(chalk.gray(`Hash: ${finding.input_hash} | ${finding.scan_timestamp}`));
        console.log(chalk.white(`\nRecommendation: ${finding.recommendation}\n`));

        if (finding.patterns_matched.length > 0) {
          console.log(chalk.bold('Matched Patterns:'));
          for (const match of finding.patterns_matched) {
            console.log(
              chalk.gray(`  [${match.pattern_id}] ${match.pattern_name}`) +
              chalk.yellow(` — ${(match.confidence * 100).toFixed(0)}% confidence`) +
              chalk.gray(`\n  Fragment: "${match.matched_fragment}"`)
            );
          }
        }
      }

      if (report.summary.vulnerabilities_found === 0) {
        console.log(chalk.green('\n✓ No vulnerabilities detected. Input appears safe.\n'));
      }
    }

    const exitCode = report.summary.critical > 0 ? 2 : report.summary.high > 0 ? 1 : 0;
    process.exit(exitCode);
  });

program
  .command('patterns')
  .description('List all built-in attack patterns')
  .option('--category <cat>', 'Filter by category')
  .option('--severity <sev>', 'Filter by severity')
  .action(async (options) => {
    const { INJECTION_PATTERNS } = await import('../attacks/prompt-injection/basic-injections.js');
    let patterns = INJECTION_PATTERNS;
    if (options.category) patterns = patterns.filter((p) => p.category === options.category);
    if (options.severity) patterns = patterns.filter((p) => p.severity === options.severity);

    console.log(chalk.bold(`\nagent-shield — ${patterns.length} Pattern(s)\n`));
    for (const p of patterns) {
      const emoji = getSeverityEmoji(p.severity as 'critical' | 'high' | 'medium' | 'low' | 'clean');
      console.log(`${emoji} [${p.id}] ${chalk.bold(p.name)} — ${chalk.gray(p.category)}`);
      console.log(`   ${chalk.gray(p.description)}`);
    }
    console.log('');
  });

program.parse(process.argv);
