#!/usr/bin/env node
/** ScriptGuard — CLI entry point */

import { Command } from 'commander';
import * as fs from 'node:fs';
import * as path from 'node:path';
import type { ScanResult, RiskLevel, AIOptions } from './types/index.js';
import { scanProject, scanPackageJsonWithAI, shouldFail, filterByRiskLevel } from './scanners/index.js';

const RISK_ICONS: Record<RiskLevel, string> = {
  low: '⚪',
  medium: '🟡',
  high: '🟠',
  critical: '🔴',
};

const RISK_COLORS: Record<RiskLevel, string> = {
  low: '\x1b[37m',
  medium: '\x1b[33m',
  high: '\x1b[38;5;208m',
  critical: '\x1b[31m',
};

const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const GREEN = '\x1b[32m';

function bold(text: string): string {
  return `${BOLD}${text}${RESET}`;
}

function dim(text: string): string {
  return `${DIM}${text}${RESET}`;
}

function colorRisk(level: RiskLevel): string {
  return `${RISK_COLORS[level]}${level.toUpperCase()}${RESET}`;
}

function formatTable(result: ScanResult): string {
  const lines: string[] = [];

  lines.push('');
  lines.push(bold('  🔒 ScriptGuard — npm Lifecycle Script Security Scanner'));
  lines.push('');
  lines.push(`  Scanned ${bold(String(result.totalPackages))} packages (${result.packagesWithScripts} with lifecycle scripts) in ${result.scanDurationMs}ms`);
  lines.push('');

  if (result.totalFindings === 0) {
    lines.push(`  ${GREEN}✅ No suspicious lifecycle scripts detected${RESET}`);
    lines.push('');
    return lines.join('\n');
  }

  // Summary
  lines.push(bold('  Summary'));
  lines.push(`  Overall Risk: ${colorRisk(result.overallRiskLevel)} (${result.overallRiskScore}/100)`);
  lines.push(`  Findings: ${result.totalFindings} total — ${RISK_ICONS.critical} ${result.findingsByLevel.critical} critical | ${RISK_ICONS.high} ${result.findingsByLevel.high} high | ${RISK_ICONS.medium} ${result.findingsByLevel.medium} medium | ${RISK_ICONS.low} ${result.findingsByLevel.low} low`);

  // AI Analysis Summary
  if (result.aiAnalysis) {
    lines.push('');
    lines.push(bold('  AI Analysis'));
    lines.push(`  False positives filtered: ${GREEN}${result.aiAnalysis.totalFalsePositivesFiltered}${RESET}`);
    lines.push(`  New threats detected: ${RISK_ICONS.high} ${result.aiAnalysis.totalNewThreatsDetected}${RESET}`);
    lines.push(`  Tokens used: ${dim(String(result.aiAnalysis.totalTokensUsed))}`);
    lines.push(`  AI duration: ${dim(result.aiAnalysis.durationMs + 'ms')}`);
  }

  lines.push('');

  // Per-package findings
  lines.push(bold('  Findings'));
  lines.push('  ' + '─'.repeat(70));

  for (const analysis of result.analyses) {
    if (analysis.findings.length === 0) continue;

    lines.push('');
    lines.push(`  ${bold(analysis.name)}${dim('@' + analysis.version)} ${colorRisk(analysis.riskLevel)} [${analysis.riskScore}/100]`);

    for (const finding of analysis.findings) {
      lines.push(`    ${RISK_ICONS[finding.riskLevel]} ${colorRisk(finding.riskLevel)} ${finding.pattern}`);
      lines.push(`      ${dim(finding.description)}`);
      if (finding.match) {
        const truncated = finding.match.length > 60 ? finding.match.substring(0, 57) + '...' : finding.match;
        lines.push(`      ${dim('Match:')} ${truncated}`);
      }

      // Display AI insights if available
      if (finding.aiAnalysis && finding.aiAnalysis.insights.length > 0) {
        for (const insight of finding.aiAnalysis.insights) {
          const insightIcon = insight.type === 'false-positive' ? '✅' : '⚠️';
          lines.push(`      ${dim(insightIcon)} ${dim(insight.description)}`);
          if (insight.attackTechnique) {
            lines.push(`        ${dim('Technique:')} ${dim(insight.attackTechnique)}`);
          }
          if (insight.remediation) {
            lines.push(`        ${dim('Remediation:')} ${dim(insight.remediation.substring(0, 80) + (insight.remediation.length > 80 ? '...' : ''))}`);
          }
        }
      }
    }
  }

  lines.push('');
  lines.push('  ' + '─'.repeat(70));
  if (result.aiAnalysis) {
    lines.push(`  ${dim('Run with --format json for machine-readable output')}`);
    lines.push(`  ${dim('Run with --ai to enable AI analysis')}`);
  } else {
    lines.push(`  ${dim('Run with --format json for machine-readable output')}`);
    lines.push(`  ${dim('Run with --ai to enable AI analysis (requires GOOGLE_AI_API_KEY)')}`);
  }
  lines.push('');

  return lines.join('\n');
}

function formatJson(result: ScanResult): string {
  return JSON.stringify(result, null, 2);
}

function formatSarif(result: ScanResult): string {
  const sarif = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'ScriptGuard',
          version: '1.0.0',
          informationUri: 'https://github.com/ferrierepete/scriptguard',
          rules: result.analyses.flatMap((a) =>
            a.findings.map((f) => ({
              id: f.pattern,
              shortDescription: { text: f.description },
              defaultConfiguration: { level: sarifLevel(f.riskLevel) },
            }))
          ),
        },
      },
      results: result.analyses.flatMap((a) =>
        a.findings.map((f) => ({
          ruleId: f.pattern,
          level: sarifLevel(f.riskLevel),
          message: { text: `[${a.name}] ${f.scriptName}: ${f.description}` },
          locations: [{
            physicalLocation: {
              artifactLocation: { uri: `node_modules/${a.name}/package.json` },
            },
          }],
        }))
      ),
    }],
  };
  return JSON.stringify(sarif, null, 2);
}

function sarifLevel(level: RiskLevel): string {
  switch (level) {
    case 'critical':
    case 'high': return 'error';
    case 'medium': return 'warning';
    case 'low': return 'note';
  }
}

const program = new Command();

program
  .name('scriptguard')
  .description('Security scanner for npm package lifecycle scripts')
  .version('1.0.0');

program
  .command('scan')
  .description('Scan installed npm packages for malicious lifecycle scripts')
  .option('-p, --path <path>', 'Project path', process.cwd())
  .option('--include-dev', 'Include devDependencies', false)
  .option('--min-risk <level>', 'Minimum risk level to report (low/medium/high/critical)', 'low')
  .option('--fail-on <level>', 'Exit with code 1 if findings at or above this level', '')
  .option('-f, --format <format>', 'Output format (table/json/sarif)', 'table')
  .option('--ast', 'Enable AST-based pattern matching (default: enabled)', true)
  .option('--no-ast', 'Disable AST analysis for faster scanning')
  .option('--deobfuscate', 'Enable deobfuscation layer (default: enabled)', true)
  .option('--no-deobfuscate', 'Disable deobfuscation for faster scanning')
  .option('--ai', 'Enable AI analysis with Gemini API')
  .option('--ai-mode <mode>', 'AI analysis depth (basic/standard/thorough)', 'standard')
  .option('--ai-mitigation', 'Include remediation recommendations in AI output', true)
  .option('--ai-max-tokens <number>', 'Maximum tokens per AI request', '1000')
  .option('--ai-timeout <ms>', 'AI request timeout in milliseconds', '10000')
  .action(async (opts) => {
    const minRisk = (opts.minRisk || 'low') as RiskLevel;
    const format = opts.format || 'table';
    const failLevel = opts.failOn ? (opts.failOn as RiskLevel) : undefined;

    // Check for AI API key if AI is enabled
    if (opts.ai && !process.env.GOOGLE_AI_API_KEY) {
      console.error('\n  ❌ Error: GOOGLE_AI_API_KEY environment variable not set');
      console.error('  Get your key at: https://makersuite.google.com/app/apikey\n');
      console.error('  Then run: export GOOGLE_AI_API_KEY=your_key_here\n');
      process.exit(2);
    }

    try {
      // Build AI options if enabled
      const aiOptions: AIOptions | undefined = opts.ai ? {
        enabled: true,
        mode: opts.aiMode || 'standard',
        mitigation: opts.aiMitigation !== false,
        maxTokens: parseInt(opts.aiMaxTokens || '1000'),
        timeout: parseInt(opts.aiTimeout || '10000'),
      } : undefined;

      let result = await scanProject({
        path: opts.path || process.cwd(),
        includeDev: opts.includeDev || false,
        minRiskLevel: minRisk,
        format,
        failLevel,
        ast: opts.ast !== false,
        deobfuscate: opts.deobfuscate !== false,
        ai: aiOptions,
      });

      if (minRisk !== 'low') {
        result = {
          ...result,
          analyses: filterByRiskLevel(result.analyses, minRisk),
        };
      }

      const output = format === 'json' ? formatJson(result)
        : format === 'sarif' ? formatSarif(result)
        : formatTable(result);

      console.log(output);

      if (failLevel && shouldFail(result, failLevel)) {
        process.exit(1);
      }
    } catch (err: any) {
      console.error(`\n  ❌ Error: ${err.message}\n`);
      process.exit(2);
    }
  });

program
  .command('check')
  .description('Check a single package.json for risky lifecycle scripts')
  .argument('<path>', 'Path to package.json')
  .option('-f, --format <format>', 'Output format (table/json/sarif)', 'table')
  .option('--ai', 'Enable AI analysis with Gemini API')
  .option('--ai-mode <mode>', 'AI analysis depth (basic/standard/thorough)', 'standard')
  .option('--ai-mitigation', 'Include remediation recommendations in AI output', true)
  .option('--ai-max-tokens <number>', 'Maximum tokens per AI request', '1000')
  .option('--ai-timeout <ms>', 'AI request timeout in milliseconds', '10000')
  .option('--explain', 'AI explains each finding in plain English (auto-enables --ai)')
  .action(async (filePath, opts) => {
    const resolved = path.resolve(filePath);
    if (!fs.existsSync(resolved)) {
      console.error(`\n  ❌ File not found: ${resolved}\n`);
      process.exit(2);
    }

    // --explain auto-enables --ai with explain mode
    const aiEnabled = opts.ai || opts.explain;
    const explainMode = !!opts.explain;

    // Check for AI API key if AI is enabled
    if (aiEnabled && !process.env.GOOGLE_AI_API_KEY) {
      console.error('\n  ❌ Error: GOOGLE_AI_API_KEY environment variable not set');
      console.error('  Get your key at: https://makersuite.google.com/app/apikey\n');
      console.error('  Then run: export GOOGLE_AI_API_KEY=your_key_here\n');
      process.exit(2);
    }

    try {
      // Build AI options if enabled
      const aiOptions: AIOptions | undefined = aiEnabled ? {
        enabled: true,
        mode: explainMode ? 'explain' : (opts.aiMode || 'standard'),
        mitigation: opts.aiMitigation !== false,
        maxTokens: parseInt(opts.aiMaxTokens || '1000'),
        timeout: parseInt(opts.aiTimeout || '10000'),
      } : undefined;

      const result = await scanPackageJsonWithAI(resolved, aiOptions);
      const format = opts.format || 'table';

      const output = format === 'json' ? formatJson(result)
        : format === 'sarif' ? formatSarif(result)
        : formatTable(result);

      console.log(output);
    } catch (err: any) {
      console.error(`\n  ❌ Error: ${err.message}\n`);
      process.exit(2);
    }
  });

program
  .command('patterns')
  .description('List all detection patterns')
  .action(async () => {
    const { PATTERN_RULES } = await import('./scanners/patterns.js');
    console.log('\n  🔒 ScriptGuard Detection Patterns\n');
    const byCategory = new Map<string, typeof PATTERN_RULES>();
    for (const rule of PATTERN_RULES) {
      const list = byCategory.get(rule.category) || [];
      list.push(rule);
      byCategory.set(rule.category, list);
    }
    for (const [category, rules] of byCategory) {
      console.log(`  ${bold(category.toUpperCase())}`);
      for (const rule of rules) {
        console.log(`    ${RISK_ICONS[rule.riskLevel]} ${rule.name} ${dim('[' + rule.riskLevel + ']')}`);
        console.log(`      ${dim(rule.description)}`);
      }
      console.log('');
    }
  });

program.parse();
