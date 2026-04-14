/** ScriptGuard — Aggregate scanner */

import type { ScanResult, ScanOptions, RiskLevel, PackageAnalysis, AIOptions, AIBatchRequest } from '../types/index.js';
import { scanInstalledPackages, analyzePackage } from './lifecycle.js';
import { getGeminiClient } from '../ai/index.js';
import * as fs from 'node:fs';
import * as path from 'node:path';

const RISK_LEVEL_ORDER: Record<RiskLevel, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

function aggregateResults(
  analyses: PackageAnalysis[],
  startTime: number,
): ScanResult {
  const totalFindings = analyses.reduce((sum, a) => sum + a.findings.length, 0);
  const findingsByLevel: Record<RiskLevel, number> = { low: 0, medium: 0, high: 0, critical: 0 };

  for (const a of analyses) {
    for (const f of a.findings) {
      findingsByLevel[f.riskLevel]++;
    }
  }

  const packagesWithScripts = analyses.filter((a) => Object.keys(a.scripts).length > 0).length;

  let overallRiskScore = 0;
  if (analyses.length > 0) {
    const total = analyses.reduce((sum, a) => sum + a.riskScore, 0);
    overallRiskScore = Math.round(total / analyses.length);
    // Weight by max finding
    const maxScore = Math.max(...analyses.map((a) => a.riskScore));
    overallRiskScore = Math.min(100, Math.round(overallRiskScore * 0.3 + maxScore * 0.7));
  }

  let overallRiskLevel: RiskLevel = 'low';
  if (findingsByLevel.critical > 0) overallRiskLevel = 'critical';
  else if (findingsByLevel.high > 0) overallRiskLevel = 'high';
  else if (findingsByLevel.medium > 0) overallRiskLevel = 'medium';

  return {
    totalPackages: analyses.length,
    packagesWithScripts,
    analyses,
    totalFindings,
    findingsByLevel,
    overallRiskScore,
    overallRiskLevel,
    scanDurationMs: Date.now() - startTime,
  };
}

export async function scanProject(options: ScanOptions & { ai?: AIOptions }): Promise<ScanResult> {
  const startTime = Date.now();
  const analyses = scanInstalledPackages(
    options.path,
    options.includeDev,
    { ast: options.ast, deobfuscate: options.deobfuscate }
  );
  let result = aggregateResults(analyses, startTime);

  // Phase 2: AI analysis (opt-in)
  if (options.ai?.enabled) {
    try {
      result = await enrichWithAI(result, options.ai);
    } catch (error: any) {
      // Graceful degradation - return regex-only results on AI failure
      console.warn(`\n  ⚠️  AI analysis failed: ${error.message}`);
      console.warn('  Continuing with regex-based scanning only.\n');
    }
  }

  return result;
}

export function scanProjectSync(options: ScanOptions): ScanResult {
  const startTime = Date.now();
  const analyses = scanInstalledPackages(options.path, options.includeDev);
  return aggregateResults(analyses, startTime);
}

export function scanPackageJson(filePath: string): ScanResult {
  const startTime = Date.now();
  const content = fs.readFileSync(filePath, 'utf-8');
  const analysis = analyzePackage(
    JSON.parse(content).name || path.basename(path.dirname(filePath)),
    JSON.parse(content).version || 'unknown',
    JSON.parse(content).scripts || {},
  );
  return aggregateResults([analysis], startTime);
}

export function shouldFail(result: ScanResult, failLevel?: RiskLevel): boolean {
  if (!failLevel) return false;
  const threshold = RISK_LEVEL_ORDER[failLevel];
  return result.analyses.some((a) =>
    a.findings.some((f) => RISK_LEVEL_ORDER[f.riskLevel] >= threshold),
  );
}

export function filterByRiskLevel(analyses: PackageAnalysis[], minLevel: RiskLevel): PackageAnalysis[] {
  const threshold = RISK_LEVEL_ORDER[minLevel];
  return analyses
    .map((a) => ({
      ...a,
      findings: a.findings.filter((f) => RISK_LEVEL_ORDER[f.riskLevel] >= threshold),
    }))
    .filter((a) => a.findings.length > 0);
}

/**
 * Enrich scan results with AI analysis
 */
async function enrichWithAI(result: ScanResult, aiOptions: AIOptions): Promise<ScanResult> {
  const aiStartTime = Date.now();

  // Prepare batch request with packages that have findings or lifecycle scripts
  const packagesToAnalyze = result.analyses.filter(
    a => a.findings.length > 0 || Object.keys(a.scripts).length > 0
  );

  if (packagesToAnalyze.length === 0) {
    return result;
  }

  // Build batch request
  const batchRequest: AIBatchRequest = {
    packages: packagesToAnalyze.map(a => ({
      name: a.name,
      version: a.version,
      scripts: a.scripts,
      findings: a.findings,
    })),
    mode: aiOptions.mode || 'standard',
  };

  // Call Gemini API
  const client = getGeminiClient(aiOptions.apiKey);
  const aiResponse = await client.analyzeBatch(batchRequest);

  // Merge AI results back into analyses
  const aiAnalyses = new Map(
    aiResponse.analyses.map(a => [`${a.package}@${a.version}`, a])
  );

  let totalFalsePositivesFiltered = 0;
  let totalNewThreatsDetected = 0;

  for (const analysis of result.analyses) {
    const key = `${analysis.name}@${analysis.version}`;
    const aiAnalysis = aiAnalyses.get(key);

    if (aiAnalysis) {
      // Add AI analysis to findings
      for (const finding of analysis.findings) {
        finding.aiAnalysis = aiAnalysis;
      }

      totalFalsePositivesFiltered += aiAnalysis.falsePositivesFiltered;
      totalNewThreatsDetected += aiAnalysis.newThreatsDetected;

      // Update risk score based on AI insights
      if (aiAnalysis.insights.length > 0) {
        const maxInsightSeverity = aiAnalysis.insights.reduce((max, insight) => {
          const severityOrder = { low: 0, medium: 1, high: 2, critical: 3 };
          return Math.max(max, severityOrder[insight.severity]);
        }, 0);

        // Adjust risk score based on AI confidence
        if (maxInsightSeverity >= 3 && aiAnalysis.confidence > 0.7) {
          analysis.riskScore = Math.min(100, analysis.riskScore + 20);
        } else if (maxInsightSeverity === 0 && aiAnalysis.falsePositivesFiltered > 0) {
          // Lower risk if AI identified false positives
          analysis.riskScore = Math.max(0, analysis.riskScore - 30);
        }

        // Recalculate risk level
        if (analysis.riskScore >= 75) analysis.riskLevel = 'critical';
        else if (analysis.riskScore >= 50) analysis.riskLevel = 'high';
        else if (analysis.riskScore >= 25) analysis.riskLevel = 'medium';
        else analysis.riskLevel = 'low';
      }
    }
  }

  // Add AI summary to result
  result.aiAnalysis = {
    totalTokensUsed: aiResponse.totalTokensUsed,
    totalFalsePositivesFiltered,
    totalNewThreatsDetected,
    durationMs: Date.now() - aiStartTime,
  };

  return result;
}
