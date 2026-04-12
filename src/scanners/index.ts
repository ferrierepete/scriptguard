/** ScriptGuard — Aggregate scanner */

import type { ScanResult, ScanOptions, RiskLevel, PackageAnalysis } from '../types/index.js';
import { scanInstalledPackages, analyzePackage } from './lifecycle.js';
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

export function scanProject(options: ScanOptions): ScanResult {
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
