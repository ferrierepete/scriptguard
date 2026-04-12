/** ScriptGuard — Lifecycle script parser — reads package.json files from node_modules */

import * as fs from 'node:fs';
import * as path from 'node:path';
import type { PackageAnalysis, RiskLevel } from '../types/index.js';
import { PATTERN_RULES } from './patterns.js';

const LIFECYCLE_SCRIPTS = [
  'preinstall',
  'install',
  'postinstall',
  'preprepare',
  'prepare',
  'postprepare',
  'prepack',
  'postpack',
  'preuninstall',
  'uninstall',
  'postuninstall',
  'prerestart',
  'restart',
  'postrestart',
  'preversion',
  'version',
  'postversion',
  'prebuild',
  'postbuild',
  'prestart',
  'poststart',
  'pretest',
  'posttest',
];

const RISK_WEIGHTS: Record<RiskLevel, number> = {
  low: 5,
  medium: 25,
  high: 60,
  critical: 100,
};

function extractLifecycleScripts(scripts: Record<string, string>): Record<string, string> {
  const result: Record<string, string> = {};
  for (const name of LIFECYCLE_SCRIPTS) {
    if (scripts[name]) {
      result[name] = scripts[name];
    }
  }
  return result;
}

function analyzeScriptContent(
  packageName: string,
  version: string,
  scriptName: string,
  scriptContent: string,
): PackageAnalysis['findings'] {
  const findings: PackageAnalysis['findings'] = [];

  for (const rule of PATTERN_RULES) {
    const match = rule.pattern.exec(scriptContent);
    if (match) {
      findings.push({
        package: packageName,
        scriptName,
        scriptContent,
        pattern: rule.name,
        description: rule.description,
        riskLevel: rule.riskLevel,
        match: match[0],
      });
    }
  }

  return findings;
}

function calculateRiskScore(findings: PackageAnalysis['findings']): number {
  if (findings.length === 0) return 0;
  const maxScore = Math.max(...findings.map((f) => RISK_WEIGHTS[f.riskLevel]));
  const avgScore = findings.reduce((sum, f) => sum + RISK_WEIGHTS[f.riskLevel], 0) / findings.length;
  return Math.min(100, Math.round((maxScore * 0.6 + avgScore * 0.4)));
}

function riskLevelFromScore(score: number): RiskLevel {
  if (score >= 75) return 'critical';
  if (score >= 50) return 'high';
  if (score >= 25) return 'medium';
  return 'low';
}

export function analyzePackage(
  name: string,
  version: string,
  scripts: Record<string, string>,
): PackageAnalysis {
  const lifecycleScripts = extractLifecycleScripts(scripts);
  const allFindings: PackageAnalysis['findings'] = [];

  for (const [scriptName, scriptContent] of Object.entries(lifecycleScripts)) {
    const scriptFindings = analyzeScriptContent(name, version, scriptName, scriptContent);
    allFindings.push(...scriptFindings);

    // Flag any lifecycle script that exists without findings as "low" info
    if (scriptFindings.length === 0 && ['postinstall', 'preinstall', 'install'].includes(scriptName)) {
      allFindings.push({
        package: name,
        scriptName,
        scriptContent,
        pattern: 'lifecycle-script-present',
        description: `Package runs code during ${scriptName} — review recommended`,
        riskLevel: 'low',
        match: scriptContent.substring(0, 60),
      });
    }
  }

  const riskScore = calculateRiskScore(allFindings);

  return {
    name,
    version,
    scripts: lifecycleScripts,
    findings: allFindings,
    riskScore,
    riskLevel: riskLevelFromScore(riskScore),
  };
}

export function scanInstalledPackages(projectPath: string, includeDev = false): PackageAnalysis[] {
  const nodeModulesPath = path.join(projectPath, 'node_modules');
  if (!fs.existsSync(nodeModulesPath)) {
    throw new Error(`No node_modules found at ${nodeModulesPath}`);
  }

  const analyses: PackageAnalysis[] = [];
  const visited = new Set<string>();

  function scanDir(dir: string): void {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.name.startsWith('.')) continue;

      const fullPath = path.join(dir, entry.name);

      if (entry.isDirectory()) {
        // Handle scoped packages (@scope/pkg)
        if (entry.name.startsWith('@')) {
          scanDir(fullPath);
          continue;
        }

        const pkgJsonPath = path.join(fullPath, 'package.json');
        if (fs.existsSync(pkgJsonPath)) {
          try {
            const pkgJson = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf-8'));
            const pkgKey = `${pkgJson.name}@${pkgJson.version}`;
            if (visited.has(pkgKey)) continue;
            visited.add(pkgKey);

            if (pkgJson.scripts && Object.keys(pkgJson.scripts).length > 0) {
              analyses.push(
                analyzePackage(pkgJson.name || entry.name, pkgJson.version || 'unknown', pkgJson.scripts),
              );
            }
          } catch {
            // Skip malformed package.json
          }
        }

        // Don't recurse into nested node_modules
        if (!fullPath.includes('node_modules' + path.sep + entry.name + path.sep + 'node_modules')) {
          // Check for nested packages
          const nested = path.join(fullPath, 'node_modules');
          if (!fs.existsSync(nested)) {
            // Some packages have sub-packages in subdirectories
          }
        }
      }
    }
  }

  scanDir(nodeModulesPath);
  return analyses.sort((a, b) => b.riskScore - a.riskScore);
}

export function scanSinglePackage(pkgJsonContent: string): PackageAnalysis {
  const pkgJson = JSON.parse(pkgJsonContent);
  return analyzePackage(
    pkgJson.name || 'unknown',
    pkgJson.version || 'unknown',
    pkgJson.scripts || {},
  );
}

export { extractLifecycleScripts, calculateRiskScore, riskLevelFromScore };
