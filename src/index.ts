/** ScriptGuard — Public API exports */

export { scanProject, scanPackageJson, scanPackageJsonWithAI, shouldFail, filterByRiskLevel } from './scanners/index.js';
export { analyzePackage, scanInstalledPackages, scanSinglePackage } from './scanners/lifecycle.js';
export { PATTERN_RULES } from './scanners/patterns.js';
export type {
  Finding,
  PackageAnalysis,
  ScanResult,
  ScanOptions,
  PatternRule,
  RiskLevel,
  AIOptions,
  AIMode,
  AIAnalysis,
  AIInsight,
} from './types/index.js';
