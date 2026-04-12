/** ScriptGuard — Type definitions */

export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';

export interface Finding {
  /** The package that triggered this finding */
  package: string;
  /** Which lifecycle script (e.g., "postinstall", "preinstall") */
  scriptName: string;
  /** The full script content */
  scriptContent: string;
  /** What was detected */
  pattern: string;
  /** Human-readable description of the risk */
  description: string;
  /** How severe */
  riskLevel: RiskLevel;
  /** Line/position where found (if applicable) */
  match: string;
}

export interface PackageAnalysis {
  /** Package name */
  name: string;
  /** Package version */
  version: string;
  /** All lifecycle scripts found */
  scripts: Record<string, string>;
  /** Findings for this package */
  findings: Finding[];
  /** Overall risk score 0-100 */
  riskScore: number;
  /** Overall risk level */
  riskLevel: RiskLevel;
}

export interface ScanResult {
  /** Total packages scanned */
  totalPackages: number;
  /** Packages with lifecycle scripts */
  packagesWithScripts: number;
  /** Individual package analyses */
  analyses: PackageAnalysis[];
  /** Total findings */
  totalFindings: number;
  /** Findings by risk level */
  findingsByLevel: Record<RiskLevel, number>;
  /** Overall risk score (average weighted) */
  overallRiskScore: number;
  /** Overall risk level */
  overallRiskLevel: RiskLevel;
  /** Duration of scan in ms */
  scanDurationMs: number;
}

export interface PatternRule {
  /** Unique name for this rule */
  name: string;
  /** Regex pattern to match */
  pattern: RegExp;
  /** Risk level if matched */
  riskLevel: RiskLevel;
  /** Human description */
  description: string;
  /** What this pattern indicates */
  category: 'network' | 'execution' | 'filesystem' | 'exfiltration' | 'obfuscation' | 'crypto';
}

export interface ScanOptions {
  /** Path to scan (defaults to cwd) */
  path: string;
  /** Include dev dependencies */
  includeDev: boolean;
  /** Minimum risk level to report */
  minRiskLevel: RiskLevel;
  /** Output format */
  format: 'table' | 'json' | 'sarif';
  /** Fail on findings at or above this level (for CI) */
  failLevel?: RiskLevel;
}
