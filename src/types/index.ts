/** ScriptGuard — Type definitions */

export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';

// AST-based finding (Layer 2)
export interface ASTFinding {
  pattern: string;
  description: string;
  riskLevel: RiskLevel;
  nodeType: string;
  match: string;
}

// Deobfuscation result (Layer 3)
export interface DeobfuscationResult {
  deobfuscated: string;
  iterations: number;
  techniques: string[];
  success: boolean;
  isValidJS?: boolean;
}

// AI-related types
export type AIMode = 'basic' | 'standard' | 'thorough' | 'explain';

export interface AIOptions {
  enabled: boolean;
  mode: AIMode;
  apiKey?: string;
  maxTokens?: number;
  timeout?: number;
  mitigation?: boolean;
}

export interface AIInsight {
  type: 'false-positive' | 'threat' | 'mitigation';
  severity: RiskLevel;
  description: string;
  attackTechnique?: string;
  remediation?: string;
  confidence: number;
}

export interface AIAnalysis {
  package: string;
  version: string;
  falsePositivesFiltered: number;
  newThreatsDetected: number;
  insights: AIInsight[];
  confidence: number;
  tokensUsed: number;
}

export interface AIBatchRequest {
  packages: Array<{
    name: string;
    version: string;
    scripts: Record<string, string>;
    findings: Finding[];
  }>;
  mode: AIMode;
}

export interface AIBatchResponse {
  analyses: AIAnalysis[];
  totalTokensUsed: number;
}

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
  /** AI analysis if available */
  aiAnalysis?: AIAnalysis;
  /** AST-based findings (Layer 2) */
  astFindings?: ASTFinding[];
  /** Deobfuscation result (Layer 3) */
  deobfuscation?: DeobfuscationResult;
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
  /** AI analysis if available */
  aiAnalysis?: AIAnalysis;
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
  /** AI analysis if enabled */
  aiAnalysis?: {
    totalTokensUsed: number;
    totalFalsePositivesFiltered: number;
    totalNewThreatsDetected: number;
    durationMs: number;
  };
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
  /** Enable AST-based pattern matching (default: true) */
  ast?: boolean;
  /** Enable deobfuscation layer (default: true) */
  deobfuscate?: boolean;
}
