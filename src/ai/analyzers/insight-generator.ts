/** ScriptGuard — Insight generator for actionable security guidance */

import type { PackageAnalysis, Finding, AIInsight, RiskLevel } from '../../types/index.js';

/**
 * Generate actionable security insights for findings
 */
export function generateInsights(
  analysis: PackageAnalysis,
  includeMitigation: boolean = true
): AIInsight[] {
  const insights: AIInsight[] = [];

  // Group findings by severity
  const findingsBySeverity = groupBySeverity(analysis.findings);

  // Generate insights for each severity level
  for (const [severity, findings] of Object.entries(findingsBySeverity)) {
    if (findings.length === 0) continue;

    const severityInsights = generateInsightsForSeverity(
      findings,
      severity as RiskLevel,
      analysis,
      includeMitigation
    );

    insights.push(...severityInsights);
  }

  return insights;
}

/**
 * Generate insights for a specific severity level
 */
function generateInsightsForSeverity(
  findings: Finding[],
  severity: RiskLevel,
  analysis: PackageAnalysis,
  includeMitigation: boolean
): AIInsight[] {
  const insights: AIInsight[] = [];

  switch (severity) {
    case 'critical':
      insights.push(generateCriticalInsight(findings, analysis, includeMitigation));
      break;

    case 'high':
      insights.push(...generateHighInsights(findings, analysis, includeMitigation));
      break;

    case 'medium':
      insights.push(...generateMediumInsights(findings, analysis, includeMitigation));
      break;

    case 'low':
      insights.push(generateLowInsight(findings, analysis));
      break;
  }

  return insights;
}

/**
 * Generate insights for critical findings
 */
function generateCriticalInsight(
  findings: Finding[],
  analysis: PackageAnalysis,
  includeMitigation: boolean
): AIInsight {
  const threatTypes = findings.map(f => f.pattern);
  const uniqueThreats = [...new Set(threatTypes)];

  const descriptions: string[] = [];
  const techniques: string[] = [];

  for (const threat of uniqueThreats) {
    switch (threat) {
      case 'curl-pipe':
      case 'wget-pipe':
        descriptions.push('Remote code execution via download pipe');
        techniques.push('Remote payload execution');
        break;

      case 'ssh-access':
        descriptions.push('SSH private key access detected');
        techniques.push('Credential theft');
        break;

      case 'aws-creds':
        descriptions.push('AWS credentials being accessed');
        techniques.push('Cloud credential theft');
        break;

      case 'passwd-shadow':
        descriptions.push('System credential file access');
        techniques.push('Privilege escalation / credential harvesting');
        break;

      case 'keychain-access':
        descriptions.push('macOS Keychain access detected');
        techniques.push('Credential theft');
        break;

      case 'base64-exec':
        descriptions.push('Base64-encoded payload execution');
        techniques.push('Obfuscated code execution');
        break;

      case 'crypto-miner':
        descriptions.push('Cryptocurrency mining software detected');
        techniques.push('Resource hijacking');
        break;

      case 'reverse-shell':
        descriptions.push('Reverse shell backdoor detected');
        techniques.push('Remote access trojan (RAT)');
        break;

      default:
        descriptions.push(`Critical threat: ${threat}`);
        techniques.push('Unknown critical threat');
    }
  }

  return {
    type: 'threat',
    severity: 'critical',
    description: `Package ${analysis.name}@${analysis.version} contains ${findings.length} critical security issue${findings.length > 1 ? 's' : ''}: ${descriptions.join(', ')}. This package should NOT be installed.`,
    attackTechnique: techniques.join(', '),
    remediation: includeMitigation ? generateCriticalMitigation(findings, analysis) : undefined,
    confidence: 0.95,
  };
}

/**
 * Generate insights for high findings
 */
function generateHighInsights(
  findings: Finding[],
  analysis: PackageAnalysis,
  includeMitigation: boolean
): AIInsight[] {
  const insights: AIInsight[] = [];

  // Group by pattern to avoid duplicate insights
  const findingsByPattern = new Map<string, Finding[]>();
  for (const finding of findings) {
    const existing = findingsByPattern.get(finding.pattern) || [];
    existing.push(finding);
    findingsByPattern.set(finding.pattern, existing);
  }

  for (const [pattern, patternFindings] of findingsByPattern) {
    const insight = generateHighInsightForPattern(pattern, patternFindings, analysis, includeMitigation);
    insights.push(insight);
  }

  return insights;
}

function generateHighInsightForPattern(
  pattern: string,
  findings: Finding[],
  analysis: PackageAnalysis,
  includeMitigation: boolean
): AIInsight {
  const scriptsAffected = [...new Set(findings.map(f => f.scriptName))];

  switch (pattern) {
    case 'curl-silent':
    case 'curl-post':
      return {
        type: 'threat',
        severity: 'high',
        description: `Silent or outbound HTTP requests in ${scriptsAffected.join(', ')} scripts. This may indicate data exfiltration or command & control communication.`,
        attackTechnique: 'Data exfiltration / C2 communication',
        remediation: includeMitigation
          ? 'Review the destination URLs. If unknown, block network access for this package and consider removing it.'
          : undefined,
        confidence: 0.8,
      };

    case 'eval-usage':
      return {
        type: 'threat',
        severity: 'high',
        description: `Dynamic code execution (eval/Function) detected in ${scriptsAffected.join(', ')} scripts. This allows arbitrary code execution and is extremely dangerous.`,
        attackTechnique: 'Arbitrary code execution',
        remediation: includeMitigation
          ? 'Avoid this package. Dynamic code execution in lifecycle scripts is unacceptable for production dependencies.'
          : undefined,
        confidence: 0.9,
      };

    case 'shell-exec':
      return {
        type: 'threat',
        severity: 'high',
        description: `Direct shell execution detected in ${scriptsAffected.join(', ')} scripts. This can execute arbitrary system commands.`,
        attackTechnique: 'Arbitrary command execution',
        remediation: includeMitigation
          ? 'Review what commands are being executed. If unclear or suspicious, remove this package.'
          : undefined,
        confidence: 0.85,
      };

    case 'node-eval':
      return {
        type: 'threat',
        severity: 'high',
        description: `Node.js evaluating code from command line in ${scriptsAffected.join(', ')} scripts. This executes arbitrary JavaScript code.`,
        attackTechnique: 'Arbitrary code execution',
        remediation: includeMitigation
          ? 'Determine what code is being evaluated. If not absolutely necessary, remove this package.'
          : undefined,
        confidence: 0.85,
      };

    case 'env-file':
      return {
        type: 'threat',
        severity: 'high',
        description: `Reading .env files in ${scriptsAffected.join(', ')} scripts. May expose API keys, database credentials, or other secrets.`,
        attackTechnique: 'Secret exfiltration',
        remediation: includeMitigation
          ? 'Check if this package legitimately needs .env access. If not, remove it. Consider using environment variables directly instead.'
          : undefined,
        confidence: 0.75,
      };

    case 'env-exfil':
      return {
        type: 'threat',
        severity: 'high',
        description: `Accessing environment variables in ${scriptsAffected.join(', ')} scripts. Could exfiltrate sensitive data like API keys or tokens.`,
        attackTechnique: 'Credential theft',
        remediation: includeMitigation
          ? 'Review which environment variables are accessed. If suspicious, remove the package and rotate any exposed credentials.'
          : undefined,
        confidence: 0.7,
      };

    case 'clipboard-access':
      return {
        type: 'threat',
        severity: 'high',
        description: `Accessing system clipboard in ${scriptsAffected.join(', ')} scripts. Can steal sensitive data recently copied by the user.`,
        attackTechnique: 'Data theft',
        remediation: includeMitigation
          ? 'Avoid packages that access the clipboard. This is highly suspicious behavior for an npm package.'
          : undefined,
        confidence: 0.85,
      };

    case 'hex-encode':
      return {
        type: 'threat',
        severity: 'high',
        description: `Hex-encoded strings detected in ${scriptsAffected.join(', ')} scripts. This is likely obfuscation to hide malicious code.`,
        attackTechnique: 'Obfuscation',
        remediation: includeMitigation
          ? 'Decode the hex strings to reveal the actual code. If the purpose is unclear, treat this package as compromised.'
          : undefined,
        confidence: 0.8,
      };

    default:
      return {
        type: 'threat',
        severity: 'high',
        description: `High-risk pattern "${pattern}" detected in ${scriptsAffected.join(', ')} scripts.`,
        attackTechnique: 'Unknown high-severity threat',
        remediation: includeMitigation
          ? 'Review the script content manually. If the purpose is unclear, remove this package.'
          : undefined,
        confidence: 0.7,
      };
  }
}

/**
 * Generate insights for medium findings
 */
function generateMediumInsights(
  findings: Finding[],
  analysis: PackageAnalysis,
  includeMitigation: boolean
): AIInsight[] {
  const insights: AIInsight[] = [];

  // Group by pattern
  const findingsByPattern = new Map<string, Finding[]>();
  for (const finding of findings) {
    const existing = findingsByPattern.get(finding.pattern) || [];
    existing.push(finding);
    findingsByPattern.set(finding.pattern, existing);
  }

  for (const [pattern, patternFindings] of findingsByPattern) {
    const insight = generateMediumInsightForPattern(pattern, patternFindings, analysis, includeMitigation);
    insights.push(insight);
  }

  return insights;
}

function generateMediumInsightForPattern(
  pattern: string,
  findings: Finding[],
  analysis: PackageAnalysis,
  includeMitigation: boolean
): AIInsight {
  const scriptsAffected = [...new Set(findings.map(f => f.scriptName))];

  switch (pattern) {
    case 'http-request':
      return {
        type: 'threat',
        severity: 'medium',
        description: `Outbound HTTP requests in ${scriptsAffected.join(', ')} scripts. Verify destination URLs are legitimate.`,
        attackTechnique: 'Network activity',
        remediation: includeMitigation
          ? 'Check the destination URLs. If unknown or suspicious, remove the package.'
          : undefined,
        confidence: 0.6,
      };

    case 'dns-lookup':
      return {
        type: 'threat',
        severity: 'medium',
        description: `DNS lookups in ${scriptsAffected.join(', ')} scripts. May be used for DNS tunneling data exfiltration.`,
        attackTechnique: 'DNS tunneling',
        remediation: includeMitigation
          ? 'Verify why DNS lookups are needed. If unclear, review the package source code.'
          : undefined,
        confidence: 0.65,
      };

    case 'child-process':
      return {
        type: 'threat',
        severity: 'medium',
        description: `Spawning child processes in ${scriptsAffected.join(', ')} scripts. This is common for build tools but can execute arbitrary commands.`,
        attackTechnique: 'Command execution',
        remediation: includeMitigation
          ? 'If this is a build tool package, it may be legitimate. Otherwise, review what commands are executed.'
          : undefined,
        confidence: 0.5,
      };

    case 'require-resolve':
      return {
        type: 'threat',
        severity: 'medium',
        description: `Dynamic require() calls in ${scriptsAffected.join(', ')} scripts. This can load arbitrary code at runtime.`,
        attackTechnique: 'Dynamic code loading',
        remediation: includeMitigation
          ? 'Determine what modules are being loaded dynamically. If unclear, treat as suspicious.'
          : undefined,
        confidence: 0.6,
      };

    case 'tmp-write':
      return {
        type: 'threat',
        severity: 'medium',
        description: `Writing to temp directory in ${scriptsAffected.join(', ')} scripts. May be used for staging malicious files.`,
        attackTechnique: 'File system activity',
        remediation: includeMitigation
          ? 'Check what files are being written and why. If unclear, review the package source.'
          : undefined,
        confidence: 0.5,
      };

    case 'chmod-exec':
      return {
        type: 'threat',
        severity: 'medium',
        description: `Making files executable in ${scriptsAffected.join(', ')} scripts. Verify what files are affected.`,
        attackTechnique: 'Permission modification',
        remediation: includeMitigation
          ? 'Review what files are being made executable. If not necessary for the package, this is suspicious.'
          : undefined,
        confidence: 0.55,
      };

    case 'unicode-escape':
      return {
        type: 'threat',
        severity: 'medium',
        description: `Unicode-escaped strings in ${scriptsAffected.join(', ')} scripts. May be obfuscating malicious code.`,
        attackTechnique: 'Obfuscation',
        remediation: includeMitigation
          ? 'Unescape the strings to check what they contain. If suspicious, remove the package.'
          : undefined,
        confidence: 0.6,
      };

    default:
      return {
        type: 'threat',
        severity: 'medium',
        description: `Medium-risk pattern "${pattern}" detected in ${scriptsAffected.join(', ')} scripts.`,
        attackTechnique: 'Unknown medium-severity threat',
        remediation: includeMitigation
          ? 'Review the script content to understand if this is legitimate for the package functionality.'
          : undefined,
        confidence: 0.5,
      };
  }
}

/**
 * Generate insights for low findings
 */
function generateLowInsight(
  findings: Finding[],
  analysis: PackageAnalysis
): AIInsight {
  const scriptsAffected = [...new Set(findings.map(f => f.scriptName))];

  return {
    type: 'threat',
    severity: 'low',
    description: `Package ${analysis.name}@${analysis.version} has ${findings.length} low-risk finding${findings.length > 1 ? 's' : ''} in ${scriptsAffected.join(', ')} scripts. These are often lifecycle scripts with no detected malicious patterns - review as needed.`,
    confidence: 0.4,
  };
}

/**
 * Generate mitigation guidance for critical findings
 */
function generateCriticalMitigation(findings: Finding[], analysis: PackageAnalysis): string {
  const steps: string[] = [];

  steps.push('IMMEDIATE ACTIONS:');
  steps.push(`1. Uninstall this package: npm uninstall ${analysis.name}`);
  steps.push('2. Review all packages installed around the same time');
  steps.push('3. Check for unauthorized access or data exfiltration');
  steps.push('4. Scan your system for compromise');
  steps.push('5. Rotate any credentials that may have been exposed');

  steps.push('\nINVESTIGATION:');
  steps.push('- Check package installation date and source');
  steps.push('- Review the full script content in node_modules');
  steps.push('- Check network logs for suspicious connections');
  steps.push('- Audit system logs for unusual activity');

  steps.push('\nPREVENTION:');
  steps.push('- Always audit packages before installation');
  steps.push('- Use `npm audit` and `scriptguard scan` regularly');
  steps.push('- Pin dependency versions to prevent surprise updates');
  steps.push('- Consider using a private npm registry');
  steps.push('- Enable 2FA on your npm account');

  return steps.join('\n');
}

/**
 * Group findings by severity
 */
function groupBySeverity(findings: Finding[]): Record<RiskLevel, Finding[]> {
  const grouped: Record<RiskLevel, Finding[]> = {
    low: [],
    medium: [],
    high: [],
    critical: [],
  };

  for (const finding of findings) {
    grouped[finding.riskLevel].push(finding);
  }

  return grouped;
}
