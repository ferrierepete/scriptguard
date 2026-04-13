/** ScriptGuard — Advanced threat detector analyzer */

import type { PackageAnalysis, AIInsight } from '../../types/index.js';

/**
 * Detect advanced threats that may have been missed by regex patterns
 */
export function detectAdvancedThreats(
  analysis: PackageAnalysis,
  aiInsights: AIInsight[]
): AIInsight[] {
  const threats: AIInsight[] = [];

  // Add AI-identified threats
  for (const insight of aiInsights) {
    if (insight.type === 'threat') {
      threats.push(insight);
    }
  }

  // Run additional detection heuristics
  const obfuscationThreats = detectObfuscation(analysis);
  threats.push(...obfuscationThreats);

  const correlationThreats = detectMultiStageAttacks(analysis);
  threats.push(...correlationThreats);

  const novelThreats = detectNovelPatterns(analysis);
  threats.push(...novelThreats);

  return threats;
}

/**
 * Detect obfuscation techniques
 */
function detectObfuscation(analysis: PackageAnalysis): AIInsight[] {
  const threats: AIInsight[] = [];
  const { scripts, name } = analysis;

  for (const [scriptName, content] of Object.entries(scripts)) {
    // Check for various obfuscation techniques

    // 1. Excessive encoding (base64, hex, unicode)
    const encodingCount = [
      (content.match(/\\x[0-9a-fA-F]{2}/g) || []).length,
      (content.match(/\\u[0-9a-fA-F]{4}/g) || []).length,
      (content.match(/atob\s*\(/g) || []).length,
      (content.match(/btoa\s*\(/g) || []).length,
      (content.match(/Buffer\.from\s*\(/g) || []).length,
      (content.match(/toString\s*\(\s*['"](base64|hex|binary)['"]\s*\)/g) || []).length,
    ].reduce((sum, count) => sum + count, 0);

    if (encodingCount > 3) {
      threats.push({
        type: 'threat',
        severity: 'high',
        description: `Script "${scriptName}" uses extensive encoding (${encodingCount} instances). This is a strong indicator of obfuscated malicious code attempting to hide its true purpose.`,
        attackTechnique: 'Obfuscation via encoding',
        remediation: 'Review the decoded content to understand what the script actually does. Avoid packages with heavily obfuscated lifecycle scripts.',
        confidence: Math.min(0.95, 0.5 + encodingCount * 0.1),
      });
    }

    // 2. String concatenation to hide keywords
    const concatenationPatterns = [
      /['"][\w\s]{1,5}['"]\s*\+\s*['"][\w\s]{1,5}['"]\s*\+\s*['"][\w\s]{1,5}['"]/g,
      /['"][\w\s]{1,5}['"]\s*\+\s*\w+\s*\+\s*['"][\w\s]{1,5}['"]/g,
    ];

    let concatenationCount = 0;
    for (const pattern of concatenationPatterns) {
      const matches = content.match(pattern);
      if (matches) concatenationCount += matches.length;
    }

    if (concatenationCount > 2) {
      threats.push({
        type: 'threat',
        severity: 'medium',
        description: `Script "${scriptName}" uses extensive string concatenation (${concatenationCount} instances). This may be used to hide malicious keywords from detection.`,
        attackTechnique: 'Keyword obfuscation',
        remediation: 'Deobfuscate the string concatenations to reveal the actual code. Be suspicious of packages trying to hide what their scripts do.',
        confidence: Math.min(0.85, 0.4 + concatenationCount * 0.15),
      });
    }

    // 3. Eval-like patterns (beyond basic regex)
    const advancedEvalPatterns = [
      /Function\s*\(\s*['"]+[\w\s]*['"]+\s*\)/g,  // Function("code")()
      /new\s+Function\s*\(/g,
      /setInterval\s*\(\s*['"]/g,  // setInterval("code")
      /setTimeout\s*\(\s*['"]/g,   // setTimeout("code")
      /require\s*\(\s*[^'"]*\+/g,  // dynamic require
    ];

    for (const pattern of advancedEvalPatterns) {
      if (pattern.test(content)) {
        threats.push({
          type: 'threat',
          severity: 'high',
          description: `Script "${scriptName}" uses dynamic code execution patterns. This allows arbitrary code execution and is commonly used in malware.`,
          attackTechnique: 'Dynamic code execution',
          remediation: 'Avoid packages with dynamic code execution in lifecycle scripts. This is extremely dangerous even if the code looks innocent.',
          confidence: 0.8,
        });
        break; // Only add once per script
      }
    }

    // 4. Polyglot code (code that can execute in multiple contexts)
    const polyglotIndicators = [
      /\/\/\s*@<script>/i,        // JavaScript inside HTML
      /\/\*\s*@if\s*\(/,          // Conditional compilation
      /<\?[pP][hH][pP]/,          // PHP tags
      /<%/g,                       // ASP tags
    ];

    for (const indicator of polyglotIndicators) {
      if (indicator.test(content)) {
        threats.push({
          type: 'threat',
          severity: 'critical',
          description: `Script "${scriptName}" contains polyglot code patterns. This can execute in multiple contexts and is a hallmark of sophisticated malware.`,
          attackTechnique: 'Polyglot code injection',
          remediation: 'Immediately remove this package. Polyglot code in lifecycle scripts is almost always malicious.',
          confidence: 0.9,
        });
        break;
      }
    }
  }

  return threats;
}

/**
 * Detect multi-stage attacks across multiple scripts
 */
function detectMultiStageAttacks(analysis: PackageAnalysis): AIInsight[] {
  const threats: AIInsight[] = [];
  const { scripts, name } = analysis;

  const scriptNames = Object.keys(scripts);
  if (scriptNames.length < 2) {
    return threats;
  }

  // Check for attack chains across scripts

  // 1. preinstall → postinstall chain (setup then execute)
  if (scripts.preinstall && scripts.postinstall) {
    const preinstallDownloads = /\b(curl|wget|fetch|request|http\.get|axios)\b/i.test(scripts.preinstall);
    const postinstallExecutes = /\b(eval|exec|spawn|bash|sh|node\s+-e)\b/i.test(scripts.postinstall);

    if (preinstallDownloads && postinstallExecutes) {
      threats.push({
        type: 'threat',
        severity: 'critical',
        description: `Multi-stage attack detected: preinstall downloads content, postinstall executes it. This is a classic supply chain attack pattern.`,
        attackTechnique: 'Multi-stage payload delivery',
        remediation: 'Immediately remove this package and review all packages installed around the same time. Scan your system for compromise.',
        confidence: 0.95,
      });
    }
  }

  // 2. Multiple scripts accessing sensitive data
  let sensitiveAccessCount = 0;
  const sensitivePatterns = [
    /~\/\.ssh/, /\.aws/, /process\.env/, /\.env/, /credential/, /secret/, /key/i
  ];

  for (const [scriptName, content] of Object.entries(scripts)) {
    for (const pattern of sensitivePatterns) {
      if (pattern.test(content)) {
        sensitiveAccessCount++;
        break;
      }
    }
  }

  if (sensitiveAccessCount >= 2) {
    threats.push({
      type: 'threat',
      severity: 'high',
      description: `${sensitiveAccessCount} lifecycle scripts access sensitive data. This coordinated access pattern suggests data exfiltration preparation.`,
      attackTechnique: 'Credential harvesting',
      remediation: 'Review all scripts to understand what data they\'re accessing. Consider this package compromised unless you can verify legitimacy.',
      confidence: 0.75,
    });
  }

  // 3. Scripts that create other scripts (persistence mechanism)
  let scriptCreationCount = 0;
  for (const [scriptName, content] of Object.entries(scripts)) {
    const createsScripts = /\b(writeFile|writeFileSync|appendFile|createWriteStream|\.js|\.sh|\.bash)\b/i.test(content);
    if (createsScripts) {
      scriptCreationCount++;
    }
  }

  if (scriptCreationCount >= 2) {
    threats.push({
      type: 'threat',
      severity: 'high',
      description: `${scriptCreationCount} lifecycle scripts create files. This may be a persistence mechanism to maintain access after installation.`,
      attackTechnique: 'Persistence via file creation',
      remediation: 'Search for any unusual files created by this package. Check for newly created scripts in node_modules, /tmp, or home directory.',
      confidence: 0.7,
    });
  }

  return threats;
}

/**
 * Detect novel attack patterns not covered by regex rules
 */
function detectNovelPatterns(analysis: PackageAnalysis): AIInsight[] {
  const threats: AIInsight[] = [];
  const { scripts, name, findings } = analysis;

  // 1. Packages with no regex findings but suspicious behavior
  if (findings.length === 0 && Object.keys(scripts).length > 0) {
    const hasComplexScript = Object.values(scripts).some(content =>
      content.length > 300 || content.includes('&&') || content.includes('||')
    );

    if (hasComplexScript) {
      threats.push({
        type: 'threat',
        severity: 'low',
        description: `Package has complex lifecycle scripts but didn't match known malicious patterns. This doesn't mean it's safe - novel attacks may not match existing rules.`,
        attackTechnique: 'Unknown / novel attack',
        remediation: 'Manually review all lifecycle scripts. Consider whether the functionality is necessary and if you trust the package maintainer.',
        confidence: 0.4,
      });
    }
  }

  // 2. Suspicious package naming patterns
  const suspiciousNaming = [
    /update/i, /patch/i, /fix/i, /critical/i, /security/i,
    /urgent/i, /important/i, /official/i, /verified/i
  ];

  for (const pattern of suspiciousNaming) {
    if (pattern.test(name) && !isWellKnownPackage(name)) {
      threats.push({
        type: 'threat',
        severity: 'medium',
        description: `Package name "${name}" includes urgency/authority keywords. Attackers often use such names to trick users into installing malicious packages.`,
        attackTechnique: 'Typosquatting / impersonation',
        remediation: 'Verify this is the official package. Check spelling, publisher, and download count. Look for the official package instead.',
        confidence: 0.6,
      });
      break;
    }
  }

  // 3. Recently created packages with invasive scripts
  // (We can't check creation date without npm registry API, but we can flag for review)
  if (Object.keys(scripts).length > 2) {
    threats.push({
      type: 'threat',
      severity: 'low',
      description: `Package has ${Object.keys(scripts).length} lifecycle scripts. Most legitimate packages only need 1-2. Multiple scripts may indicate unnecessary complexity or malicious intent.`,
      attackTechnique: 'Excessive script footprint',
      remediation: 'Review each script to understand its purpose. Be suspicious of packages with more lifecycle scripts than necessary.',
      confidence: 0.5,
    });
  }

  return threats;
}

/**
 * Check if package is well-known/legitimate
 */
function isWellKnownPackage(packageName: string): boolean {
  const knownPackages = [
    'eslint', 'prettier', 'typescript', 'babel', 'webpack',
    'vite', 'rollup', 'esbuild', 'jest', 'vitest',
    'lodash', 'axios', 'react', 'vue', 'angular'
  ];

  return knownPackages.some(known => packageName.startsWith(known));
}
