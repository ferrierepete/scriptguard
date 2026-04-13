/** ScriptGuard — AI prompt templates for different analysis modes */

import type { AIMode, AIBatchRequest } from '../types/index.js';

/**
 * Build the analysis prompt based on mode
 */
export function buildPrompt(request: AIBatchRequest, mode: AIMode): string {
  const basePrompt = getBasePrompt();
  const modePrompt = getModePrompt(mode);
  const packageData = formatPackageData(request);

  return `${basePrompt}\n\n${modePrompt}\n\n${packageData}\n\n${getOutputInstructions(mode)}`;
}

/**
 * Base system prompt - context about ScriptGuard and npm security
 */
function getBasePrompt(): string {
  return `You are ScriptGuard AI, an expert security analyst specializing in npm package supply chain attacks.

Your task is to analyze npm package lifecycle scripts (postinstall, preinstall, prepare, etc.) and provide security insights.

## Context

- **Supply chain attacks**: Malicious code often hides in lifecycle scripts that run automatically during \`npm install\`
- **Common threats**: Remote code execution (curl | bash), credential theft, data exfiltration, obfuscated payloads
- **False positives**: Many legitimate packages use similar patterns for build tools, platform-specific binaries, or configuration

## Your Role

1. **Distinguish safe from unsafe**: Understand context to identify false positives
2. **Detect advanced threats**: Identify obfuscated code, novel attack patterns, multi-stage attacks
3. **Provide actionable insights**: Explain threats clearly and suggest remediation steps

## Safety Rules

- **DO NOT** execute any code - analyze only
- **Assume malicious intent** unless there's clear evidence of legitimacy
- **Flag suspicious patterns** even if they might be legitimate - better safe than sorry
- **Consider the package context**: Unknown packages with risky scripts = higher suspicion`;
}

/**
 * Mode-specific instructions
 */
function getModePrompt(mode: AIMode): string {
  switch (mode) {
    case 'basic':
      return `## Analysis Mode: Basic

Focus on identifying **false positives** from regex pattern matching.

For each package with findings:
1. Analyze the script content and context
2. Determine if the pattern match represents a real threat or a false positive
3. Consider: Is this a well-known package? Does the pattern serve a legitimate purpose?
4. Provide brief explanation for your decision

**Time constraint**: Quick analysis, focus on obvious false positives`;

    case 'standard':
      return `## Analysis Mode: Standard

Provide comprehensive security analysis for each package.

For each package:
1. **False positive analysis**: Determine which regex matches are false positives
2. **Threat detection**: Identify advanced threats (obfuscation, novel patterns, multi-stage attacks)
3. **Contextual understanding**: What does this script actually do?
4. **Risk assessment**: Overall confidence in your analysis

**Output**: Balanced depth - detailed analysis without excessive detail`;

    case 'thorough':
      return `## Analysis Mode: Thorough

Perform deep security analysis with cross-script correlation.

For each package:
1. **Comprehensive false positive analysis**: Examine each finding in detail
2. **Advanced threat detection**: Identify obfuscation, encoding, polyglot code, novel attack patterns
3. **Cross-script correlation**: Analyze relationships between multiple lifecycle scripts
4. **Attack chain identification**: Detect multi-stage attacks across scripts
5. **Package reputation context**: Consider package name, version patterns, script complexity
6. **Detailed explanations**: Step-by-step breakdown of what the code does

**Output**: Maximum depth - leave no stone unturned`;
  }
}

/**
 * Format package data for the AI
 */
function formatPackageData(request: AIBatchRequest): string {
  const packages = request.packages.map((pkg, idx) => {
    const scriptsList = Object.entries(pkg.scripts)
      .map(([name, content]) => `\`${name}\`: ${content}`)
      .join('\n    ');

    const findingsList = pkg.findings.length > 0
      ? pkg.findings.map(f =>
          `  - Pattern: \`${f.pattern}\` (Risk: ${f.riskLevel})\n` +
          `    Match: \`${f.match.substring(0, 100)}${f.match.length > 100 ? '...' : ''}\``
        ).join('\n')
      : '  (No regex findings)';

    return `## Package ${idx + 1}: ${pkg.name}@${pkg.version}

**Lifecycle Scripts:**
    ${scriptsList}

**Regex Pattern Findings:**
${findingsList}`;
  }).join('\n\n');

  return `## Packages to Analyze

Total packages: ${request.packages.length}

${packages}`;
}

/**
 * Output format instructions for the AI
 */
function getOutputInstructions(mode: AIMode): string {
  return `## Required Output Format

Respond ONLY with valid JSON in this exact structure:

\`\`\`json
{
  "analyses": [
    {
      "package": "package-name",
      "version": "1.0.0",
      "falsePositivesFiltered": 2,
      "newThreatsDetected": 1,
      "insights": [
        {
          "type": "false-positive",
          "severity": "low",
          "description": "Brief explanation of why this is a false positive",
          "confidence": 0.9
        },
        {
          "type": "threat",
          "severity": "high",
          "description": "Detailed explanation of the threat",
          "attackTechnique": "e.g., DNS tunneling, reverse shell, credential theft",
          "remediation": "Specific steps to mitigate",
          "confidence": 0.85
        }
      ],
      "confidence": 0.88,
      "tokensUsed": 150
    }
  ],
  "totalTokensUsed": 150
}
\`\`\`

## Field Descriptions

- **type**: Either "false-positive", "threat", or "mitigation"
- **severity**: "low", "medium", "high", or "critical"
- **description**: Clear, concise explanation
- **attackTechnique**: (optional) Name of the attack technique (e.g., "reverse shell", "DNS exfiltration")
- **remediation**: (optional) Specific steps to fix or mitigate the issue
- **confidence**: Number from 0.0 to 1.0 indicating your certainty

## Insight Type Guidelines

**false-positive**: The regex match is actually safe
  - Example: \`process.env.PORT\` is for config, not exfiltration
  - Example: \`child_process\` compiling native modules
  - Required fields: type, severity, description, confidence

**threat**: Confirmed security issue (including missed threats)
  - Example: Obfuscated base64 payload
  - Example: Suspicious network request to unknown domain
  - Required fields: type, severity, description, attackTechnique (optional), remediation, confidence

**mitigation**: Remediation advice for confirmed threats
  - Example: "Remove this script entirely" or "Replace with auditable alternative"
  - Required fields: type, severity, description, remediation, confidence

## Confidence Scoring

- **0.9-1.0**: Very confident - clear evidence
- **0.7-0.9**: Confident - strong indicators
- **0.5-0.7**: Moderately confident - some ambiguity
- **0.3-0.5**: Low confidence - significant uncertainty
- **0.0-0.3**: Very uncertain - highly speculative

## Additional Guidelines

${mode === 'basic' ? `- Focus on obvious false positives
- Keep descriptions brief (1-2 sentences)
- Only report high-confidence findings (>0.7)` : mode === 'standard' ? `- Provide balanced detail
- Include both obvious and subtle findings
- Report moderate-confidence findings (>0.5)` : `- Be exhaustive in your analysis
- Report all findings regardless of confidence
- Provide detailed explanations and context
- Correlate findings across multiple scripts
- Consider package reputation and naming patterns`}

**CRITICAL**: Respond with ONLY the JSON. No markdown formatting, no explanations outside the JSON structure.`;
}

/**
 * Sanitize script content to remove obvious secrets before sending to AI
 */
export function sanitizeForPrompt(content: string): string {
  // Redact API keys, tokens, secrets
  return content
    .replace(/(?:api[_-]?key|secret|token)\s*[:=]\s*['"]?[a-zA-Z0-9_\-]{20,}['"]?/gi, '[REDACTED_SECRET]')
    .replace(/bearer\s+[a-zA-Z0-9_\-]{20,}/gi, 'bearer [REDACTED_TOKEN]')
    .replace(/sk-[a-zA-Z0-9]{48}/g, 'sk-[REDACTED]')
    .replace(/ghp_[a-zA-Z0-9]{36}/g, 'ghp_[REDACTED]')
    .replace(/AKIA[0-9A-Z]{16}/g, 'AKIA[REDACTED]');
}
