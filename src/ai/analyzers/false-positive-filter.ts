/** ScriptGuard — False positive filter analyzer */

import type { PackageAnalysis, Finding, AIInsight } from '../../types/index.js';

/**
 * Analyze findings to identify false positives
 * This is a lightweight analyzer that works in conjunction with AI analysis
 */
export function analyzeFalsePositives(
  analysis: PackageAnalysis,
  aiInsights: AIInsight[]
): {
  filteredFindings: Finding[];
  falsePositivesFiltered: number;
} {
  const filteredFindings: Finding[] = [];
  let falsePositivesFiltered = 0;

  // Get AI-identified false positives
  const aiFalsePositives = new Set(
    aiInsights
      .filter(insight => insight.type === 'false-positive')
      .map(insight => insight.description)
  );

  for (const finding of analysis.findings) {
    const isFalsePositive = isLikelyFalsePositive(finding, analysis);

    if (isFalsePositive || aiMatchesFinding(finding, aiFalsePositives)) {
      falsePositivesFiltered++;
    } else {
      filteredFindings.push(finding);
    }
  }

  return {
    filteredFindings,
    falsePositivesFiltered,
  };
}

/**
 * Rule-based false positive detection
 * Works independently of AI to catch obvious cases
 */
function isLikelyFalsePositive(finding: Finding, analysis: PackageAnalysis): boolean {
  const { pattern, scriptContent, scriptName } = finding;

  // Known safe patterns in specific contexts

  // 1. child_process for build tools (esbuild, webpack, vite, etc.)
  if (pattern === 'child-process') {
    const safeBuildTools = [
      'esbuild', 'webpack', 'vite', 'rollup', 'tsc', 'ts-node',
      'babel', 'prebuild', 'postbuild', 'node-gyp', 'node-pre-gyp',
      'cmake', 'make', 'gyp', 'preinstall', 'npm run'
    ];
    const scriptLower = scriptContent.toLowerCase();
    if (safeBuildTools.some(tool => scriptLower.includes(tool))) {
      return true;
    }
  }

  // 2. process.env for configuration (not exfiltration)
  if (pattern === 'env-exfil') {
    const safeEnvVars = [
      'PORT', 'HOST', 'NODE_ENV', 'DEBUG', 'VERBOSE', 'LOG_LEVEL',
      'CI', 'DEPLOYMENT', 'ENVIRONMENT', 'CONFIG', 'PATH',
      'HOME', 'TMP', 'TEMP', 'USER', 'SHELL'
    ];
    const hasSafeEnv = safeEnvVars.some(envVar =>
      scriptContent.includes(`process.env.${envVar}`) ||
      scriptContent.includes(`${envVar}=`)
    );
    const hasSuspiciousEnv = [
      'SECRET', 'KEY', 'TOKEN', 'PASSWORD', 'CREDENTIAL', 'AWS_',
      'API_KEY', 'PRIVATE', 'AUTH'
    ].some(suspicious =>
      scriptContent.toLowerCase().includes(suspicious.toLowerCase())
    );

    // Only mark as false positive if we see safe env vars but no suspicious ones
    if (hasSafeEnv && !hasSuspiciousEnv) {
      return true;
    }
  }

  // 3. HTTP requests to well-known CDN/registry (not data exfiltration)
  if (pattern === 'http-request' || pattern === 'curl-silent') {
    const safeDomains = [
      'npmjs.com', 'unpkg.com', 'cdn.jsdelivr.net', 'cdn.skypack.dev',
      'esm.sh', 'github.com', 'raw.githubusercontent.com',
      'registry.npmjs.org', 'registry.yarnpkg.com'
    ];
    const hasSafeDomain = safeDomains.some(domain =>
      scriptContent.includes(domain)
    );
    const hasSuspiciousDomain = [
      'pastebin', 'transfer.sh', 'tinyurl', 'bit.ly', 'discord',
      'exfil', 'evil', 'malware', 'payload'
    ].some(suspicious =>
      scriptContent.toLowerCase().includes(suspicious)
    );

    if (hasSafeDomain && !hasSuspiciousDomain) {
      return true;
    }
  }

  // 4. chmod for making binaries executable (common in native modules)
  if (pattern === 'chmod-exec') {
    const binaryExtensions = ['.exe', '.bin', '.node', '.sh', '.bash'];
    const hasBinary = binaryExtensions.some(ext =>
      scriptContent.includes(ext)
    );
    const hasSuspiciousTarget = [
      '/bin/bash', '/bin/sh', 'authorized_keys', 'ssh',
      'password', 'secret', 'credential'
    ].some(suspicious =>
      scriptContent.toLowerCase().includes(suspicious.toLowerCase())
    );

    if (hasBinary && !hasSuspiciousTarget) {
      return true;
    }
  }

  // 5. Write to temp dir for legitimate build purposes
  if (pattern === 'tmp-write') {
    const legitimateTempUsage = [
      'extract', 'download', 'cache', 'build', 'compile',
      'install', 'binary', 'artifact'
    ];
    const hasLegitimatePurpose = legitimateTempUsage.some(purpose =>
      scriptContent.toLowerCase().includes(purpose)
    );
    const hasSuspiciousPurpose = [
      'reverse', 'shell', 'payload', 'malware', 'evil'
    ].some(suspicious =>
      scriptContent.toLowerCase().includes(suspicious)
    );

    if (hasLegitimatePurpose && !hasSuspiciousPurpose) {
      return true;
    }
  }

  return false;
}

/**
 * Check if AI identified this finding as a false positive
 */
function aiMatchesFinding(finding: Finding, aiFalsePositives: Set<string>): boolean {
  // Check if any AI false positive description mentions this pattern or match
  for (const aiDesc of aiFalsePositives) {
    if (aiDesc.toLowerCase().includes(finding.pattern.toLowerCase()) ||
        aiDesc.toLowerCase().includes(finding.match.toLowerCase().substring(0, 50))) {
      return true;
    }
  }
  return false;
}

/**
 * Calculate confidence score for false positive determination
 */
export function getFalsePositiveConfidence(finding: Finding, analysis: PackageAnalysis): number {
  let confidence = 0.5; // Base confidence

  const { pattern, scriptContent } = finding;

  // Higher confidence for well-known packages
  if (isWellKnownPackage(analysis.name)) {
    confidence += 0.2;
  }

  // Higher confidence if script is simple and clear
  if (scriptContent.length < 200) {
    confidence += 0.1;
  }

  // Lower confidence for complex scripts
  if (scriptContent.length > 500) {
    confidence -= 0.1;
  }

  // Lower confidence for critical patterns
  if (finding.riskLevel === 'critical') {
    confidence -= 0.2;
  }

  return Math.max(0, Math.min(1, confidence));
}

/**
 * Check if package is well-known/legitimate
 */
function isWellKnownPackage(packageName: string): boolean {
  const knownPackages = [
    'eslint', 'prettier', 'typescript', 'babel', 'webpack',
    'vite', 'rollup', 'esbuild', 'jest', 'vitest', 'mocha',
    'lodash', 'axios', 'react', 'vue', 'angular', 'svelte',
    'express', 'koa', 'fastify', 'next', 'nuxt', 'gatsby',
    '@types', '@babel', '@typescript', '@vue', '@angular'
  ];

  return knownPackages.some(known => packageName.startsWith(known));
}
