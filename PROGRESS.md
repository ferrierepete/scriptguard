# Project Progress

## What: Security scanner for npm package lifecycle scripts — detect malicious postinstall, preinstall, and prepare scripts before they run
## Last Updated: 2026-04-12

## Definition of Done Checklist
- [x] Core feature works end-to-end (26 patterns, 6 categories, scan/check/patterns commands)
- [x] Build passes with zero errors (tsc clean)
- [x] 5+ unit tests passing (20 tests across 1 suite, all passing)
- [x] README complete (install, usage, CI/CD, API, tech stack)
- [x] No placeholders or TODOs in production code
- [x] Error handling (missing node_modules, malformed JSON, bad paths)
- [ ] Git initialized, clean history — **TODO**
- [ ] Remote configured and pushed — **BLOCKED: No GH_TOKEN**
- [x] package.json complete (name, version, description, bin, scripts, keywords)

## What's Done
- **26 detection patterns** across 6 categories (network, execution, filesystem, exfiltration, obfuscation, crypto)
- **CLI with 3 commands**: scan (project-wide), check (single package.json), patterns (list rules)
- **3 output formats**: table (colored terminal), JSON (machine-readable), SARIF (GitHub AS)
- **CI mode**: --fail-on flag for non-zero exit on threshold breach
- **Risk scoring**: 0-100 weighted scores, LOW/MEDIUM/HIGH/CRITICAL levels
- **20 unit tests**: lifecycle extraction, risk scoring, malicious/safe/suspicious/obfuscated package detection, pattern validation
- **Programmatic API**: exported functions for library usage
- **TypeScript**: strict mode, clean build
- **npm name available**: `scriptguard` is not taken (different from the React-focused `hookguard`)

## What's Remaining
- **Git init + commit** — needs to be done
- **Push to GitHub** — blocked by GH_TOKEN
- **npm publish** — name available, ready to publish
- **Test on real project** — scan a project with node_modules
- **Consider: `scriptguard init`** — add as postinstall hook to prevent future bad installs

## Known Issues
- GitHub push blocked (no GH_TOKEN in env — recurring blocker across all projects)
- base64-exec pattern requires decode THEN execute in same string; shell eval wrapping decode isn't caught by combined pattern (but eval-usage catches the eval part)
- No auto-update mechanism for detection patterns
