# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-04-14

### Changed

- Deobfuscation layer no longer gated behind AST findings — runs when encoding patterns (hex, base64, unicode escapes, atob, Buffer.from) are detected in the script content
- Pipeline order restructured: Regex → Deobfuscation → AST (runs on both original and deobfuscated content)
- Deobfuscation no longer discards decoded content that isn't valid JavaScript (e.g. shell commands with decoded arguments) — still useful for regex pattern matching

## [1.1.3] - 2026-04-14

### Fixed

- `newThreatsDetected` now derived from actual threat insights count instead of AI model-reported number — terminal and JSON output always agree
- Threat severity icon in AI summary dynamically reflects the highest threat level instead of hardcoded orange

## [1.1.2] - 2026-04-14

### Fixed

- `findingsByLevel` now counts only static (regex/AST) findings — sums correctly to `totalFindings`
- `overallRiskLevel` is derived from `overallRiskScore` thresholds, not from `findingsByLevel`, so AI-escalated severity flows through blended per-package scores

## [1.1.1] - 2026-04-14

### Fixed

- AI threat insights no longer create duplicate `ai-threat` entries in the findings array. They live only in `aiAnalysis.insights` — clean separation between static findings and AI analysis
- `totalFindings` now counts only static (regex/AST) findings — no inflation from AI
- `findingsByLevel` and `overallRiskLevel` still correctly reflect AI-escalated severities via blended scoring
- `shouldFail` now checks AI threat insights in addition to static findings, so `--fail-on critical` catches AI-flagged packages

## [1.1.0] - 2026-04-14

### Added

- `fs-write` pattern — detects `fs.writeFile`, `fs.writeFileSync`, `fs.unlink`, and other filesystem modifications (high)
- `network-interfaces` pattern — detects `os.networkInterfaces()` enumeration (medium)
- `home-dir-access` pattern — detects `os.homedir()` access (high)
- `geo-ip-lookup` pattern — detects IP geolocation API calls for location-based targeting (critical)
- Protestware test fixture based on node-ipc incident

### Fixed

- AI threat insights now create synthetic findings so `findingsByLevel`, `overallRiskLevel`, and `--fail-on critical` reflect AI-escalated severity
- Removed crude +20/-30 score heuristic in favor of proper score recalculation from findings (including AI-generated ones)
- `recalculateOverall` now recomputes per-package `riskScore` and `riskLevel` from findings, not just top-level totals

## [1.0.5] - 2026-04-14

### Fixed

- `overallRiskScore` and `overallRiskLevel` now reflect AI-adjusted per-package scores instead of showing stale pre-AI values

## [1.0.4] - 2026-04-14

### Fixed

- AI insights now render once per package instead of repeating identically for every finding

### Changed

- AI analysis is now stored at the package level (`PackageAnalysis.aiAnalysis`) instead of per-finding

## [1.0.3] - 2026-04-14

### Added

- `--ai` flag on `check` command — AI-powered analysis of a single package.json (false positive filtering, threat detection, insights)
- `--explain` flag on `check` command — AI narrates each finding in plain English (auto-enables `--ai`)
- `--ai-mode`, `--ai-mitigation`, `--ai-max-tokens`, `--ai-timeout` flags on `check` command (parity with `scan`)
- `scanPackageJsonWithAI()` async function for programmatic use with optional AI enrichment
- `AIMode`, `AIOptions`, `AIAnalysis`, `AIInsight` types exported from public API
- 17 tests covering `check --ai`, `check --explain`, mocked AI enrichment, graceful degradation, and CLI integration

## [1.0.2] - 2026-04-14

### Added

- AST-based pattern matching layer — detects dynamic `require()`, computed `eval()`, computed property access, and string building patterns
- Deobfuscation layer — decodes base64, hex escape, and unicode payloads and re-analyzes decoded content
- 4-layer detection pipeline: regex → AST → deobfuscation → AI
- `--no-ast` and `--no-deobfuscate` CLI flags for fine-grained control
- Few-shot examples in AI analysis prompts for better accuracy
- Content-hash-based caching in Gemini client for better cache hit rates
- `ASTFinding` and `DeobfuscationResult` types
- AST and deobfuscation test fixtures
- `acorn` and `acorn-walk` as dependencies for JavaScript parsing

## [1.0.1] - 2026-04-13

### Added

- AI-powered script analysis with Google Gemini integration
- Three AI analysis modes: basic, standard, thorough
- False positive filtering via AI context analysis
- Threat detection and insight generation analyzers
- SARIF output format for GitHub Advanced Security integration
- `--ai`, `--ai-mode`, and `--ai-mitigation` CLI flags
- AI response caching (24-hour TTL)
- `.npmignore` for clean npm package publishing

## [1.0.0] - 2026-04-12

### Added

- Core lifecycle script scanner with 26 detection patterns across 6 categories
- CLI with `scan`, `check`, and `patterns` commands
- Table, JSON, and SARIF output formats
- Risk scoring (0-100) with LOW/MEDIUM/HIGH/CRITICAL levels
- `--fail-on` flag for CI/CD exit codes
- `--include-dev` flag for dev dependency scanning
- Programmatic API for library usage
- TypeScript strict mode build
- 20 unit tests with Vitest
