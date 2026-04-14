# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
