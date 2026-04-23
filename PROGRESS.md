# Project Progress

## ⚠️ NPM Publish Policy
This package must NOT be published to npm by automated processes (cron jobs, agents). Peter will manually test and manually publish to npm. If the package is code-complete and ready for npm, note the status here and move on.

## What: Security scanner for npm package lifecycle scripts — 4-layer detection pipeline (regex → AST → deobfuscation → AI) catches obfuscated supply chain attacks
## Last Updated: 2026-04-20

## Definition of Done Checklist
- [x] Core feature works end-to-end (4-layer pipeline: regex, AST, deobfuscation, AI analysis)
- [x] Build passes with zero errors
- [x] 5+ unit tests passing (multiple test suites including AST, AI, scanner tests)
- [x] README complete (badges, install, usage, detection evidence)
- [x] No placeholders or TODOs in production code
- [x] Error handling
- [x] Git initialized with clean commit history
- [ ] Remote configured and pushed — **BLOCKED: No GH_TOKEN**
- [x] package.json complete (name, version, description, bin, scripts, keywords)
- [x] **npm published** — `scriptguard@1.2.1` on npm ✅

## What's Done
- 4-layer detection pipeline: regex → AST analysis → deobfuscation → AI (Gemini/OpenAI)
- Real-world attack fixtures (flatmap-stream, node-ipc, ua-parser-js)
- CLI with scan, check commands
- AI-powered threat analysis with dynamic insights
- EVIDENCE.md documenting real-world attack detection
- Full CHANGELOG, CODE_OF_CONDUCT, CONTRIBUTING guides

## What's Remaining
- GitHub push (blocked by missing GH_TOKEN)

## Known Issues
- None blocking
