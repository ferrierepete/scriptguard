# ScriptGuard: Next-Gen Detection Pipeline Plan

> Date: 2026-04-13
> Status: Planning (no implementation yet)

---

## The Problem with Regex Alone

Current 26 regex patterns catch obvious attacks but miss:

- **Base64 layered encoding**: `eval(Buffer.from(atob('ZXZhbCgu..'), 'base64').toString())`
- **Hex escapes**: `\x72\x65\x71\x75\x69\x72\x65` = "require"
- **String.fromCharCode**: `String.fromCharCode(114,101,113,117,105,114,101)` = "require"
- **Array-based building**: `['r','e','q','u','i','r','e'].join('')`
- **eval chains**: `new Function(atob(payload))()`
- **Anti-analysis**: code that checks for CI env vars and behaves differently
- **Multi-stage**: script A downloads script B, script B has the real payload

---

## Proposed 4-Layer Architecture

### Layer 1: Fast Regex Pre-Filter (KEEP — current approach)

- ~0.5ms per script, already built
- Catches obvious patterns: `curl | bash`, `eval()`, `child_process`
- Purpose: eliminate ~80% of benign scripts from deeper analysis
- No changes needed — this is the fast path

### Layer 2: AST-Based Pattern Matching (NEW)

- Parse scripts into AST with `acorn` (~3-5ms per script)
- Walk AST looking for structural patterns regex can't see:
  - Dynamic `require()` with computed arguments
  - `eval()` / `new Function()` with non-literal arguments
  - Member expression chains accessing `process.env`, `child_process`, `fs`, `net`
  - String concatenation that builds executable code
  - Property access via computed keys: `obj['con' + 'cat']`
- Dependencies: `acorn` + `acorn-walk` (~60KB, zero native deps)
- Handles: hex escapes, Unicode escapes, computed property access

### Layer 3: Recursive Deobfuscation (NEW)

- Only runs on scripts flagged by Layer 1 or 2
- Pipeline:
  1. Detect base64 layer → decode → re-analyze
  2. Resolve string concatenation → simplify
  3. Extract eval/Function arguments → inline
  4. Constant folding → simplify expressions
  5. Repeat until fixed point (typically 3-5 iterations)
- Uses: `acorn` (parse) + `astring` (generate) + custom transforms
- ~15-30ms per suspicious script
- Catches: multi-layer encoding, obfuscated payloads, eval chains

### Layer 4: AI-Powered Semantic Analysis (UPGRADE existing)

- Only for scripts that are still ambiguous after Layers 1-3
- Send **deobfuscated** code to LLM for classification
- Prompt: "Is this npm lifecycle script malicious? Analyze what it does. Rate: benign/suspicious/malicious"
- Two modes:
  - **Fast mode**: Gemini Flash (~$0.00001/script, ~1s) — for bulk CI scans
  - **Deep mode**: Gemini Pro / GPT-4o-mini (~$0.0001/script, ~3s) — for flagged packages
- AI catches: novel attack patterns, subtle social engineering, context-dependent risks
- Already partially built — needs integration with deobfuscation pipeline

---

## Performance Targets

| Layer | When | Per-Script | For 1000 pkgs |
|-------|------|-----------|---------------|
| L1: Regex | Always | ~0.5ms | ~0.5s |
| L2: AST | L1 flagged (~20%) | ~5ms | ~1s |
| L3: Deobfuscation | L2 flagged (~5%) | ~25ms | ~1.25s |
| L4: AI | L3 ambiguous (~1%) | ~2s | ~20s |
| **Total** | | | **~23s** |

Currently: regex-only scan of 1000 packages = ~0.5s
Target: full 4-layer scan = ~23s for 1000 packages
Acceptable for CI — runs in parallel with tests.

---

## New Detection Categories to Add

Beyond the current 26 patterns, add these AST-aware rules:

1. **Deobfuscation attempts** — code that decodes and evals (base64, hex, ROT13)
2. **Dynamic require** — `require(variable)` or `require(computed string)`
3. **Environment fingerprinting** — checking `CI`, `NODE_ENV`, `TERM` before acting
4. **Sleep/timing checks** — `setTimeout` with long delays (anti-VM)
5. **Conditional execution** — if/else branches that only run in production
6. **Data staging** — collecting env vars/SSH keys into variables before sending
7. **DNS exfiltration** — constructing hostnames from stolen data
8. **Clipboard access** — `child_process` calling `pbcopy`/`xclip`
9. **Crypto pattern obfuscation** — mining scripts hidden in innocent-looking loops
10. **Polyglot scripts** — bash embedded in JS comments, or vice versa

---

## AI Integration Details

### What AI is GOOD at

- Reducing false positives on flagged scripts (e.g., `process.env.PORT` is fine, `process.env.AWS_SECRET` is not)
- Understanding context — is this a build tool or data thief?
- Catching novel attack patterns not in any rule set
- Explaining WHY a script is suspicious (for human review)

### What AI is BAD at

- Analyzing raw obfuscated code (needs deobfuscation first)
- Consistent classification of edge cases
- Speed (seconds vs milliseconds)
- Running without network (can't hit API offline)

### Recommended approach

- AI as a **judge**, not a scanner — only evaluate pre-processed, deobfuscated scripts
- Use few-shot prompting with 10-20 examples of malicious vs benign scripts
- Return structured JSON: `{verdict, confidence, reasoning, riskScore}`
- Cache results by script hash — same script never analyzed twice
- Fallback: if AI is unavailable, fall back to Layer 1-3 results with lower confidence

### Cost estimate (Gemini Flash)

- ~500 tokens per script analysis
- ~$0.00001 per script at current pricing
- Scanning 100 packages/day = ~$0.03/month

---

## Competitive Landscape

### How teams manage this right now

1. **Most teams**: just `npm audit` in CI — completely blind to lifecycle script content
2. **~15-25% of serious teams**: use `--ignore-scripts` — breaks legit packages (bcrypt, sharp, esbuild)
3. **Security-conscious orgs**: pay for Socket.dev ($25/seat/mo) or Snyk ($52/dev/mo)
4. **Small teams**: can't afford commercial tools, have NO lifecycle script coverage
5. **Many developers**: unaware that `npm install` runs arbitrary code

### Feature Comparison

| Feature | ScriptGuard | Socket.dev | Snyk | npm audit | ignore-scripts | Phylum |
|---------|-------------|------------|------|-----------|----------------|--------|
| Script content analysis | ✅ (26 patterns) | ✅ (deep) | ❌ | ❌ | N/A | ✅ (basic) |
| Local/offline | ✅ | ❌ | ✅ (CLI) | ✅ | ✅ | ❌ |
| Free | ✅ | Limited | Limited | ✅ | ✅ | Limited |
| Open source | ✅ | ❌ | ❌ | ✅ | N/A | ❌ |
| CI/CD integration | ✅ (SARIF) | ✅ | ✅ | ✅ | Manual | ✅ |
| AI analysis | ✅ (Gemini) | ✅ (proprietary) | ❌ | ❌ | N/A | ❌ |
| CVE database | ❌ | ✅ | ✅ | ✅ | N/A | ✅ |
| Proactive (unknown attacks) | ✅ (patterns) | ✅ | ❌ | ❌ | ✅ (blocks) | ✅ |
| Obfuscation detection | Planned | ✅ | ❌ | ❌ | N/A | Partial |

### Key differentiators

- Only free, open source, LOCAL tool that analyzes script content
- SARIF output = direct GitHub Advanced Security integration
- AI analysis via Gemini = deeper than regex alone
- Complements npm audit/Snyk (doesn't compete)
- This 4-layer pipeline would be genuinely unique in the free/local space

---

## Implementation Priority

### Phase 1 — AST Foundation (est. 1 week)

- Add `acorn` + `acorn-walk` dependencies
- Build AST walker with pattern detection rules
- Integrate as Layer 2 between regex pre-filter and reporting
- Test against known malicious packages

### Phase 2 — Deobfuscation (est. 1-2 weeks)

- Build recursive deobfuscation pipeline
- Base64/hex/eval layer peeling
- String concatenation resolution
- Integrate with Layer 2 for re-analysis
- Test against obfuscated real-world samples

### Phase 3 — AI Integration Upgrade (est. 1 week)

- Upgrade existing Gemini integration to use deobfuscated input
- Add few-shot prompt with malicious/benign examples
- Structured JSON output with confidence scores
- Result caching by script hash

### Phase 4 — Advanced Rules (est. ongoing)

- Add new detection categories (fingerprinting, timing, staging)
- Environment-aware risk scoring
- Polyglot detection (bash-in-JS)
- Community-contributed patterns

---

## Technical Notes

### AST parsing benchmarks (typical lifecycle script ~2-5KB)

- acorn: 2-5ms (pure JS) ← recommended
- @babel/parser: 5-15ms
- tree-sitter (WASM): 0.5-2ms (complexity not worth it vs acorn)
- esprima: 3-8ms (superseded by acorn)

### Recommended dependencies (3 packages, ~200KB total)

- `acorn` — parsing
- `acorn-walk` — AST traversal
- `astring` — code generation (for deobfuscation output)

### What NOT to implement

- Symbolic execution (no practical JS tools exist)
- Dynamic taint analysis (requires code execution = security risk)
- tree-sitter (WASM complexity not worth it vs acorn's speed)
- CodeQL integration (too slow for real-time, ~5-30s per package)

---

## Research Sources

- Socket.dev blog and product documentation
- Snyk npm security research
- GitHub Blog: supply chain security guidance
- Reddit (r/node, r/javascript, r/cybersecurity, r/netsec) community discussions
- Hacker News threads on npm supply chain attacks
- Sonatype/OpsShift research reports on npm malware
- acorn, acorn-walk, astring documentation
- Semgrep taint mode documentation
- npm advisory database and security advisories
