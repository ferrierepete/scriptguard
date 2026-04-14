# Contributing to ScriptGuard

Thanks for your interest in improving ScriptGuard! Contributions of all kinds are welcome — bug reports, feature ideas, detection patterns, code, and docs.

## Quick Start

```bash
git clone https://github.com/ferrierepete/scriptguard.git
cd scriptguard
npm install
npm run build
npm test
```

## Development

| Command | Description |
|---------|-------------|
| `npm run build` | Compile TypeScript to `dist/` |
| `npm test` | Run test suite (Vitest) |
| `npm run test:watch` | Run tests in watch mode |
| `npm run lint` | Type-check without emitting |

## Reporting Bugs

Open a [GitHub Issue](https://github.com/ferrierepete/scriptguard/issues/new) and include:

1. **ScriptGuard version** — `scriptguard --version`
2. **Node.js version** — `node --version`
3. **The package** that triggered the issue (name/version or a sample `package.json`)
4. **Expected vs actual behavior**
5. **Output** — paste the command output or a screenshot

## Suggesting Features

Open an issue with the label `enhancement` and describe:

- The use case or threat pattern you want to address
- How you expect it to work
- Any examples of real-world packages that exhibit the pattern

## Adding Detection Patterns

1. Add your pattern to `src/scanners/patterns.ts` in the `PATTERN_RULES` array
2. Each pattern needs:
   - `pattern`: RegExp for the detection
   - `category`: One of `network`, `execution`, `filesystem`, `exfiltration`, `obfuscation`, `crypto`, `ast-level`
   - `description`: Clear explanation of what it catches
   - `riskLevel`: `low`, `medium`, `high`, or `critical`
   - `riskScore`: Weighted score (0-100)
3. Add a test fixture in `tests/fixtures/` and a corresponding test in `tests/scanner.test.ts`
4. Run `npm test` to verify

## Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b my-feature`
3. Make your changes with tests
4. Ensure all tests pass: `npm test`
5. Ensure the build is clean: `npm run build`
6. Open a PR against `main`

### PR Guidelines

- One logical change per PR
- Include tests for new functionality
- Update `CHANGELOG.md` under an `[Unreleased]` heading
- Keep changes focused — avoid unrelated refactors in the same PR

## Code Style

- TypeScript strict mode — no `any` without justification
- Follow the existing patterns in the codebase
- Run `npm run lint` before submitting — it should produce no errors

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
