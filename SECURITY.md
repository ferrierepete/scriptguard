# Security Policy

## Reporting a Vulnerability

If you find a security vulnerability in ScriptGuard — a bypass of its detection, a crash from malicious input, or any security-relevant bug — please report it privately.

**Do not open a public GitHub issue.**

Instead, use one of these methods:

- **GitHub Security Advisories**: [Report a vulnerability](https://github.com/ferrierepete/scriptguard/security/advisories/new)
- **Email**: Send details to the repository maintainer via GitHub profile

Please include:

1. A description of the vulnerability
2. Steps to reproduce (sample package, script, or input)
3. The impact (what an attacker could achieve)
4. Any suggested fix

## Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 5 business days
- **Fix or mitigation**: Depends on severity, but critical issues will be prioritized

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 1.0.x   | Yes       |

## Scope

### In Scope

- Detection bypasses (malicious scripts that ScriptGuard fails to flag)
- False negative patterns (legitimate threats not caught by the scanner)
- Crashes or denial-of-service from scanning malicious packages
- Path traversal or injection via scanner input

### Out of Scope

- Threats in packages that ScriptGuard is not designed to detect (e.g., runtime behavior)
- Feature requests for new detection categories (open a regular issue instead)

## Disclaimer

ScriptGuard performs **static analysis only** — it does not execute package code. However, it parses JavaScript (via acorn) and decodes strings (base64, hex, unicode). If you discover a vulnerability in these parsing paths, please report it using the process above.
