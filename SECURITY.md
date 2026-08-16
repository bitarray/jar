# Security Policy

## Reporting a Vulnerability

We take security seriously. If you discover a vulnerability, please report it responsibly.

### How to Report

**Preferred method:** Use [GitHub Security Advisories](https://github.com/jarchain/jar/security/advisories/new)

Do NOT open a public issue for security vulnerabilities.

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Potential impact
- Suggested fix (if any)

## Response Timeline

| Stage | Timeline |
|-------|----------|
| Initial response | Within 48 hours |
| Triage | Within 7 days |
| Fix development | Depends on severity |
| Disclosure | After fix is released |

## Disclosure Policy

We follow **coordinated disclosure**:

1. Report received and confirmed
2. Fix developed and tested
3. Fix merged and released
4. Advisory published
5. CVE requested (if applicable)

Please do not disclose publicly until a fix is available.

## Supported Versions

| Version | Supported |
|---------|-----------|
| master branch | ✅ |
| Development builds | ⚠️ Best effort |

## Security Best Practices

- We use `cargo audit` in CI to detect known vulnerabilities
- Dependencies are pinned to specific versions
- `unsafe` code requires `// SAFETY:` comments

## Known Advisories

Check [GitHub Security Advisories](https://github.com/jarchain/jar/security/advisories) for published advisories.

---

Thank you for helping keep JAR secure.
