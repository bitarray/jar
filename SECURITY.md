# Security Policy

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue in
JAR or the Grey node, please report it responsibly.

### Preferred: GitHub Security Advisories

Submit a private vulnerability report via
[GitHub Security Advisories](https://github.com/jarchain/jar/security/advisories/new).

This allows us to coordinate a fix before public disclosure.

### Alternative: Email

Send a description of the vulnerability to the project maintainers via
[GitHub](https://github.com/jarchain/jar). Please do **not** file a public
issue for security vulnerabilities.

## What to Include

- Description of the vulnerability
- Steps to reproduce (if applicable)
- Affected versions
- Potential impact
- Suggested fix (if you have one)

## Response Timeline

| Stage | Target |
|-------|--------|
| Acknowledgment | Within 48 hours |
| Initial assessment | Within 5 business days |
| Fix or mitigation | Depends on severity and complexity |

## Disclosure Policy

- We follow **coordinated disclosure**
- Vulnerabilities are disclosed after a fix is available
- We credit reporters in security advisories (unless anonymity is requested)

## Supported Versions

| Version | Supported |
|---------|-----------|
| master branch | ✅ |
| Release tags | ✅ |

## Known Security Advisories

The project uses `cargo audit` in CI to monitor for known vulnerabilities in
Rust dependencies. See [Issue #722](https://github.com/jarchain/jar/issues/722)
for the current status of RUSTSEC advisories affecting the codebase.
