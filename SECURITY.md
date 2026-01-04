# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security seriously at Khao2. If you discover a security vulnerability, please report it responsibly.

### How to Report

**Email:** odin@odinglynn.com

Please include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fixes (optional)

### What to Expect

- **Acknowledgment:** Within 48 hours
- **Initial Assessment:** Within 7 days
- **Resolution Timeline:** Depends on severity, typically 30-90 days

### Scope

This policy covers:
- The `khao2` CLI tool
- Configuration handling and token storage
- API communication security

Out of scope:
- The Khao2 SaaS platform (report separately at https://www.khao2.com)
- Third-party dependencies (report to respective maintainers)

### Safe Harbor

We will not pursue legal action against security researchers who:
- Act in good faith
- Avoid privacy violations and data destruction
- Do not exploit vulnerabilities beyond proof-of-concept
- Report findings promptly and confidentially

## Security Best Practices

When using Khao2:
- Keep your API token secure and never commit it to version control
- Use environment variables or the secure config storage (`~/.khao2/forensicwaffle`)
- Regularly rotate your API keys
- Keep the CLI updated to the latest version
