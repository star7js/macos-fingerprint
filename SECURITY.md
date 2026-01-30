# Security Policy

## Supported Versions

We release patches for security vulnerabilities for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 2.0.x   | :white_check_mark: |
| < 2.0   | :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to the maintainers at:
- Create a [Security Advisory](https://github.com/star7js/macos-fingerprint/security/advisories/new)
- Or email: [maintainer email - update this]

You should receive a response within 48 hours. If for some reason you do not, please follow up to ensure we received your original message.

Please include the following information:

- Type of issue (e.g. buffer overflow, SQL injection, cross-site scripting, etc.)
- Full paths of source file(s) related to the manifestation of the issue
- The location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit the issue

## Security Best Practices

When using macOS Fingerprint:

1. **Encrypt sensitive fingerprints**: Use `--encrypt` flag for sensitive data
2. **Secure storage**: Store fingerprints in secure locations with proper permissions
3. **Regular updates**: Keep the tool updated to get latest security patches
4. **Review changes**: Always review fingerprint comparisons for suspicious changes
5. **Limit access**: Restrict who can create/compare fingerprints in your organization

## Known Security Considerations

- This tool collects system information including network configurations and installed applications
- By default, sensitive fields (IPs, MACs) are hashed using SHA-3
- Encryption uses AES-256-GCM with password-based key derivation
- All subprocess calls use safe command execution (no shell injection)
- File operations include path sanitization to prevent traversal attacks

## Security Update Process

1. Security issues are triaged within 48 hours
2. Patches are developed and tested privately
3. Security advisories are published
4. Fixes are released as patch versions
5. Users are notified through GitHub releases and advisories
