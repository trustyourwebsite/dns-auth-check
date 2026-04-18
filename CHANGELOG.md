# Changelog

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] — 2026-04-18

### Changed
- Expanded npm keywords for better discoverability (added email-authentication, email-security, auditor, cli, nodejs, typescript, zero-dependencies, gdpr, eu).
- Normalized `repository.url` in `package.json` to the `git+https://...git` form npm expects.
- Added `"type": "module"` for ESM consistency with the other @trustyourwebsite packages.
- Added `"sideEffects": false` to help bundlers tree-shake unused checks.
- Added `"publishConfig": { "access": "public" }` so scoped public publishing is explicit.
- The published tarball now includes `README.md` and `LICENSE` alongside `dist/`.

### Docs
- Fixed the Related section that previously linked to an unrelated third-party repo; it now links to the sibling [@trustyourwebsite/security-headers](https://github.com/trustyourwebsite/security-headers) and [@trustyourwebsite/cookie-consent-validator](https://github.com/trustyourwebsite/cookie-consent-validator) packages.

No runtime behaviour changes. Safe drop-in upgrade from 1.0.0.

## [1.0.0] — 2026-04-08

Initial public release.

- SPF validation with recursive DNS lookup counting (RFC 7208 limit of 10).
- DKIM auto-discovery across 18 common selectors.
- DMARC parsing with full tag analysis.
- BIMI and MTA-STS detection.
- Optional MX record listing with provider identification.
- A+ to F grading with actionable fix suggestions.
- JSON, text and table output formats.
- CI mode (`--ci`) that exits non-zero when critical/high issues are found.
