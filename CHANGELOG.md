# Changelog

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] — 2026-07-12

### Added
- **TLS-RPT check** (SMTP TLS Reporting, RFC 8460): looks up the TXT record at `_smtp._tls.<domain>`, parses the `rua=` reporting URIs, and validates their scheme (`mailto:` / `https:`). Exported as `checkTLSRPT()` and included in the audit result (`tlsRpt`), grading (small positive contribution when present, no penalty when absent), and both output formatters.
- **Null MX detection** (RFC 7505): a single MX record with exchange `.` (or an empty exchange) and priority 0 is now recognised as an intentional "this domain does not accept mail" configuration rather than a broken record.
- npm package `exports` map (conditional `types`/`import`) alongside the existing `main`/`types` fields.

### Changed
- `--version` now reads the real version from `package.json` at runtime instead of a hardcoded string (previously stuck at `1.0.0`).
- **DKIM Ed25519 support:** Ed25519 keys (`k=ed25519`) are now reported as a fixed 256-bit key and are no longer misreported as a "too short / weak" key by the RSA-oriented length estimator or penalised in grading.
- **DMARC `pct=` handling** (RFC 7489): the percentage is clamped to the valid 0–100 range and a warning is emitted when the raw value is out of range or non-numeric.
- CI matrix now tests Node 18, 20 and 22, plus a non-blocking `npm audit --audit-level=high` step.
- npm publish now uses `--provenance` (with `id-token: write`) for supply-chain attestation.
- `prepublishOnly` now runs lint, tests and build.


## [1.1.1] — 2026-05-20

### Changed
- Migrated the `homepage` field and all TrustYourWebsite references to the canonical trustyourwebsite.com domain.

### Docs
- Added a GitHub Pages landing page.

## [1.1.0] — 2026-04-19

### Added
- DNS error classification: the tool now distinguishes between missing records (NOTFOUND/NODATA) and DNS infrastructure errors (SERVFAIL, TIMEOUT, CONNREFUSED). Previously, all DNS failures were silently treated as "record missing," producing false negatives.
- New `isDnsNotFound()` and `getDnsErrorMessage()` utility functions exported for programmatic use.
- Error status icon (`!`) in table output for DNS failures.

### Changed
- DNS infrastructure errors now deduct only -5 points (instead of the full -25/-20/-25 for missing records) since the record may actually exist.
- DNS errors are reported with severity `high` so CI mode (`--ci`) still catches them.


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
