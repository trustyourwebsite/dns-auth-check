# @trustyourwebsite/dns-auth-check

Built and maintained by [TrustYourWebsite](https://trustyourwebsite.com), a compliance scanner for EU websites.

US business? The same scanner runs at [getuptocode.com](https://getuptocode.com) (Get Up to Code), focused on ADA accessibility and privacy lawsuit risk.

Zero-dependency Node.js tool that validates SPF, DKIM, DMARC, BIMI and MTA-STS configuration, with recursive SPF lookup counting and automatic DKIM selector discovery. CI-friendly.

## Features

- **SPF validation** with recursive DNS lookup counting (RFC 7208 limit of 10)
- **DKIM auto-discovery** across 18 common selectors (Google, Microsoft 365, SendGrid, Resend, etc.)
- **DMARC parsing** with full tag analysis (policy, subdomain policy, reporting URIs, alignment)
- **BIMI detection** — logo URL and VMC (Verified Mark Certificate) validation
- **MTA-STS checking** — TXT record and policy file validation
- **MX record listing** with provider identification (30+ providers)
- **Grading system** from A+ to F with actionable fix suggestions
- **Zero runtime dependencies** — uses only `node:dns` and `node:https`
- **CI-friendly** — exit code 1 when critical issues are found

## Installation

```bash
# Run without installing
npx @trustyourwebsite/dns-auth-check example.com

# Install globally
npm install -g @trustyourwebsite/dns-auth-check
dns-auth-check example.com
```

## Grading

| Grade | Score | Meaning |
|-------|-------|---------|
| A+ | 95-100 | Excellent — all protocols properly configured |
| A | 85-94 | Good — minor improvements possible |
| B | 70-84 | Fair — some important issues to fix |
| C | 55-69 | Poor — significant gaps in email auth |
| D | 40-54 | Bad — major security risks |
| F | 0-39 | Failing — email auth is essentially absent |

## Requirements

- Node.js >= 18
- Zero runtime dependencies

See the [API Reference](api.md) for options, exports and the checks performed, or [Examples](examples.md) for CLI and CI/CD recipes.
