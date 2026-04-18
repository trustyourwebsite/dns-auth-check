# dns-auth-check

Zero-dependency Node.js tool that validates SPF, DKIM, DMARC, BIMI, and MTA-STS configuration. Recursive SPF lookup counting and automatic DKIM selector discovery. CI-friendly.

Built by [TrustYourWebsite](https://trustyourwebsite.nl) — automated website compliance scanning for EU businesses.

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

## Quick Start

```bash
# Run without installing
npx @trustyourwebsite/dns-auth-check trustyourwebsite.nl

# Install globally
npm install -g @trustyourwebsite/dns-auth-check
dns-auth-check trustyourwebsite.nl
```

## CLI Usage

```bash
# Basic check
dns-auth-check example.com

# JSON output for scripting
dns-auth-check example.com --format json

# Include MX record analysis
dns-auth-check example.com --check-mx

# Check specific DKIM selectors
dns-auth-check example.com --dkim-selectors google,s1,mandrill

# Save report to file
dns-auth-check example.com --output report.json --format json

# CI mode — exits with code 1 if critical/high issues found
dns-auth-check example.com --ci

# Custom DNS timeout
dns-auth-check example.com --timeout 10000
```

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `--format <json\|text\|table>` | Output format | `table` |
| `--dkim-selector <name>` | DKIM selector to check (repeatable) | Common selectors |
| `--dkim-selectors <s1,s2>` | Comma-separated DKIM selectors | Common selectors |
| `--check-mx` | Also check MX records | `false` |
| `--output <file>` | Save report to file | stdout |
| `--ci` | Exit code 1 if critical/high issues | `false` |
| `--timeout <ms>` | DNS query timeout | `5000` |

## Library Usage

```typescript
import { auditDNSAuth } from '@trustyourwebsite/dns-auth-check';

const result = await auditDNSAuth('example.com', {
  dkimSelectors: ['google', 's1', 'default'],
  checkMX: true,
  timeout: 5000,
});

console.log(result.grade);  // 'A+' | 'A' | 'B' | 'C' | 'D' | 'F'
console.log(result.score);  // 0-100
console.log(result.issues); // Array of { severity, message, fix? }

// Access individual check results
console.log(result.spf.lookupCount);     // Recursive DNS lookup count
console.log(result.dkim.selectors);      // Per-selector results
console.log(result.dmarc.policy);        // 'none' | 'quarantine' | 'reject'
```

### Individual Checks

You can also run checks individually:

```typescript
import {
  checkSPF,
  checkDKIM,
  checkDMARC,
  checkBIMI,
  checkMTASTS,
  checkMX,
} from '@trustyourwebsite/dns-auth-check';

const spf = await checkSPF('example.com');
const dkim = await checkDKIM('example.com', ['google', 'default']);
const dmarc = await checkDMARC('example.com');
```

## Example Output

```
DNS Email Authentication Report
================================
Domain:  trustyourwebsite.nl
Grade:   B (74/100)

SPF Record:
  ✓ Record found: v=spf1 include:_spf.google.com include:amazonses.com -all
  ✓ Hard fail (-all) configured
  ✓ DNS lookup count: 4/10
  ✓ Record length: 68 bytes

DKIM Records:
  ✓ Found 1 DKIM selector(s): google
  ✓ Record found at google._domainkey.trustyourwebsite.nl
  - Key type: RSA
  ✓ Key length: ~2048 bits

DMARC Record:
  ✓ Record found: v=DMARC1; p=none; rua=mailto:dmarc@trustyourwebsite.nl
  ⚠ Policy is "none" — DMARC is monitoring only, not blocking spoofed emails
  ✓ Reporting URI (rua) configured: mailto:dmarc@trustyourwebsite.nl
  ⚠ No subdomain policy (sp=) — subdomains inherit p=none

BIMI:
  - No BIMI record found (optional)

MTA-STS:
  - No MTA-STS record found (optional)

Issues (ordered by priority):
  1. [HIGH] DMARC policy is "none" — monitoring only, not blocking spoofed emails
     Fix: Change p=none to p=quarantine or p=reject after reviewing DMARC reports
  2. [LOW] No subdomain DMARC policy (sp=) — subdomains inherit p=none
     Fix: Add sp=reject to your DMARC record to protect subdomains
  3. [INFO] No BIMI record — consider adding one for brand visibility in inboxes

Full website compliance scan → https://trustyourwebsite.nl
```

## Checks Performed

### SPF (Sender Policy Framework)
- Record exists (root domain + email subdomains)
- Syntax validation
- DNS lookup count (recursive, against RFC 7208 limit of 10)
- `all` qualifier analysis (`-all` ✓, `~all` ⚠, `+all` ✗)
- Multiple SPF records detection (invalid per RFC)
- Record length vs 512-byte UDP limit
- Deprecated `ptr` mechanism detection
- Overly permissive IP ranges

### DKIM (DomainKeys Identified Mail)
- Auto-probes 18 common selectors: `default`, `google`, `s1`, `s2`, `k1`, `selector1`, `selector2`, `mail`, `dkim`, `mandrill`, `smtp`, `resend`, `sendgrid`, `ses`, `mesmtp`, `cm`, `protonmail`, `zoho`
- Key type detection (RSA, Ed25519)
- Key length estimation (warns < 2048 bits)
- Revoked key detection (empty `p=`)

### DMARC (Domain-based Message Authentication)
- Record exists at `_dmarc.<domain>`
- Policy analysis (`p=reject` > `quarantine` > `none`)
- Subdomain policy (`sp=`)
- Reporting URI (`rua=`) presence
- Forensic reporting (`ruf=`) detection
- Percentage (`pct=`) validation
- Alignment modes (`adkim=`, `aspf=`)

### BIMI (Brand Indicators for Message Identification)
- Record at `default._bimi.<domain>`
- Logo URL (`l=`) validation
- VMC (Verified Mark Certificate) detection

### MTA-STS (Mail Transfer Agent Strict Transport Security)
- TXT record at `_mta-sts.<domain>`
- Policy file fetch and mode validation

### MX Records (with `--check-mx`)
- Record listing with priority
- Hostname resolution verification
- Provider identification (30+ providers including Google Workspace, Microsoft 365, Zoho, Proton, SendGrid, etc.)

## Grading

| Grade | Score | Meaning |
|-------|-------|---------|
| A+ | 95-100 | Excellent — all protocols properly configured |
| A | 85-94 | Good — minor improvements possible |
| B | 70-84 | Fair — some important issues to fix |
| C | 55-69 | Poor — significant gaps in email auth |
| D | 40-54 | Bad — major security risks |
| F | 0-39 | Failing — email auth is essentially absent |

## CI/CD Integration

Use `--ci` flag to fail your pipeline when email authentication has critical issues:

```yaml
# GitHub Actions
- name: Check email DNS auth
  run: npx @trustyourwebsite/dns-auth-check yourdomain.com --ci
```

```yaml
# GitLab CI
email-auth-check:
  script:
    - npx @trustyourwebsite/dns-auth-check yourdomain.com --ci
```

## Requirements

- Node.js >= 18
- Zero runtime dependencies

## Related

- [TrustYourWebsite](https://trustyourwebsite.nl) — Full website compliance scanning for EU businesses
- [@trustyourwebsite/security-headers](https://github.com/trustyourwebsite/security-headers) — HTTP security headers grader (HSTS, CSP, X-Frame-Options)
- [@trustyourwebsite/cookie-consent-validator](https://github.com/trustyourwebsite/cookie-consent-validator) — Verify cookie consent banners actually stop tracking on "Reject All"
## License

MIT © [TrustYourWebsite](https://trustyourwebsite.nl)
