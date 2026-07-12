# Examples

## CLI usage

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

## Example output

```
DNS Email Authentication Report
================================
Domain:  example.com
Grade:   B (74/100)

SPF Record:
  ✓ Record found: v=spf1 include:_spf.google.com include:amazonses.com -all
  ✓ Hard fail (-all) configured
  ✓ DNS lookup count: 4/10
  ✓ Record length: 68 bytes

DKIM Records:
  ✓ Found 1 DKIM selector(s): google
  ✓ Record found at google._domainkey.example.com
  - Key type: RSA
  ✓ Key length: ~2048 bits

DMARC Record:
  ✓ Record found: v=DMARC1; p=none; rua=mailto:dmarc@example.com
  ⚠ Policy is "none" — DMARC is monitoring only, not blocking spoofed emails
  ✓ Reporting URI (rua) configured: mailto:dmarc@example.com
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
```

## Programmatic usage

```typescript
import { auditDNSAuth } from '@trustyourwebsite/dns-auth-check';

const result = await auditDNSAuth('example.com', {
  dkimSelectors: ['google', 's1', 'default'],
  checkMX: true,
  timeout: 5000,
});

console.log(result.grade);  // 'A+' | 'A' | 'B' | 'C' | 'D' | 'F'
console.log(result.issues); // Array of { severity, message, fix? }
```

## CI/CD integration

Use `--ci` to fail your pipeline when email authentication has critical issues.

### GitHub Actions

```yaml
- name: Check email DNS auth
  run: npx @trustyourwebsite/dns-auth-check yourdomain.com --ci
```

### GitLab CI

```yaml
email-auth-check:
  script:
    - npx @trustyourwebsite/dns-auth-check yourdomain.com --ci
```
