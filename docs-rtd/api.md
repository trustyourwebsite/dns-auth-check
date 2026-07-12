# API Reference

## CLI options

| Option | Description | Default |
|--------|-------------|---------|
| `--format <json\|text\|table>` | Output format | `table` |
| `--dkim-selector <name>` | DKIM selector to check (repeatable) | Common selectors |
| `--dkim-selectors <s1,s2>` | Comma-separated DKIM selectors | Common selectors |
| `--check-mx` | Also check MX records | `false` |
| `--output <file>` | Save report to file | stdout |
| `--ci` | Exit code 1 if critical/high issues | `false` |
| `--timeout <ms>` | DNS query timeout | `5000` |

## Exit codes

- `0` — no critical/high issues (or `--ci` not set).
- `1` — in `--ci` mode, critical or high-severity issues were found.

## Library exports

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
console.log(result.spf.lookupCount);   // Recursive DNS lookup count
console.log(result.dkim.selectors);    // Per-selector results
console.log(result.dmarc.policy);      // 'none' | 'quarantine' | 'reject'
```

Checks can also be run individually:

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

## Checks performed

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
