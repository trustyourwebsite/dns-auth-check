import { describe, it, expect } from 'vitest';
import { formatTable } from '../src/formatters/table.js';
import { formatJSON } from '../src/formatters/json.js';
import type { AuditResult } from '../src/types.js';

function makeResult(overrides: Partial<AuditResult> = {}): AuditResult {
  return {
    domain: 'example.com',
    timestamp: '2026-07-12T00:00:00.000Z',
    grade: 'B',
    score: 74,
    spf: {
      found: true,
      record: 'v=spf1 include:_spf.google.com -all',
      domain: 'example.com',
      valid: true,
      mechanisms: [],
      lookupCount: 4,
      allQualifier: '-',
      recordLength: 40,
      multipleRecords: false,
      hasDeprecatedPtr: false,
      checks: [{ status: 'pass', message: 'Record found' }],
    },
    dkim: {
      selectorsChecked: ['google'],
      selectors: [
        { selector: 'google', found: true, record: 'v=DKIM1; k=rsa; p=abc', keyType: 'rsa', keyLength: 2048, checks: [] },
      ],
      found: true,
      checks: [{ status: 'pass', message: 'Found 1 DKIM selector(s): google' }],
    },
    dmarc: {
      found: true,
      record: 'v=DMARC1; p=reject; rua=mailto:d@example.com',
      policy: 'reject',
      subdomainPolicy: null,
      rua: 'mailto:d@example.com',
      ruf: null,
      pct: null,
      adkim: null,
      aspf: null,
      tags: [],
      checks: [{ status: 'pass', message: 'Policy: reject' }],
    },
    bimi: { found: false, record: null, logoUrl: null, vmcUrl: null, checks: [{ status: 'info', message: 'No BIMI record found (optional)' }] },
    mtaSts: { found: false, record: null, policyMode: null, checks: [{ status: 'info', message: 'No MTA-STS record found (optional)' }] },
    tlsRpt: { found: true, record: 'v=TLSRPTv1; rua=mailto:tls@example.com', ruaUris: ['mailto:tls@example.com'], checks: [{ status: 'pass', message: 'TXT record found: v=TLSRPTv1; rua=mailto:tls@example.com' }] },
    mx: null,
    issues: [
      { severity: 'low', message: 'No subdomain DMARC policy (sp=)', fix: 'Add sp=reject' },
      { severity: 'info', message: 'No BIMI record' },
    ],
    ...overrides,
  };
}

describe('formatTable', () => {
  it('renders the report header, grade and section titles', () => {
    const out = formatTable(makeResult());
    expect(out).toContain('DNS Email Authentication Report');
    expect(out).toContain('Domain:  example.com');
    expect(out).toContain('Grade:   B (74/100)');
    expect(out).toContain('SPF Record:');
    expect(out).toContain('DKIM Records:');
    expect(out).toContain('DMARC Record:');
    expect(out).toContain('BIMI:');
    expect(out).toContain('MTA-STS:');
    expect(out).toContain('TLS-RPT:');
  });

  it('renders the TLS-RPT check line', () => {
    const out = formatTable(makeResult());
    expect(out).toContain('TXT record found: v=TLSRPTv1; rua=mailto:tls@example.com');
  });

  it('renders issues with severity labels and fixes', () => {
    const out = formatTable(makeResult());
    expect(out).toContain('Issues (ordered by priority):');
    expect(out).toContain('[LOW] No subdomain DMARC policy (sp=)');
    expect(out).toContain('Fix: Add sp=reject');
  });

  it('shows MX section only when checked', () => {
    const withoutMx = formatTable(makeResult({ mx: null }));
    expect(withoutMx).not.toContain('MX Records:');

    const withMx = formatTable(
      makeResult({
        mx: { found: true, records: [{ priority: 10, exchange: 'mail.example.com', provider: null }], checks: [{ status: 'pass', message: '10\tmail.example.com' }] },
      }),
    );
    expect(withMx).toContain('MX Records:');
  });
});

describe('formatJSON', () => {
  it('produces valid, round-trippable JSON', () => {
    const result = makeResult();
    const json = formatJSON(result);
    const parsed = JSON.parse(json);
    expect(parsed.domain).toBe('example.com');
    expect(parsed.grade).toBe('B');
    expect(parsed.score).toBe(74);
  });

  it('includes the tlsRpt field in the JSON output', () => {
    const parsed = JSON.parse(formatJSON(makeResult()));
    expect(parsed.tlsRpt).toBeTruthy();
    expect(parsed.tlsRpt.found).toBe(true);
    expect(parsed.tlsRpt.ruaUris).toEqual(['mailto:tls@example.com']);
  });

  it('is pretty-printed with two-space indentation', () => {
    const json = formatJSON(makeResult());
    expect(json).toContain('\n  "domain": "example.com"');
  });
});
