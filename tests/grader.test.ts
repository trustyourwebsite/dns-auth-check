import { describe, it, expect } from 'vitest';
import { gradeResult } from '../src/grader.js';
import type { SPFResult, DKIMResult, DMARCResult, BIMIResult, MTASTSResult, MXResult } from '../src/types.js';

function makeSpf(overrides: Partial<SPFResult> = {}): SPFResult {
  return {
    found: true,
    record: 'v=spf1 -all',
    domain: 'example.com',
    valid: true,
    mechanisms: [],
    lookupCount: 2,
    allQualifier: '-',
    recordLength: 20,
    multipleRecords: false,
    hasDeprecatedPtr: false,
    checks: [],
    ...overrides,
  };
}

function makeDkim(overrides: Partial<DKIMResult> = {}): DKIMResult {
  return {
    selectorsChecked: ['default'],
    selectors: [{ selector: 'default', found: true, record: 'v=DKIM1; k=rsa; p=abc', keyType: 'rsa', keyLength: 2048, checks: [] }],
    found: true,
    checks: [],
    ...overrides,
  };
}

function makeDmarc(overrides: Partial<DMARCResult> = {}): DMARCResult {
  return {
    found: true,
    record: 'v=DMARC1; p=reject; rua=mailto:d@example.com; sp=reject',
    policy: 'reject',
    subdomainPolicy: 'reject',
    rua: 'mailto:d@example.com',
    ruf: null,
    pct: null,
    adkim: null,
    aspf: null,
    tags: [],
    checks: [],
    ...overrides,
  };
}

describe('gradeResult', () => {
  it('gives A+ for perfect config', () => {
    const result = gradeResult({
      domain: 'example.com',
      timestamp: new Date().toISOString(),
      spf: makeSpf(),
      dkim: makeDkim(),
      dmarc: makeDmarc(),
      bimi: { found: true, record: 'v=BIMI1; l=https://logo.svg', logoUrl: 'https://logo.svg', vmcUrl: null, checks: [] },
      mtaSts: { found: true, record: 'v=STSv1; id=123', policyMode: 'enforce', checks: [] },
      mx: null,
    });

    expect(result.grade).toBe('A+');
    expect(result.score).toBeGreaterThanOrEqual(95);
  });

  it('gives F for no SPF, DKIM, or DMARC', () => {
    const result = gradeResult({
      domain: 'example.com',
      timestamp: new Date().toISOString(),
      spf: makeSpf({ found: false }),
      dkim: makeDkim({ found: false }),
      dmarc: makeDmarc({ found: false }),
      bimi: null,
      mtaSts: null,
      mx: null,
    });

    expect(result.grade).toBe('F');
    expect(result.score).toBeLessThanOrEqual(35);
    expect(result.issues.length).toBeGreaterThan(0);
    expect(result.issues[0].severity).toBe('critical');
  });

  it('deducts for DMARC p=none', () => {
    const result = gradeResult({
      domain: 'example.com',
      timestamp: new Date().toISOString(),
      spf: makeSpf(),
      dkim: makeDkim(),
      dmarc: makeDmarc({ policy: 'none', subdomainPolicy: null, rua: 'mailto:d@example.com' }),
      bimi: null,
      mtaSts: null,
      mx: null,
    });

    expect(result.score).toBeLessThan(90);
    expect(result.issues).toContainEqual(
      expect.objectContaining({ message: expect.stringContaining('monitoring only') }),
    );
  });

  it('deducts for SPF +all', () => {
    const result = gradeResult({
      domain: 'example.com',
      timestamp: new Date().toISOString(),
      spf: makeSpf({ allQualifier: '+' }),
      dkim: makeDkim(),
      dmarc: makeDmarc(),
      bimi: null,
      mtaSts: null,
      mx: null,
    });

    expect(result.score).toBeLessThan(85);
    expect(result.issues).toContainEqual(
      expect.objectContaining({ severity: 'critical' }),
    );
  });

  it('deducts for SPF exceeding lookup limit', () => {
    const result = gradeResult({
      domain: 'example.com',
      timestamp: new Date().toISOString(),
      spf: makeSpf({ lookupCount: 12, valid: false }),
      dkim: makeDkim(),
      dmarc: makeDmarc(),
      bimi: null,
      mtaSts: null,
      mx: null,
    });

    expect(result.issues).toContainEqual(
      expect.objectContaining({ message: expect.stringContaining('lookup limit') }),
    );
  });

  it('deducts for missing MX when checked', () => {
    const mx: MXResult = { found: false, records: [], checks: [] };
    const result = gradeResult({
      domain: 'example.com',
      timestamp: new Date().toISOString(),
      spf: makeSpf(),
      dkim: makeDkim(),
      dmarc: makeDmarc(),
      bimi: null,
      mtaSts: null,
      mx,
    });

    expect(result.issues).toContainEqual(
      expect.objectContaining({ message: expect.stringContaining('MX') }),
    );
  });

  it('issues are sorted by severity', () => {
    const result = gradeResult({
      domain: 'example.com',
      timestamp: new Date().toISOString(),
      spf: makeSpf({ found: false }),
      dkim: makeDkim({ found: false }),
      dmarc: makeDmarc({ found: false }),
      bimi: null,
      mtaSts: null,
      mx: null,
    });

    const severities = result.issues.map((i) => i.severity);
    const order = ['critical', 'high', 'medium', 'low', 'info'];
    for (let i = 1; i < severities.length; i++) {
      expect(order.indexOf(severities[i])).toBeGreaterThanOrEqual(order.indexOf(severities[i - 1]));
    }
  });
});
