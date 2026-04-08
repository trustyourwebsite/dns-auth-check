import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('node:dns', () => {
  const resolverInstance = {
    resolveTxt: vi.fn(),
    resolveMx: vi.fn(),
    resolve4: vi.fn(),
  };
  return {
    Resolver: vi.fn(() => resolverInstance),
    __mockResolver: resolverInstance,
  };
});

import { checkDMARC } from '../src/checks/dmarc.js';
import { __mockResolver } from 'node:dns';

const mockResolver = __mockResolver as any;

beforeEach(() => {
  vi.clearAllMocks();
});

describe('checkDMARC', () => {
  it('detects missing DMARC record', async () => {
    mockResolver.resolveTxt.mockImplementation(
      (_domain: string, cb: (err: Error | null, records: string[][]) => void) => {
        cb(new Error('ENOTFOUND'), []);
      },
    );

    const result = await checkDMARC('example.com');
    expect(result.found).toBe(false);
    expect(result.checks).toContainEqual(
      expect.objectContaining({ status: 'fail' }),
    );
  });

  it('parses full DMARC record', async () => {
    mockResolver.resolveTxt.mockImplementation(
      (_domain: string, cb: (err: Error | null, records: string[][]) => void) => {
        cb(null, [['v=DMARC1; p=reject; sp=quarantine; rua=mailto:dmarc@example.com; ruf=mailto:forensic@example.com; pct=100; adkim=s; aspf=r']]);
      },
    );

    const result = await checkDMARC('example.com');
    expect(result.found).toBe(true);
    expect(result.policy).toBe('reject');
    expect(result.subdomainPolicy).toBe('quarantine');
    expect(result.rua).toBe('mailto:dmarc@example.com');
    expect(result.ruf).toBe('mailto:forensic@example.com');
    expect(result.adkim).toBe('s');
    expect(result.aspf).toBe('r');
  });

  it('warns on p=none', async () => {
    mockResolver.resolveTxt.mockImplementation(
      (_domain: string, cb: (err: Error | null, records: string[][]) => void) => {
        cb(null, [['v=DMARC1; p=none; rua=mailto:dmarc@example.com']]);
      },
    );

    const result = await checkDMARC('example.com');
    expect(result.policy).toBe('none');
    expect(result.checks).toContainEqual(
      expect.objectContaining({ status: 'warn', message: expect.stringContaining('monitoring only') }),
    );
  });

  it('passes on p=reject', async () => {
    mockResolver.resolveTxt.mockImplementation(
      (_domain: string, cb: (err: Error | null, records: string[][]) => void) => {
        cb(null, [['v=DMARC1; p=reject; rua=mailto:dmarc@example.com']]);
      },
    );

    const result = await checkDMARC('example.com');
    expect(result.policy).toBe('reject');
    expect(result.checks).toContainEqual(
      expect.objectContaining({ status: 'pass', message: expect.stringContaining('reject') }),
    );
  });

  it('warns on missing rua', async () => {
    mockResolver.resolveTxt.mockImplementation(
      (_domain: string, cb: (err: Error | null, records: string[][]) => void) => {
        cb(null, [['v=DMARC1; p=reject']]);
      },
    );

    const result = await checkDMARC('example.com');
    expect(result.rua).toBeNull();
    expect(result.checks).toContainEqual(
      expect.objectContaining({ status: 'warn', message: expect.stringContaining('rua') }),
    );
  });

  it('warns on pct < 100', async () => {
    mockResolver.resolveTxt.mockImplementation(
      (_domain: string, cb: (err: Error | null, records: string[][]) => void) => {
        cb(null, [['v=DMARC1; p=quarantine; pct=50; rua=mailto:dmarc@example.com']]);
      },
    );

    const result = await checkDMARC('example.com');
    expect(result.pct).toBe(50);
    expect(result.checks).toContainEqual(
      expect.objectContaining({ status: 'warn', message: expect.stringContaining('50%') }),
    );
  });

  it('warns on missing subdomain policy', async () => {
    mockResolver.resolveTxt.mockImplementation(
      (_domain: string, cb: (err: Error | null, records: string[][]) => void) => {
        cb(null, [['v=DMARC1; p=reject; rua=mailto:dmarc@example.com']]);
      },
    );

    const result = await checkDMARC('example.com');
    expect(result.subdomainPolicy).toBeNull();
    expect(result.checks).toContainEqual(
      expect.objectContaining({ status: 'warn', message: expect.stringContaining('subdomain') }),
    );
  });
});
