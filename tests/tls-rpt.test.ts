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

import { checkTLSRPT, parseTlsRptRua } from '../src/checks/tls-rpt.js';
import { __mockResolver } from 'node:dns';

const mockResolver = __mockResolver as any;

beforeEach(() => {
  vi.clearAllMocks();
});

describe('parseTlsRptRua', () => {
  it('extracts a single mailto URI', () => {
    expect(parseTlsRptRua('v=TLSRPTv1; rua=mailto:tls@example.com')).toEqual([
      'mailto:tls@example.com',
    ]);
  });

  it('extracts multiple comma-separated URIs', () => {
    expect(
      parseTlsRptRua('v=TLSRPTv1; rua=mailto:tls@example.com,https://example.com/report'),
    ).toEqual(['mailto:tls@example.com', 'https://example.com/report']);
  });

  it('returns an empty array when rua is absent', () => {
    expect(parseTlsRptRua('v=TLSRPTv1;')).toEqual([]);
  });
});

describe('checkTLSRPT', () => {
  it('detects a present, valid TLS-RPT record', async () => {
    mockResolver.resolveTxt.mockImplementation(
      (domain: string, cb: (err: Error | null, records: string[][]) => void) => {
        if (domain === '_smtp._tls.example.com') {
          cb(null, [['v=TLSRPTv1; rua=mailto:tls@example.com']]);
        } else {
          cb(new Error('ENOTFOUND'), []);
        }
      },
    );

    const result = await checkTLSRPT('example.com');
    expect(result.found).toBe(true);
    expect(result.ruaUris).toEqual(['mailto:tls@example.com']);
    expect(result.checks).toContainEqual(
      expect.objectContaining({ status: 'pass', message: expect.stringContaining('Reporting URI') }),
    );
  });

  it('warns on a malformed record with no reporting URI', async () => {
    mockResolver.resolveTxt.mockImplementation(
      (domain: string, cb: (err: Error | null, records: string[][]) => void) => {
        if (domain === '_smtp._tls.example.com') {
          cb(null, [['v=TLSRPTv1;']]);
        } else {
          cb(new Error('ENOTFOUND'), []);
        }
      },
    );

    const result = await checkTLSRPT('example.com');
    expect(result.found).toBe(true);
    expect(result.ruaUris).toEqual([]);
    expect(result.checks).toContainEqual(
      expect.objectContaining({ status: 'warn', message: expect.stringContaining('no reporting URI') }),
    );
  });

  it('warns when a rua URI uses an unsupported scheme', async () => {
    mockResolver.resolveTxt.mockImplementation(
      (domain: string, cb: (err: Error | null, records: string[][]) => void) => {
        if (domain === '_smtp._tls.example.com') {
          cb(null, [['v=TLSRPTv1; rua=ftp://example.com/report']]);
        } else {
          cb(new Error('ENOTFOUND'), []);
        }
      },
    );

    const result = await checkTLSRPT('example.com');
    expect(result.found).toBe(true);
    expect(result.ruaUris).toEqual(['ftp://example.com/report']);
    expect(result.checks).toContainEqual(
      expect.objectContaining({ status: 'warn', message: expect.stringContaining('unsupported scheme') }),
    );
  });

  it('reports absent when no TLS-RPT record exists', async () => {
    mockResolver.resolveTxt.mockImplementation(
      (_domain: string, cb: (err: Error | null, records: string[][]) => void) => {
        cb(new Error('ENOTFOUND'), []);
      },
    );

    const result = await checkTLSRPT('example.com');
    expect(result.found).toBe(false);
    expect(result.ruaUris).toEqual([]);
    expect(result.checks).toContainEqual(
      expect.objectContaining({ status: 'info', message: expect.stringContaining('No TLS-RPT') }),
    );
  });

  it('flags a DNS infrastructure error distinctly from a missing record', async () => {
    mockResolver.resolveTxt.mockImplementation(
      (_domain: string, cb: (err: Error | null, records: string[][]) => void) => {
        const err = new Error('SERVFAIL') as Error & { code?: string };
        err.code = 'ESERVFAIL';
        cb(err, []);
      },
    );

    const result = await checkTLSRPT('example.com');
    expect(result.found).toBe(false);
    expect(result.dnsError).toBe(true);
    expect(result.checks).toContainEqual(
      expect.objectContaining({ status: 'error' }),
    );
  });
});
