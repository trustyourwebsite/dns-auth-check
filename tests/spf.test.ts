import { describe, it, expect, vi, beforeEach } from 'vitest';

// Mock dns module before importing
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

import { checkSPF } from '../src/checks/spf.js';
import { Resolver, __mockResolver } from 'node:dns';

const mockResolver = __mockResolver as any;

beforeEach(() => {
  vi.clearAllMocks();
});

describe('checkSPF', () => {
  it('detects missing SPF record', async () => {
    mockResolver.resolveTxt.mockImplementation(
      (_domain: string, cb: (err: Error | null, records: string[][]) => void) => {
        cb(new Error('ENOTFOUND'), []);
      },
    );

    const result = await checkSPF('example.com');
    expect(result.found).toBe(false);
    expect(result.checks).toContainEqual(
      expect.objectContaining({ status: 'fail', message: 'No SPF record found' }),
    );
  });

  it('detects valid SPF with hard fail', async () => {
    mockResolver.resolveTxt.mockImplementation(
      (domain: string, cb: (err: Error | null, records: string[][]) => void) => {
        if (domain === 'example.com') {
          cb(null, [['v=spf1 include:_spf.google.com -all']]);
        } else {
          cb(new Error('ENOTFOUND'), []);
        }
      },
    );

    const result = await checkSPF('example.com');
    expect(result.found).toBe(true);
    expect(result.allQualifier).toBe('-');
    expect(result.checks).toContainEqual(
      expect.objectContaining({ status: 'pass', message: 'Hard fail (-all) configured' }),
    );
  });

  it('warns on soft fail (~all)', async () => {
    mockResolver.resolveTxt.mockImplementation(
      (domain: string, cb: (err: Error | null, records: string[][]) => void) => {
        if (domain === 'example.com') {
          cb(null, [['v=spf1 include:_spf.google.com ~all']]);
        } else {
          cb(new Error('ENOTFOUND'), []);
        }
      },
    );

    const result = await checkSPF('example.com');
    expect(result.allQualifier).toBe('~');
    expect(result.checks).toContainEqual(
      expect.objectContaining({ status: 'warn' }),
    );
  });

  it('fails on +all', async () => {
    mockResolver.resolveTxt.mockImplementation(
      (domain: string, cb: (err: Error | null, records: string[][]) => void) => {
        if (domain === 'example.com') {
          cb(null, [['v=spf1 +all']]);
        } else {
          cb(new Error('ENOTFOUND'), []);
        }
      },
    );

    const result = await checkSPF('example.com');
    expect(result.allQualifier).toBe('+');
    expect(result.checks).toContainEqual(
      expect.objectContaining({ status: 'fail' }),
    );
  });

  it('detects multiple SPF records', async () => {
    mockResolver.resolveTxt.mockImplementation(
      (domain: string, cb: (err: Error | null, records: string[][]) => void) => {
        if (domain === 'example.com') {
          cb(null, [['v=spf1 -all'], ['v=spf1 include:other.com -all']]);
        } else {
          cb(new Error('ENOTFOUND'), []);
        }
      },
    );

    const result = await checkSPF('example.com');
    expect(result.multipleRecords).toBe(true);
    expect(result.valid).toBe(false);
  });

  it('counts recursive DNS lookups', async () => {
    // Root SPF has 2 includes, each include has 1 more include = 4 lookups total
    mockResolver.resolveTxt.mockImplementation(
      (domain: string, cb: (err: Error | null, records: string[][]) => void) => {
        if (domain === 'example.com') {
          cb(null, [['v=spf1 include:a.example.com include:b.example.com -all']]);
        } else if (domain === 'a.example.com') {
          cb(null, [['v=spf1 include:c.example.com -all']]);
        } else if (domain === 'b.example.com') {
          cb(null, [['v=spf1 ip4:1.2.3.4 -all']]);
        } else if (domain === 'c.example.com') {
          cb(null, [['v=spf1 ip4:5.6.7.8 -all']]);
        } else {
          cb(new Error('ENOTFOUND'), []);
        }
      },
    );

    const result = await checkSPF('example.com');
    expect(result.found).toBe(true);
    // 2 includes at root + 1 include in a.example.com = 3 lookups
    expect(result.lookupCount).toBe(3);
  });

  it('detects deprecated ptr mechanism', async () => {
    mockResolver.resolveTxt.mockImplementation(
      (domain: string, cb: (err: Error | null, records: string[][]) => void) => {
        if (domain === 'example.com') {
          cb(null, [['v=spf1 ptr -all']]);
        } else {
          cb(new Error('ENOTFOUND'), []);
        }
      },
    );

    const result = await checkSPF('example.com');
    expect(result.hasDeprecatedPtr).toBe(true);
  });

  it('parses mechanisms correctly', async () => {
    mockResolver.resolveTxt.mockImplementation(
      (domain: string, cb: (err: Error | null, records: string[][]) => void) => {
        if (domain === 'example.com') {
          cb(null, [['v=spf1 ip4:192.168.1.0/24 include:_spf.google.com mx a -all']]);
        } else {
          cb(new Error('ENOTFOUND'), []);
        }
      },
    );

    const result = await checkSPF('example.com');
    expect(result.mechanisms).toHaveLength(5); // ip4, include, mx, a, -all
    expect(result.mechanisms[0]).toEqual({
      qualifier: '+',
      type: 'ip4',
      value: '192.168.1.0/24',
    });
  });
});
