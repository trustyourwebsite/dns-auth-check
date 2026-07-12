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

import { checkBIMI } from '../src/checks/bimi.js';
import { __mockResolver } from 'node:dns';

const mockResolver = __mockResolver as any;

beforeEach(() => {
  vi.clearAllMocks();
});

describe('checkBIMI', () => {
  it('detects a missing BIMI record', async () => {
    mockResolver.resolveTxt.mockImplementation(
      (_domain: string, cb: (err: Error | null, records: string[][]) => void) => {
        cb(new Error('ENOTFOUND'), []);
      },
    );

    const result = await checkBIMI('example.com');
    expect(result.found).toBe(false);
    expect(result.logoUrl).toBeNull();
    expect(result.vmcUrl).toBeNull();
    expect(result.checks).toContainEqual(
      expect.objectContaining({ status: 'info' }),
    );
  });

  it('parses a BIMI record with a logo URL', async () => {
    mockResolver.resolveTxt.mockImplementation(
      (domain: string, cb: (err: Error | null, records: string[][]) => void) => {
        if (domain === 'default._bimi.example.com') {
          cb(null, [['v=BIMI1; l=https://example.com/logo.svg']]);
        } else {
          cb(new Error('ENOTFOUND'), []);
        }
      },
    );

    const result = await checkBIMI('example.com');
    expect(result.found).toBe(true);
    expect(result.logoUrl).toBe('https://example.com/logo.svg');
    expect(result.checks).toContainEqual(
      expect.objectContaining({ status: 'pass', message: expect.stringContaining('Logo URL') }),
    );
  });

  it('detects a VMC when present', async () => {
    mockResolver.resolveTxt.mockImplementation(
      (domain: string, cb: (err: Error | null, records: string[][]) => void) => {
        if (domain === 'default._bimi.example.com') {
          cb(null, [['v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem']]);
        } else {
          cb(new Error('ENOTFOUND'), []);
        }
      },
    );

    const result = await checkBIMI('example.com');
    expect(result.found).toBe(true);
    expect(result.vmcUrl).toBe('https://example.com/vmc.pem');
    expect(result.checks).toContainEqual(
      expect.objectContaining({ status: 'pass', message: expect.stringContaining('VMC') }),
    );
  });

  it('notes when a VMC is absent', async () => {
    mockResolver.resolveTxt.mockImplementation(
      (domain: string, cb: (err: Error | null, records: string[][]) => void) => {
        if (domain === 'default._bimi.example.com') {
          cb(null, [['v=BIMI1; l=https://example.com/logo.svg']]);
        } else {
          cb(new Error('ENOTFOUND'), []);
        }
      },
    );

    const result = await checkBIMI('example.com');
    expect(result.vmcUrl).toBeNull();
    expect(result.checks).toContainEqual(
      expect.objectContaining({ status: 'info', message: expect.stringContaining('No VMC') }),
    );
  });

  it('warns when the logo URL is not HTTPS', async () => {
    mockResolver.resolveTxt.mockImplementation(
      (domain: string, cb: (err: Error | null, records: string[][]) => void) => {
        if (domain === 'default._bimi.example.com') {
          cb(null, [['v=BIMI1; l=http://example.com/logo.svg']]);
        } else {
          cb(new Error('ENOTFOUND'), []);
        }
      },
    );

    const result = await checkBIMI('example.com');
    expect(result.logoUrl).toBe('http://example.com/logo.svg');
    expect(result.checks).toContainEqual(
      expect.objectContaining({ status: 'warn', message: expect.stringContaining('HTTPS') }),
    );
  });
});
