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

import { checkDKIM } from '../src/checks/dkim.js';
import { __mockResolver } from 'node:dns';

const mockResolver = __mockResolver as any;

beforeEach(() => {
  vi.clearAllMocks();
});

describe('checkDKIM', () => {
  it('detects missing DKIM across all selectors', async () => {
    mockResolver.resolveTxt.mockImplementation(
      (_domain: string, cb: (err: Error | null, records: string[][]) => void) => {
        cb(new Error('ENOTFOUND'), []);
      },
    );

    const result = await checkDKIM('example.com');
    expect(result.found).toBe(false);
    expect(result.checks).toContainEqual(
      expect.objectContaining({ status: 'fail' }),
    );
  });

  it('finds DKIM on google selector', async () => {
    mockResolver.resolveTxt.mockImplementation(
      (domain: string, cb: (err: Error | null, records: string[][]) => void) => {
        if (domain === 'google._domainkey.example.com') {
          cb(null, [['v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1234567890']]);
        } else {
          cb(new Error('ENOTFOUND'), []);
        }
      },
    );

    const result = await checkDKIM('example.com');
    expect(result.found).toBe(true);
    expect(result.selectors.find((s) => s.selector === 'google')?.found).toBe(true);
  });

  it('checks custom selectors', async () => {
    mockResolver.resolveTxt.mockImplementation(
      (domain: string, cb: (err: Error | null, records: string[][]) => void) => {
        if (domain === 'mycompany._domainkey.example.com') {
          cb(null, [['v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1234567890']]);
        } else {
          cb(new Error('ENOTFOUND'), []);
        }
      },
    );

    const result = await checkDKIM('example.com', ['mycompany', 'other']);
    expect(result.found).toBe(true);
    expect(result.selectorsChecked).toEqual(['mycompany', 'other']);
  });

  it('detects revoked DKIM key (empty p=)', async () => {
    mockResolver.resolveTxt.mockImplementation(
      (domain: string, cb: (err: Error | null, records: string[][]) => void) => {
        if (domain === 'default._domainkey.example.com') {
          cb(null, [['v=DKIM1; k=rsa; p=']]);
        } else {
          cb(new Error('ENOTFOUND'), []);
        }
      },
    );

    const result = await checkDKIM('example.com');
    const defaultSel = result.selectors.find((s) => s.selector === 'default');
    expect(defaultSel?.found).toBe(true);
    expect(defaultSel?.checks).toContainEqual(
      expect.objectContaining({ status: 'fail', message: expect.stringContaining('revoked') }),
    );
  });

  it('detects ed25519 key type', async () => {
    mockResolver.resolveTxt.mockImplementation(
      (domain: string, cb: (err: Error | null, records: string[][]) => void) => {
        if (domain === 'default._domainkey.example.com') {
          cb(null, [['v=DKIM1; k=ed25519; p=AAAA']]);
        } else {
          cb(new Error('ENOTFOUND'), []);
        }
      },
    );

    const result = await checkDKIM('example.com');
    const defaultSel = result.selectors.find((s) => s.selector === 'default');
    expect(defaultSel?.keyType).toBe('ed25519');
  });
});
