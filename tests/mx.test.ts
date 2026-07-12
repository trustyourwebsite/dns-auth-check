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

import { checkMX } from '../src/checks/mx.js';
import { __mockResolver } from 'node:dns';

const mockResolver = __mockResolver as any;

/** Make resolve4 succeed for every hostname (so records resolve). */
function stubResolves(): void {
  mockResolver.resolve4.mockImplementation(
    (_host: string, cb: (err: Error | null, addrs: string[]) => void) => {
      cb(null, ['1.2.3.4']);
    },
  );
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe('checkMX', () => {
  it('detects a missing MX record', async () => {
    mockResolver.resolveMx.mockImplementation(
      (_domain: string, cb: (err: Error | null, records: any[]) => void) => {
        cb(new Error('ENOTFOUND'), []);
      },
    );

    const result = await checkMX('example.com');
    expect(result.found).toBe(false);
    expect(result.records).toEqual([]);
    expect(result.checks).toContainEqual(
      expect.objectContaining({ status: 'fail', message: expect.stringContaining('No MX records') }),
    );
  });

  it('identifies the provider from the MX hostname', async () => {
    mockResolver.resolveMx.mockImplementation(
      (_domain: string, cb: (err: Error | null, records: any[]) => void) => {
        cb(null, [{ priority: 1, exchange: 'aspmx.l.google.com' }]);
      },
    );
    stubResolves();

    const result = await checkMX('example.com');
    expect(result.found).toBe(true);
    expect(result.records[0].provider).toBe('Google Workspace');
  });

  it('sorts multiple MX records by priority', async () => {
    mockResolver.resolveMx.mockImplementation(
      (_domain: string, cb: (err: Error | null, records: any[]) => void) => {
        cb(null, [
          { priority: 20, exchange: 'alt.mail.example.com' },
          { priority: 5, exchange: 'primary.mail.example.com' },
          { priority: 10, exchange: 'secondary.mail.example.com' },
        ]);
      },
    );
    stubResolves();

    const result = await checkMX('example.com');
    expect(result.records.map((r) => r.priority)).toEqual([5, 10, 20]);
    expect(result.records[0].exchange).toBe('primary.mail.example.com');
  });

  it('warns when an MX hostname does not resolve', async () => {
    mockResolver.resolveMx.mockImplementation(
      (_domain: string, cb: (err: Error | null, records: any[]) => void) => {
        cb(null, [{ priority: 10, exchange: 'dead.mail.example.com' }]);
      },
    );
    mockResolver.resolve4.mockImplementation(
      (_host: string, cb: (err: Error | null, addrs: string[]) => void) => {
        cb(new Error('ENOTFOUND'), []);
      },
    );

    const result = await checkMX('example.com');
    expect(result.found).toBe(true);
    expect(result.checks).toContainEqual(
      expect.objectContaining({ status: 'warn', message: expect.stringContaining('does not resolve') }),
    );
  });

  it('detects an RFC 7505 null MX ("." with priority 0)', async () => {
    mockResolver.resolveMx.mockImplementation(
      (_domain: string, cb: (err: Error | null, records: any[]) => void) => {
        cb(null, [{ priority: 0, exchange: '.' }]);
      },
    );

    const result = await checkMX('example.com');
    expect(result.found).toBe(true);
    expect(result.records).toHaveLength(1);
    expect(result.records[0].exchange).toBe('.');
    expect(result.records[0].priority).toBe(0);
    expect(result.checks).toContainEqual(
      expect.objectContaining({ status: 'info', message: expect.stringContaining('Null MX') }),
    );
    // A null MX must not trigger a hostname resolution attempt.
    expect(mockResolver.resolve4).not.toHaveBeenCalled();
  });

  it('detects a null MX surfaced as an empty exchange string', async () => {
    mockResolver.resolveMx.mockImplementation(
      (_domain: string, cb: (err: Error | null, records: any[]) => void) => {
        cb(null, [{ priority: 0, exchange: '' }]);
      },
    );

    const result = await checkMX('example.com');
    expect(result.found).toBe(true);
    expect(result.checks).toContainEqual(
      expect.objectContaining({ status: 'info', message: expect.stringContaining('Null MX') }),
    );
  });
});
