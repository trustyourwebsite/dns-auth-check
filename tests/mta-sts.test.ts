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

// Mock the HTTPS policy fetch. checkMTASTS dynamically imports 'node:https'
// and calls https.get(url, opts, cb) — we simulate a response stream.
vi.mock('node:https', () => {
  const get = vi.fn();
  return {
    default: { get },
    get,
    __mockGet: get,
  };
});

import { checkMTASTS } from '../src/checks/mta-sts.js';
import { __mockResolver } from 'node:dns';
import { __mockGet } from 'node:https';

const mockResolver = __mockResolver as any;
const mockGet = __mockGet as any;

/**
 * Wire up https.get to invoke the callback with a fake response that emits the
 * given body, or to error when body is null.
 */
function stubPolicy(body: string | null, statusCode = 200): void {
  mockGet.mockImplementation((_url: string, _opts: unknown, cb: (res: any) => void) => {
    const req = {
      on: vi.fn(),
      destroy: vi.fn(),
    };
    if (body === null) {
      // Simulate a request error path
      req.on = vi.fn((event: string, handler: (err?: Error) => void) => {
        if (event === 'error') handler(new Error('connection refused'));
        return req;
      });
      return req;
    }
    const res = {
      statusCode,
      on: vi.fn((event: string, handler: (chunk?: Buffer) => void) => {
        if (event === 'data') handler(Buffer.from(body));
        if (event === 'end') (handler as () => void)();
        return res;
      }),
    };
    cb(res);
    return req;
  });
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe('checkMTASTS', () => {
  it('detects a missing MTA-STS record', async () => {
    mockResolver.resolveTxt.mockImplementation(
      (_domain: string, cb: (err: Error | null, records: string[][]) => void) => {
        cb(new Error('ENOTFOUND'), []);
      },
    );

    const result = await checkMTASTS('example.com');
    expect(result.found).toBe(false);
    expect(result.policyMode).toBeNull();
  });

  it('reports enforce mode', async () => {
    mockResolver.resolveTxt.mockImplementation(
      (domain: string, cb: (err: Error | null, records: string[][]) => void) => {
        if (domain === '_mta-sts.example.com') {
          cb(null, [['v=STSv1; id=20230101T000000']]);
        } else {
          cb(new Error('ENOTFOUND'), []);
        }
      },
    );
    stubPolicy('version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 604800');

    const result = await checkMTASTS('example.com');
    expect(result.found).toBe(true);
    expect(result.policyMode).toBe('enforce');
    expect(result.checks).toContainEqual(
      expect.objectContaining({ status: 'pass', message: expect.stringContaining('enforce') }),
    );
  });

  it('reports testing mode', async () => {
    mockResolver.resolveTxt.mockImplementation(
      (domain: string, cb: (err: Error | null, records: string[][]) => void) => {
        if (domain === '_mta-sts.example.com') {
          cb(null, [['v=STSv1; id=20230101T000000']]);
        } else {
          cb(new Error('ENOTFOUND'), []);
        }
      },
    );
    stubPolicy('version: STSv1\nmode: testing\nmx: mail.example.com\nmax_age: 604800');

    const result = await checkMTASTS('example.com');
    expect(result.policyMode).toBe('testing');
    expect(result.checks).toContainEqual(
      expect.objectContaining({ status: 'warn', message: expect.stringContaining('testing') }),
    );
  });

  it('reports none mode', async () => {
    mockResolver.resolveTxt.mockImplementation(
      (domain: string, cb: (err: Error | null, records: string[][]) => void) => {
        if (domain === '_mta-sts.example.com') {
          cb(null, [['v=STSv1; id=20230101T000000']]);
        } else {
          cb(new Error('ENOTFOUND'), []);
        }
      },
    );
    stubPolicy('version: STSv1\nmode: none\nmx: mail.example.com\nmax_age: 604800');

    const result = await checkMTASTS('example.com');
    expect(result.policyMode).toBe('none');
    expect(result.checks).toContainEqual(
      expect.objectContaining({ status: 'info', message: expect.stringContaining('disabled') }),
    );
  });

  it('warns when the record exists but the policy file is unreachable', async () => {
    mockResolver.resolveTxt.mockImplementation(
      (domain: string, cb: (err: Error | null, records: string[][]) => void) => {
        if (domain === '_mta-sts.example.com') {
          cb(null, [['v=STSv1; id=20230101T000000']]);
        } else {
          cb(new Error('ENOTFOUND'), []);
        }
      },
    );
    stubPolicy(null);

    const result = await checkMTASTS('example.com');
    expect(result.found).toBe(true);
    expect(result.policyMode).toBeNull();
    expect(result.checks).toContainEqual(
      expect.objectContaining({ status: 'warn', message: expect.stringContaining('not accessible') }),
    );
  });
});
