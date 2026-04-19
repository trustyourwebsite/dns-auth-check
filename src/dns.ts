import { Resolver } from 'node:dns';
import type { MxRecord } from 'node:dns';

let timeout = 5000;

function getResolver(): Resolver {
  return new Resolver();
}

/**
 * Set the DNS query timeout for all subsequent lookups.
 * @param ms Timeout in milliseconds
 */
export function setDnsTimeout(ms: number): void {
  timeout = ms;
}

/**
 * Resolve TXT records for a domain. Returns an array of joined TXT strings.
 */
export async function resolveTxt(domain: string): Promise<string[]> {
  const resolver = getResolver();

  return new Promise<string[]>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`DNS timeout for TXT ${domain}`)), timeout);
    resolver.resolveTxt(domain, (err: Error | null, records: string[][]) => {
      clearTimeout(timer);
      if (err) return reject(err);
      resolve(records.map((chunks: string[]) => chunks.join('')));
    });
  });
}

/**
 * Resolve MX records for a domain.
 */
export async function resolveMx(domain: string): Promise<MxRecord[]> {
  const resolver = getResolver();

  return new Promise<MxRecord[]>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`DNS timeout for MX ${domain}`)), timeout);
    resolver.resolveMx(domain, (err: Error | null, records: MxRecord[]) => {
      clearTimeout(timer);
      if (err) return reject(err);
      resolve(records);
    });
  });
}

/**
 * Resolve A records for a domain.
 */
export async function resolveA(domain: string): Promise<string[]> {
  const resolver = getResolver();

  return new Promise<string[]>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`DNS timeout for A ${domain}`)), timeout);
    resolver.resolve4(domain, (err: Error | null, addresses: string[]) => {
      clearTimeout(timer);
      if (err) return reject(err);
      resolve(addresses);
    });
  });
}

/**
 * DNS error codes that indicate the record legitimately does not exist.
 * NOTFOUND = domain doesn't exist, NODATA = domain exists but no records of requested type.
 */
const RECORD_NOT_FOUND_CODES = new Set(['ENOTFOUND', 'NODATA']);

/**
 * Determine if a DNS error indicates a missing record (false negative safe)
 * vs a DNS infrastructure failure that could hide existing records.
 *
 * @param err The error from a dns.resolve* call
 * @returns `true` if the record is legitimately missing, `false` if it's a DNS infrastructure error
 */
export function isDnsNotFound(err: unknown): boolean {
  if (err instanceof Error) {
    // Check the .code property (standard Node.js DNS errors)
    if ('code' in err) {
      const code = (err as Error & { code?: string }).code;
      if (code && RECORD_NOT_FOUND_CODES.has(code)) {
        return true;
      }
    }
    // Also check the error message for the code string (some environments put it there)
    for (const code of RECORD_NOT_FOUND_CODES) {
      if (err.message.includes(code)) {
        return true;
      }
    }
  }
  return false;
}

/**
 * Extract a human-readable DNS error description from an error object.
 *
 * @param err The error from a dns.resolve* call
 * @returns A string describing the DNS error
 */
export function getDnsErrorMessage(err: unknown): string {
  if (err instanceof Error && 'code' in err) {
    const code = (err as Error & { code?: string }).code;
    switch (code) {
      case 'ESERVFAIL':
      case 'SERVFAIL':
        return 'DNS server failure (SERVFAIL)';
      case 'ETIMEOUT':
      case 'TIMEOUT':
        return 'DNS query timed out';
      case 'ECONNREFUSED':
      case 'CONNREFUSED':
        return 'DNS connection refused';
      case 'EREFUSED':
      case 'REFUSED':
        return 'DNS query refused';
      default:
        return `DNS error: ${code}`;
    }
  }
  if (err instanceof Error) {
    // Handle our custom timeout error
    if (err.message.startsWith('DNS timeout')) {
      return 'DNS query timed out';
    }
    return `DNS error: ${err.message}`;
  }
  return 'DNS error: unknown';
}
