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
