import { checkSPF } from './checks/spf.js';
import { checkDKIM } from './checks/dkim.js';
import { checkDMARC } from './checks/dmarc.js';
import { checkBIMI } from './checks/bimi.js';
import { checkMTASTS } from './checks/mta-sts.js';
import { checkMX } from './checks/mx.js';
import { gradeResult } from './grader.js';
import { setDnsTimeout } from './dns.js';
import type { AuditResult, AuditOptions } from './types.js';

/**
 * Run a full DNS email authentication audit on a domain.
 *
 * @param domain - The domain to audit (e.g. "trustyourwebsite.nl")
 * @param options - Audit options
 * @returns Full audit result with grade, score, and per-check details
 *
 * @example
 * ```ts
 * const result = await auditDNSAuth('trustyourwebsite.nl');
 * console.log(result.grade); // 'A'
 * console.log(result.score); // 92
 * ```
 */
export async function auditDNSAuth(
  domain: string,
  options: AuditOptions = {},
): Promise<AuditResult> {
  // Strip protocol and path if accidentally included
  const cleanDomain = domain
    .replace(/^https?:\/\//, '')
    .replace(/\/.*$/, '')
    .replace(/:\d+$/, '')
    .toLowerCase()
    .trim();

  if (!cleanDomain || !cleanDomain.includes('.')) {
    throw new Error(`Invalid domain: "${domain}"`);
  }

  if (options.timeout) {
    setDnsTimeout(options.timeout);
  }

  // Run core checks in parallel
  const [spf, dkim, dmarc, bimi, mtaSts] = await Promise.all([
    checkSPF(cleanDomain),
    checkDKIM(cleanDomain, options.dkimSelectors),
    checkDMARC(cleanDomain),
    checkBIMI(cleanDomain),
    checkMTASTS(cleanDomain),
  ]);

  // MX is optional
  const mx = options.checkMX ? await checkMX(cleanDomain) : null;

  // Calculate grade and issues
  const { grade, score, issues } = gradeResult({
    domain: cleanDomain,
    timestamp: new Date().toISOString(),
    spf,
    dkim,
    dmarc,
    bimi,
    mtaSts,
    mx,
  });

  return {
    domain: cleanDomain,
    timestamp: new Date().toISOString(),
    grade,
    score,
    spf,
    dkim,
    dmarc,
    bimi,
    mtaSts,
    mx,
    issues,
  };
}
