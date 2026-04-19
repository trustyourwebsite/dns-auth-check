import { resolveTxt, isDnsNotFound, getDnsErrorMessage } from '../dns.js';
import type { SPFResult, SPFMechanism, CheckResult } from '../types.js';

const SPF_SUBDOMAINS = ['send', 'mail', 'em', 'email'];

/**
 * Count DNS lookups recursively for SPF record.
 * RFC 7208 §4.6.4: mechanisms that cause DNS lookups count toward the limit of 10.
 * include, a, mx, ptr, exists all count. redirect counts too.
 */
async function countLookups(
  record: string,
  visited: Set<string>,
  depth: number,
): Promise<number> {
  if (depth > 12) return 0; // Prevent infinite recursion

  let count = 0;
  const parts = record.split(/\s+/);

  for (const part of parts) {
    const clean = part.replace(/^[+\-~?]/, '');

    if (clean.startsWith('include:')) {
      const target = clean.slice(8);
      if (visited.has(target)) continue;
      visited.add(target);
      count += 1;
      try {
        const records = await resolveTxt(target);
        const spfRecord = records.find((r) => r.startsWith('v=spf1'));
        if (spfRecord) {
          count += await countLookups(spfRecord, visited, depth + 1);
        }
      } catch {
        // Target unresolvable — still counts as a lookup
      }
    } else if (clean.startsWith('redirect=')) {
      const target = clean.slice(9);
      if (visited.has(target)) continue;
      visited.add(target);
      count += 1;
      try {
        const records = await resolveTxt(target);
        const spfRecord = records.find((r) => r.startsWith('v=spf1'));
        if (spfRecord) {
          count += await countLookups(spfRecord, visited, depth + 1);
        }
      } catch {
        // Target unresolvable
      }
    } else if (clean.startsWith('a:') || clean === 'a') {
      count += 1;
    } else if (clean.startsWith('mx:') || clean === 'mx') {
      count += 1;
    } else if (clean.startsWith('ptr:') || clean === 'ptr') {
      count += 1;
    } else if (clean.startsWith('exists:')) {
      count += 1;
    }
  }

  return count;
}

function parseMechanisms(record: string): SPFMechanism[] {
  const mechanisms: SPFMechanism[] = [];
  const parts = record.split(/\s+/).slice(1); // Skip v=spf1

  for (const part of parts) {
    let qualifier: SPFMechanism['qualifier'] = '+';
    let rest = part;

    if (/^[+\-~?]/.test(rest)) {
      qualifier = rest[0] as SPFMechanism['qualifier'];
      rest = rest.slice(1);
    }

    const colonIdx = rest.indexOf(':');
    const eqIdx = rest.indexOf('=');
    let type: string;
    let value: string;

    if (colonIdx !== -1) {
      type = rest.slice(0, colonIdx);
      value = rest.slice(colonIdx + 1);
    } else if (eqIdx !== -1) {
      type = rest.slice(0, eqIdx);
      value = rest.slice(eqIdx + 1);
    } else {
      type = rest;
      value = '';
    }

    mechanisms.push({ qualifier, type, value });
  }

  return mechanisms;
}

function getAllQualifier(record: string): SPFMechanism['qualifier'] | null {
  const match = record.match(/\s([+\-~?]?)all\b/);
  if (!match) return null;
  return (match[1] || '+') as SPFMechanism['qualifier'];
}

/**
 * Check SPF configuration for a domain.
 */
export async function checkSPF(domain: string): Promise<SPFResult> {
  const checks: CheckResult[] = [];

  // Try root domain first, then common email subdomains
  const domainsToCheck = [domain, ...SPF_SUBDOMAINS.map((sub) => `${sub}.${domain}`)];
  let spfRecord: string | null = null;
  let spfDomain: string | null = null;
  let multipleRecords = false;

  for (const d of domainsToCheck) {
    try {
      const records = await resolveTxt(d);
      const spfRecords = records.filter((r) => r.startsWith('v=spf1'));

      if (spfRecords.length > 1) {
        multipleRecords = true;
        spfRecord = spfRecords[0];
        spfDomain = d;
        break;
      }

      if (spfRecords.length === 1) {
        spfRecord = spfRecords[0];
        spfDomain = d;
        break;
      }
    } catch (err) {
      if (!isDnsNotFound(err)) {
        // DNS infrastructure error � don't treat as "not found"
        const errorMsg = getDnsErrorMessage(err);
        checks.push({ status: 'error', message: `DNS lookup failed for ${d}: ${errorMsg}` });
        return {
          found: false,
          dnsError: true,
          record: null,
          domain: null,
          valid: false,
          mechanisms: [],
          lookupCount: 0,
          allQualifier: null,
          recordLength: 0,
          multipleRecords: false,
          hasDeprecatedPtr: false,
          checks,
        };
      }
      // NOTFOUND/NODATA � no records for this domain, continue checking
    }
  }

  if (!spfRecord) {
    checks.push({ status: 'fail', message: 'No SPF record found' });
    return {
      found: false,
      record: null,
      domain: null,
      valid: false,
      mechanisms: [],
      lookupCount: 0,
      allQualifier: null,
      recordLength: 0,
      multipleRecords: false,
      hasDeprecatedPtr: false,
      checks,
    };
  }

  checks.push({
    status: 'pass',
    message: `Record found: ${spfRecord}`,
  });

  // Multiple SPF records (invalid per RFC 7208)
  if (multipleRecords) {
    checks.push({
      status: 'fail',
      message: 'Multiple SPF records found — invalid per RFC 7208 (must be exactly one)',
    });
  }

  const mechanisms = parseMechanisms(spfRecord);
  const allQualifier = getAllQualifier(spfRecord);

  // Check all qualifier
  if (allQualifier === '-') {
    checks.push({ status: 'pass', message: 'Hard fail (-all) configured' });
  } else if (allQualifier === '~') {
    checks.push({
      status: 'warn',
      message: 'Soft fail (~all) configured — consider upgrading to -all (hard fail)',
    });
  } else if (allQualifier === '+') {
    checks.push({
      status: 'fail',
      message: 'SPF allows all senders (+all) — this effectively disables SPF protection',
    });
  } else if (allQualifier === '?') {
    checks.push({
      status: 'warn',
      message: 'Neutral (?all) configured — SPF result is neither pass nor fail',
    });
  } else if (!allQualifier) {
    checks.push({ status: 'warn', message: 'No "all" mechanism found in SPF record' });
  }

  // Recursive DNS lookup count
  const visited = new Set<string>();
  const lookupCount = await countLookups(spfRecord, visited, 0);

  if (lookupCount > 10) {
    checks.push({
      status: 'fail',
      message: `DNS lookup count: ${lookupCount}/10 — exceeds RFC 7208 limit of 10`,
    });
  } else if (lookupCount >= 8) {
    checks.push({
      status: 'warn',
      message: `DNS lookup count: ${lookupCount}/10 — approaching the limit`,
    });
  } else {
    checks.push({ status: 'pass', message: `DNS lookup count: ${lookupCount}/10` });
  }

  // Record length check
  const recordLength = Buffer.byteLength(spfRecord, 'utf-8');
  if (recordLength > 512) {
    checks.push({
      status: 'fail',
      message: `Record length: ${recordLength} bytes — exceeds 512-byte DNS UDP limit`,
    });
  } else if (recordLength > 400) {
    checks.push({
      status: 'warn',
      message: `Record length: ${recordLength} bytes — approaching DNS UDP limits`,
    });
  } else {
    checks.push({ status: 'pass', message: `Record length: ${recordLength} bytes` });
  }

  // Deprecated ptr mechanism
  const hasDeprecatedPtr = mechanisms.some((m) => m.type === 'ptr');
  if (hasDeprecatedPtr) {
    checks.push({
      status: 'warn',
      message: 'Uses deprecated "ptr" mechanism — remove it per RFC 7208 §5.5',
    });
  }

  // Overly permissive IP ranges
  const broadIpv4 = mechanisms.some(
    (m) =>
      m.type === 'ip4' &&
      m.value.includes('/') &&
      parseInt(m.value.split('/')[1], 10) < 16,
  );
  if (broadIpv4) {
    checks.push({
      status: 'warn',
      message: 'Very broad IP range in SPF — may be overly permissive',
    });
  }

  return {
    found: true,
    record: spfRecord,
    domain: spfDomain,
    valid: !multipleRecords && lookupCount <= 10,
    mechanisms,
    lookupCount,
    allQualifier,
    recordLength,
    multipleRecords,
    hasDeprecatedPtr,
    checks,
  };
}
