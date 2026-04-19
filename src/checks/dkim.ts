import { resolveTxt, isDnsNotFound, getDnsErrorMessage } from '../dns.js';
import type { DKIMResult, DKIMSelector, CheckResult } from '../types.js';

const DEFAULT_SELECTORS = [
  'default',
  'google',
  's1',
  's2',
  'k1',
  'selector1',
  'selector2',
  'mail',
  'dkim',
  'mandrill',
  'smtp',
  'resend',
  'sendgrid',
  'ses',
  'mesmtp',
  'cm',
  'protonmail',
  'zoho',
];

/**
 * Try to extract RSA key length from a DKIM public key.
 * The p= value is base64-encoded DER SubjectPublicKeyInfo.
 * RSA key size can be estimated from the decoded length.
 */
function estimateKeyLength(pValue: string): number | null {
  try {
    const decoded = Buffer.from(pValue, 'base64');
    const byteLength = decoded.length;
    // SubjectPublicKeyInfo overhead is ~38 bytes for RSA
    // Actual key modulus length ≈ total - overhead
    const modulusBytes = byteLength - 38;
    if (modulusBytes > 0) {
      const bits = modulusBytes * 8;
      // Round to nearest common key size
      if (bits >= 3800) return 4096;
      if (bits >= 1800) return 2048;
      if (bits >= 900) return 1024;
      if (bits >= 400) return 512;
      return bits;
    }
  } catch {
    // Can't decode — return null
  }
  return null;
}

function parseKeyType(record: string): string | null {
  const match = record.match(/k=(\w+)/);
  if (match) return match[1];
  // Default is rsa if k= is absent
  if (record.includes('p=')) return 'rsa';
  return null;
}

function parsePublicKey(record: string): string | null {
  const match = record.match(/p=([A-Za-z0-9+/=]*)/);
  return match ? match[1] : null;
}

/**
 * Check DKIM configuration for a domain.
 */
export async function checkDKIM(
  domain: string,
  customSelectors?: string[],
): Promise<DKIMResult> {
  const selectorsToCheck = customSelectors && customSelectors.length > 0
    ? customSelectors
    : DEFAULT_SELECTORS;

  const selectors: DKIMSelector[] = [];
  const overallChecks: CheckResult[] = [];

  for (const selector of selectorsToCheck) {
    const selectorResult = await checkSelector(domain, selector);
    selectors.push(selectorResult);
  }

  const foundSelectors = selectors.filter((s) => s.found);
  const errorSelectors = selectors.filter((s) => s.dnsError);
  const found = foundSelectors.length > 0;
  const hasDnsError = errorSelectors.length > 0 && !found;

  if (found) {
    overallChecks.push({
      status: 'pass',
      message: `Found ${foundSelectors.length} DKIM selector(s): ${foundSelectors.map((s) => s.selector).join(', ')}`,
    });
  } else if (hasDnsError) {
    overallChecks.push({
      status: 'error',
      message: `DNS lookup failed for DKIM selectors � cannot determine if DKIM is configured`,
    });
  } else {
    overallChecks.push({
      status: 'fail',
      message: `No DKIM records found across ${selectorsToCheck.length} selectors`,
    });
  }

  return {
    selectorsChecked: selectorsToCheck,
    selectors,
    found,
    dnsError: hasDnsError,
    checks: overallChecks,
  };
}

async function checkSelector(domain: string, selector: string): Promise<DKIMSelector> {
  const dkimDomain = `${selector}._domainkey.${domain}`;
  const checks: CheckResult[] = [];

  try {
    const records = await resolveTxt(dkimDomain);
    const flat = records.map((chunks) => (Array.isArray(chunks) ? chunks.join('') : chunks));
    const dkimRecord = flat.find(
      (r) => r.includes('v=DKIM1') || r.includes('k=rsa') || r.includes('k=ed25519') || r.includes('p='),
    );

    if (!dkimRecord) {
      return {
        selector,
        found: false,
        record: null,
        keyType: null,
        keyLength: null,
        checks: [{ status: 'info', message: `No DKIM record at ${dkimDomain}` }],
      };
    }

    checks.push({ status: 'pass', message: `Record found at ${dkimDomain}` });

    const keyType = parseKeyType(dkimRecord);
    const publicKey = parsePublicKey(dkimRecord);
    let keyLength: number | null = null;

    if (keyType) {
      checks.push({ status: 'info', message: `Key type: ${keyType.toUpperCase()}` });
    }

    if (publicKey && publicKey.length > 0) {
      keyLength = estimateKeyLength(publicKey);
      if (keyLength !== null) {
        if (keyLength < 1024) {
          checks.push({
            status: 'fail',
            message: `Key length: ${keyLength} bits — too short, minimum 1024 required`,
          });
        } else if (keyLength === 1024) {
          checks.push({
            status: 'warn',
            message: `Key length: ~${keyLength} bits — consider upgrading to 2048-bit`,
          });
        } else {
          checks.push({ status: 'pass', message: `Key length: ~${keyLength} bits` });
        }
      }
    } else if (publicKey === '') {
      checks.push({
        status: 'fail',
        message: 'Empty public key (p=) — DKIM key has been revoked',
      });
    }

    return {
      selector,
      found: true,
      record: dkimRecord,
      keyType,
      keyLength,
      checks,
    };
  } catch (err) {
    if (!isDnsNotFound(err)) {
      // DNS infrastructure error
      const errorMsg = getDnsErrorMessage(err);
      return {
        selector,
        found: false,
        dnsError: true,
        record: null,
        keyType: null,
        keyLength: null,
        checks: [{ status: 'error', message: `DNS lookup failed for ${dkimDomain}: ${errorMsg}` }],
      };
    }
    return {
      selector,
      found: false,
      record: null,
      keyType: null,
      keyLength: null,
      checks: [{ status: 'info', message: `No DKIM record at ${dkimDomain}` }],
    };
  }
}
