import type { MxRecord } from 'node:dns';
import { resolveMx, resolveA, isDnsNotFound, getDnsErrorMessage } from '../dns.js';
import type { MXResult, MXRecord, CheckResult } from '../types.js';

/** Map of MX hostname patterns to provider names. */
const PROVIDER_PATTERNS: [RegExp, string][] = [
  [/\.google\.com$/i, 'Google Workspace'],
  [/\.googlemail\.com$/i, 'Google Workspace'],
  [/outlook\.com$/i, 'Microsoft 365'],
  [/\.protection\.outlook\.com$/i, 'Microsoft 365'],
  [/\.pphosted\.com$/i, 'Proofpoint'],
  [/\.zoho\.(com|eu|in)$/i, 'Zoho Mail'],
  [/\.protonmail\.ch$/i, 'Proton Mail'],
  [/\.messagingengine\.com$/i, 'Fastmail'],
  [/\.mimecast\.(com|co\.za)$/i, 'Mimecast'],
  [/\.barracudanetworks\.com$/i, 'Barracuda'],
  [/\.fireeyecloud\.com$/i, 'Trellix (FireEye)'],
  [/\.mailgun\.org$/i, 'Mailgun'],
  [/\.sendgrid\.net$/i, 'SendGrid'],
  [/\.amazonaws\.com$/i, 'Amazon SES'],
  [/\.postmarkapp\.com$/i, 'Postmark'],
  [/\.mandrillapp\.com$/i, 'Mandrill (Mailchimp)'],
  [/\.hover\.com$/i, 'Hover'],
  [/\.icloud\.com$/i, 'iCloud Mail'],
  [/\.yahoodns\.net$/i, 'Yahoo Mail'],
  [/\.registrar-servers\.com$/i, 'Namecheap Email'],
  [/\.titan\.email$/i, 'Titan Email'],
  [/\.secureserver\.net$/i, 'GoDaddy Email'],
  [/\.pair\.com$/i, 'pair Networks'],
  [/\.transip\.email$/i, 'TransIP'],
  [/\.antagonist\.nl$/i, 'Antagonist'],
];

function identifyProvider(exchange: string): string | null {
  for (const [pattern, name] of PROVIDER_PATTERNS) {
    if (pattern.test(exchange)) return name;
  }
  return null;
}

/**
 * Detect an RFC 7505 "null MX" configuration: a single MX record whose exchange
 * is the root domain (".", sometimes surfaced as an empty string by resolvers)
 * with preference 0, signalling the domain does not accept mail.
 *
 * @param records MX records already sorted by priority
 * @returns `true` if the records represent a null MX
 */
function isNullMx(records: MxRecord[]): boolean {
  if (records.length !== 1) return false;
  const [only] = records;
  const exchange = only.exchange.trim();
  return only.priority === 0 && (exchange === '.' || exchange === '');
}

/**
 * Check MX records for a domain.
 */
export async function checkMX(domain: string): Promise<MXResult> {
  const checks: CheckResult[] = [];

  try {
    const rawRecords = await resolveMx(domain);

    if (!rawRecords || rawRecords.length === 0) {
      checks.push({
        status: 'fail',
        message: 'No MX records found — domain cannot receive email',
      });
      return { found: false, records: [], checks };
    }

    const sorted = rawRecords.sort((a, b) => a.priority - b.priority);

    // RFC 7505 "null MX": a single MX with an empty exchange (".") and priority 0
    // explicitly signals that the domain does not accept mail. Treat it as an
    // intentional configuration rather than a broken record.
    if (isNullMx(sorted)) {
      const nullRecord: MXRecord = { priority: 0, exchange: '.', provider: null };
      checks.push({
        status: 'info',
        message: 'Null MX (RFC 7505) — this domain explicitly does not accept email',
      });
      return { found: true, records: [nullRecord], checks };
    }

    const records: MXRecord[] = [];

    for (const mx of sorted) {
      const provider = identifyProvider(mx.exchange);
      const record: MXRecord = {
        priority: mx.priority,
        exchange: mx.exchange,
        provider,
      };
      records.push(record);

      // Check that MX hostname resolves
      try {
        await resolveA(mx.exchange);
        const providerInfo = provider ? ` (${provider})` : '';
        checks.push({
          status: 'pass',
          message: `${mx.priority}\t${mx.exchange}${providerInfo}`,
        });
      } catch {
        checks.push({
          status: 'warn',
          message: `${mx.priority}\t${mx.exchange} — hostname does not resolve`,
        });
      }
    }

    return { found: true, records, checks };
  } catch (err) {
    if (!isDnsNotFound(err)) {
      const errorMsg = getDnsErrorMessage(err);
      checks.push({
        status: 'error',
        message: `DNS lookup failed for MX records: ${errorMsg}`,
      });
      return { found: false, dnsError: true, records: [], checks };
    }
    checks.push({
      status: 'fail',
      message: 'No MX records found — domain cannot receive email',
    });
    return { found: false, records: [], checks };
  }
}
