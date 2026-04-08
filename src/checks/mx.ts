import { resolveMx, resolveA } from '../dns.js';
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
  } catch {
    checks.push({
      status: 'fail',
      message: 'No MX records found — domain cannot receive email',
    });
    return { found: false, records: [], checks };
  }
}
