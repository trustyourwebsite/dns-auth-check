import { resolveTxt, isDnsNotFound, getDnsErrorMessage } from '../dns.js';
import type { TLSRPTResult, CheckResult } from '../types.js';

/**
 * Parse the reporting URIs from a TLS-RPT `rua=` tag.
 * Per RFC 8460 §3, rua is a comma-separated list of mailto: or https: URIs.
 *
 * @param record The raw TLS-RPT TXT record
 * @returns Array of trimmed reporting URIs (may be empty)
 */
export function parseTlsRptRua(record: string): string[] {
  const match = record.match(/rua=([^;]+)/i);
  if (!match) return [];
  return match[1]
    .split(',')
    .map((uri) => uri.trim())
    .filter(Boolean);
}

/**
 * Check TLS-RPT (SMTP TLS Reporting, RFC 8460) configuration for a domain.
 * Looks up the TXT record at `_smtp._tls.<domain>` and parses reporting URIs.
 */
export async function checkTLSRPT(domain: string): Promise<TLSRPTResult> {
  const checks: CheckResult[] = [];
  const tlsRptDomain = `_smtp._tls.${domain}`;

  try {
    const records = await resolveTxt(tlsRptDomain);
    const tlsRptRecord = records.find((r) => r.startsWith('v=TLSRPTv1'));

    if (!tlsRptRecord) {
      checks.push({ status: 'info', message: 'No TLS-RPT record found (optional)' });
      return { found: false, record: null, ruaUris: [], checks };
    }

    checks.push({ status: 'pass', message: `TXT record found: ${tlsRptRecord}` });

    const ruaUris = parseTlsRptRua(tlsRptRecord);
    if (ruaUris.length > 0) {
      const validScheme = ruaUris.filter((u) => /^(mailto:|https:)/i.test(u));
      if (validScheme.length > 0) {
        checks.push({
          status: 'pass',
          message: `Reporting URI (rua) configured: ${ruaUris.join(', ')}`,
        });
      }
      if (validScheme.length < ruaUris.length) {
        checks.push({
          status: 'warn',
          message: 'Some rua= URIs use an unsupported scheme — only mailto: and https: are valid (RFC 8460)',
        });
      }
    } else {
      checks.push({
        status: 'warn',
        message: 'TLS-RPT record has no reporting URI (rua=) — no TLS failure reports will be sent',
      });
    }

    return { found: true, record: tlsRptRecord, ruaUris, checks };
  } catch (err) {
    if (!isDnsNotFound(err)) {
      const errorMsg = getDnsErrorMessage(err);
      checks.push({ status: 'error', message: `DNS lookup failed for TLS-RPT: ${errorMsg}` });
      return { found: false, dnsError: true, record: null, ruaUris: [], checks };
    }
    checks.push({ status: 'info', message: 'No TLS-RPT record found (optional)' });
    return { found: false, record: null, ruaUris: [], checks };
  }
}
