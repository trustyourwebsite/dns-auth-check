import { resolveTxt } from '../dns.js';
import type { BIMIResult, CheckResult } from '../types.js';

/**
 * Check BIMI (Brand Indicators for Message Identification) configuration.
 */
export async function checkBIMI(domain: string): Promise<BIMIResult> {
  const checks: CheckResult[] = [];
  const bimiDomain = `default._bimi.${domain}`;

  try {
    const records = await resolveTxt(bimiDomain);
    const bimiRecord = records.find((r) => r.startsWith('v=BIMI1'));

    if (!bimiRecord) {
      checks.push({ status: 'info', message: 'No BIMI record found (optional)' });
      return { found: false, record: null, logoUrl: null, vmcUrl: null, checks };
    }

    checks.push({ status: 'pass', message: `Record found: ${bimiRecord}` });

    // Parse l= (logo URL)
    const logoMatch = bimiRecord.match(/l=(\S+)/);
    const logoUrl = logoMatch ? logoMatch[1].replace(/;$/, '') : null;
    if (logoUrl) {
      if (logoUrl.startsWith('https://')) {
        checks.push({ status: 'pass', message: `Logo URL: ${logoUrl}` });
      } else {
        checks.push({ status: 'warn', message: `Logo URL should use HTTPS: ${logoUrl}` });
      }
    } else {
      checks.push({ status: 'warn', message: 'No logo URL (l=) in BIMI record' });
    }

    // Parse a= (VMC authority)
    const vmcMatch = bimiRecord.match(/a=(\S+)/);
    const vmcUrl = vmcMatch ? vmcMatch[1].replace(/;$/, '') : null;
    if (vmcUrl && vmcUrl !== '') {
      checks.push({ status: 'pass', message: `VMC (Verified Mark Certificate): ${vmcUrl}` });
    } else {
      checks.push({
        status: 'info',
        message: 'No VMC (Verified Mark Certificate) — logo display depends on email provider',
      });
    }

    return { found: true, record: bimiRecord, logoUrl, vmcUrl, checks };
  } catch {
    checks.push({ status: 'info', message: 'No BIMI record found (optional)' });
    return { found: false, record: null, logoUrl: null, vmcUrl: null, checks };
  }
}
