import { resolveTxt } from '../dns.js';
import type { MTASTSResult, CheckResult } from '../types.js';

/**
 * Fetch MTA-STS policy file over HTTPS.
 * Uses node:https with no dependencies.
 */
async function fetchPolicy(domain: string, timeout: number): Promise<string | null> {
  const https = await import('node:https');
  const url = `https://mta-sts.${domain}/.well-known/mta-sts.txt`;

  return new Promise<string | null>((resolve) => {
    const req = https.get(url, { timeout }, (res) => {
      if (res.statusCode !== 200) {
        resolve(null);
        return;
      }
      let body = '';
      res.on('data', (chunk: Buffer) => {
        body += chunk.toString();
      });
      res.on('end', () => resolve(body));
      res.on('error', () => resolve(null));
    });
    req.on('error', () => resolve(null));
    req.on('timeout', () => {
      req.destroy();
      resolve(null);
    });
  });
}

/**
 * Check MTA-STS (Mail Transfer Agent Strict Transport Security) configuration.
 */
export async function checkMTASTS(domain: string): Promise<MTASTSResult> {
  const checks: CheckResult[] = [];
  const mtaStsDomain = `_mta-sts.${domain}`;

  try {
    const records = await resolveTxt(mtaStsDomain);
    const stsRecord = records.find((r) => r.startsWith('v=STSv1'));

    if (!stsRecord) {
      checks.push({ status: 'info', message: 'No MTA-STS record found (optional)' });
      return { found: false, record: null, policyMode: null, checks };
    }

    checks.push({ status: 'pass', message: `TXT record found: ${stsRecord}` });

    // Fetch and validate the policy file
    const policy = await fetchPolicy(domain, 5000);
    let policyMode: string | null = null;

    if (policy) {
      const modeMatch = policy.match(/mode:\s*(\w+)/);
      policyMode = modeMatch ? modeMatch[1] : null;

      if (policyMode === 'enforce') {
        checks.push({ status: 'pass', message: 'Policy mode: enforce — TLS is required' });
      } else if (policyMode === 'testing') {
        checks.push({
          status: 'warn',
          message: 'Policy mode: testing — TLS failures are reported but not enforced',
        });
      } else if (policyMode === 'none') {
        checks.push({
          status: 'info',
          message: 'Policy mode: none — MTA-STS is effectively disabled',
        });
      }
    } else {
      checks.push({
        status: 'warn',
        message: `MTA-STS TXT record exists but policy file not accessible at https://mta-sts.${domain}/.well-known/mta-sts.txt`,
      });
    }

    return { found: true, record: stsRecord, policyMode, checks };
  } catch {
    checks.push({ status: 'info', message: 'No MTA-STS record found (optional)' });
    return { found: false, record: null, policyMode: null, checks };
  }
}
