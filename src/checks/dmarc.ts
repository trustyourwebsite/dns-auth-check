import { resolveTxt, isDnsNotFound, getDnsErrorMessage } from '../dns.js';
import type { DMARCResult, DMARCTag, CheckResult } from '../types.js';

function parseTags(record: string): DMARCTag[] {
  return record
    .split(';')
    .map((s) => s.trim())
    .filter(Boolean)
    .map((pair) => {
      const eqIdx = pair.indexOf('=');
      if (eqIdx === -1) return { tag: pair.trim(), value: '' };
      return {
        tag: pair.slice(0, eqIdx).trim(),
        value: pair.slice(eqIdx + 1).trim(),
      };
    });
}

function getTagValue(tags: DMARCTag[], name: string): string | null {
  const tag = tags.find((t) => t.tag.toLowerCase() === name.toLowerCase());
  return tag ? tag.value : null;
}

/**
 * Check DMARC configuration for a domain.
 */
export async function checkDMARC(domain: string): Promise<DMARCResult> {
  const checks: CheckResult[] = [];
  const dmarcDomain = `_dmarc.${domain}`;

  try {
    const records = await resolveTxt(dmarcDomain);
    const dmarcRecord = records.find((r) => r.startsWith('v=DMARC1'));

    if (!dmarcRecord) {
      checks.push({ status: 'fail', message: `No DMARC record found at ${dmarcDomain}` });
      return {
        found: false,
        record: null,
        policy: null,
        subdomainPolicy: null,
        rua: null,
        ruf: null,
        pct: null,
        adkim: null,
        aspf: null,
        tags: [],
        checks,
      };
    }

    const tags = parseTags(dmarcRecord);
    checks.push({ status: 'pass', message: `Record found: ${dmarcRecord}` });

    // Policy (p=)
    const policy = getTagValue(tags, 'p');
    if (!policy) {
      checks.push({ status: 'fail', message: 'No policy (p=) tag — record is invalid' });
    } else if (policy === 'reject') {
      checks.push({ status: 'pass', message: 'Policy: reject — strongest protection' });
    } else if (policy === 'quarantine') {
      checks.push({
        status: 'pass',
        message: 'Policy: quarantine — suspicious emails flagged',
      });
    } else if (policy === 'none') {
      checks.push({
        status: 'warn',
        message: 'Policy is "none" — DMARC is monitoring only, not blocking spoofed emails',
      });
    }

    // Subdomain policy (sp=)
    const subdomainPolicy = getTagValue(tags, 'sp');
    if (subdomainPolicy) {
      checks.push({ status: 'info', message: `Subdomain policy: ${subdomainPolicy}` });
    } else {
      checks.push({
        status: 'warn',
        message: `No subdomain policy (sp=) — subdomains inherit p=${policy || 'none'}`,
      });
    }

    // Reporting URI (rua=)
    const rua = getTagValue(tags, 'rua');
    if (rua) {
      checks.push({ status: 'pass', message: `Reporting URI (rua) configured: ${rua}` });
    } else {
      checks.push({
        status: 'warn',
        message: 'No reporting URI (rua=) — you won\'t receive authentication failure reports',
      });
    }

    // Forensic reporting (ruf=)
    const ruf = getTagValue(tags, 'ruf');
    if (ruf) {
      checks.push({ status: 'info', message: `Forensic reporting (ruf) configured: ${ruf}` });
    }

    // Percentage (pct=)
    const pctRaw = getTagValue(tags, 'pct');
    const pct = pctRaw ? parseInt(pctRaw, 10) : null;
    if (pct !== null && pct < 100) {
      checks.push({
        status: 'warn',
        message: `Only ${pct}% of emails are subject to DMARC policy — consider increasing to 100%`,
      });
    }

    // Alignment modes
    const adkim = getTagValue(tags, 'adkim');
    const aspf = getTagValue(tags, 'aspf');
    if (adkim) {
      checks.push({
        status: 'info',
        message: `DKIM alignment: ${adkim === 's' ? 'strict' : 'relaxed'}`,
      });
    }
    if (aspf) {
      checks.push({
        status: 'info',
        message: `SPF alignment: ${aspf === 's' ? 'strict' : 'relaxed'}`,
      });
    }

    return {
      found: true,
      record: dmarcRecord,
      policy,
      subdomainPolicy,
      rua,
      ruf,
      pct,
      adkim,
      aspf,
      tags,
      checks,
    };
  } catch (err) {
    if (!isDnsNotFound(err)) {
      // DNS infrastructure error
      const errorMsg = getDnsErrorMessage(err);
      checks.push({ status: 'error', message: `DNS lookup failed for ${dmarcDomain}: ${errorMsg}` });
      return {
        found: false,
        dnsError: true,
        record: null,
        policy: null,
        subdomainPolicy: null,
        rua: null,
        ruf: null,
        pct: null,
        adkim: null,
        aspf: null,
        tags: [],
        checks,
      };
    }
    checks.push({ status: 'fail', message: `No DMARC record found at ${dmarcDomain}` });
    return {
      found: false,
      record: null,
      policy: null,
      subdomainPolicy: null,
      rua: null,
      ruf: null,
      pct: null,
      adkim: null,
      aspf: null,
      tags: [],
      checks,
    };
  }
}
