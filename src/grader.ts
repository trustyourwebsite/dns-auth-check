import type { AuditResult, Grade, Issue } from './types.js';

/**
 * Calculate score and grade from audit results.
 * Score starts at 100, deductions apply per issue.
 */
export function gradeResult(result: Omit<AuditResult, 'grade' | 'score' | 'issues'>): {
  grade: Grade;
  score: number;
  issues: Issue[];
} {
  let score = 100;
  const issues: Issue[] = [];

  // --- SPF scoring ---
  if (result.spf.dnsError) {
    score -= 5;
    issues.push({
      severity: 'high',
      message: 'SPF DNS lookup failed — cannot determine if record exists',
      fix: 'Check your DNS configuration or try again later',
    });
  } else if (!result.spf.found) {
    score -= 25;
    issues.push({
      severity: 'critical',
      message: 'No SPF record found — anyone can send email pretending to be your domain',
      fix: 'Add a TXT record: v=spf1 include:<your-email-provider> -all',
    });
  } else {
    if (result.spf.multipleRecords) {
      score -= 15;
      issues.push({
        severity: 'high',
        message: 'Multiple SPF records found — invalid per RFC 7208',
        fix: 'Merge all SPF rules into a single TXT record',
      });
    }
    if (result.spf.lookupCount > 10) {
      score -= 15;
      issues.push({
        severity: 'high',
        message: `SPF exceeds 10 DNS lookup limit (${result.spf.lookupCount} lookups)`,
        fix: 'Flatten SPF record by replacing includes with direct IP ranges, or use an SPF flattening service',
      });
    }
    if (result.spf.allQualifier === '+') {
      score -= 20;
      issues.push({
        severity: 'critical',
        message: 'SPF uses +all — allows anyone to send email as your domain',
        fix: 'Change +all to -all to reject unauthorized senders',
      });
    } else if (result.spf.allQualifier === '~') {
      score -= 5;
      issues.push({
        severity: 'medium',
        message: 'SPF uses soft fail (~all) instead of hard fail (-all)',
        fix: 'Change ~all to -all for stronger protection',
      });
    } else if (result.spf.allQualifier === '?') {
      score -= 10;
      issues.push({
        severity: 'medium',
        message: 'SPF uses neutral (?all) — provides no protection',
        fix: 'Change ?all to -all to reject unauthorized senders',
      });
    }
    if (result.spf.hasDeprecatedPtr) {
      score -= 3;
      issues.push({
        severity: 'low',
        message: 'SPF uses deprecated "ptr" mechanism',
        fix: 'Remove ptr mechanism per RFC 7208 §5.5 — use ip4/ip6 instead',
      });
    }
    if (result.spf.recordLength > 512) {
      score -= 5;
      issues.push({
        severity: 'medium',
        message: `SPF record exceeds 512-byte DNS UDP limit (${result.spf.recordLength} bytes)`,
        fix: 'Shorten SPF record or use includes to reduce direct record size',
      });
    }
  }

  // --- DKIM scoring ---
  if (result.dkim.dnsError) {
    score -= 5;
    issues.push({
      severity: 'high',
      message: 'DKIM DNS lookup failed — cannot determine if records exist',
      fix: 'Check your DNS configuration or try again later',
    });
  } else if (!result.dkim.found) {
    score -= 20;
    issues.push({
      severity: 'high',
      message: 'No DKIM records found for common selectors',
      fix: 'Configure DKIM signing with your email provider — they will give you a DNS record to add',
    });
  } else {
    const foundSelectors = result.dkim.selectors.filter((s) => s.found);
    for (const sel of foundSelectors) {
      if (sel.keyLength !== null && sel.keyLength < 1024) {
        score -= 10;
        issues.push({
          severity: 'high',
          message: `DKIM key for "${sel.selector}" is only ${sel.keyLength} bits — too weak`,
          fix: 'Generate a new DKIM key with at least 2048 bits',
        });
      } else if (sel.keyLength === 1024) {
        score -= 3;
        issues.push({
          severity: 'low',
          message: `DKIM key for "${sel.selector}" is 1024 bits — consider upgrading to 2048`,
          fix: 'Generate a new 2048-bit DKIM key for stronger security',
        });
      }
    }
  }

  // --- DMARC scoring ---
  if (result.dmarc.dnsError) {
    score -= 5;
    issues.push({
      severity: 'high',
      message: 'DMARC DNS lookup failed — cannot determine if record exists',
      fix: 'Check your DNS configuration or try again later',
    });
  } else if (!result.dmarc.found) {
    score -= 25;
    issues.push({
      severity: 'critical',
      message: 'No DMARC record found — email receivers have no policy for handling spoofed emails',
      fix: 'Add a TXT record at _dmarc.yourdomain.com: v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com',
    });
  } else {
    if (result.dmarc.policy === 'none') {
      score -= 10;
      issues.push({
        severity: 'high',
        message: 'DMARC policy is "none" — monitoring only, not blocking spoofed emails',
        fix: 'Change p=none to p=quarantine or p=reject after reviewing DMARC reports',
      });
    } else if (result.dmarc.policy === 'quarantine') {
      // Good but not best
      score -= 2;
    }
    // p=reject: no deduction

    if (!result.dmarc.rua) {
      score -= 5;
      issues.push({
        severity: 'medium',
        message: 'No DMARC reporting URI (rua=) — you won\'t know about authentication failures',
        fix: 'Add rua=mailto:dmarc-reports@yourdomain.com to your DMARC record',
      });
    }

    if (!result.dmarc.subdomainPolicy) {
      score -= 3;
      issues.push({
        severity: 'low',
        message: `No subdomain DMARC policy (sp=) — subdomains inherit p=${result.dmarc.policy || 'none'}`,
        fix: 'Add sp=reject to your DMARC record to protect subdomains',
      });
    }

    if (result.dmarc.pct !== null && result.dmarc.pct < 100) {
      score -= 3;
      issues.push({
        severity: 'low',
        message: `DMARC applies to only ${result.dmarc.pct}% of emails`,
        fix: 'Remove pct= tag or set pct=100 to apply DMARC to all emails',
      });
    }
  }

  // --- BIMI (informational, small bonus) ---
  if (result.bimi && result.bimi.found) {
    score = Math.min(100, score + 2);
  } else {
    issues.push({
      severity: 'info',
      message: 'No BIMI record — consider adding one for brand visibility in inboxes',
    });
  }

  // --- MTA-STS (informational) ---
  if (result.mtaSts && result.mtaSts.found) {
    score = Math.min(100, score + 2);
    if (result.mtaSts.policyMode === 'testing') {
      issues.push({
        severity: 'info',
        message: 'MTA-STS is in testing mode — consider switching to enforce',
      });
    }
  }

  // --- MX (if checked) ---
  if (result.mx?.dnsError) {
    score -= 5;
    issues.push({
      severity: 'high',
      message: 'MX DNS lookup failed — cannot determine if records exist',
      fix: 'Check your DNS configuration or try again later',
    });
  } else if (result.mx && !result.mx.found) {
    score -= 10;
    issues.push({
      severity: 'high',
      message: 'No MX records found — domain cannot receive email',
      fix: 'Add MX records pointing to your email provider\'s mail servers',
    });
  }

  // Clamp score
  score = Math.max(0, Math.min(100, score));

  // Sort issues by severity
  const severityOrder: Record<string, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    info: 4,
  };
  issues.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  return { grade: scoreToGrade(score), score, issues };
}

function scoreToGrade(score: number): Grade {
  if (score >= 95) return 'A+';
  if (score >= 85) return 'A';
  if (score >= 70) return 'B';
  if (score >= 55) return 'C';
  if (score >= 40) return 'D';
  return 'F';
}
