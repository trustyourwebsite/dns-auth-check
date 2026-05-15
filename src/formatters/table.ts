import type { AuditResult, CheckResult } from '../types.js';

const ICONS: Record<string, string> = {
  pass: '\u2713',   // ✓
  warn: '\u26A0',   // ⚠
  fail: '\u2717',   // ✗
  info: '-',
  error: '!',
};

const SEVERITY_LABELS: Record<string, string> = {
  critical: 'CRITICAL',
  high: 'HIGH',
  medium: 'MEDIUM',
  low: 'LOW',
  info: 'INFO',
};

function formatChecks(checks: CheckResult[]): string {
  return checks
    .map((c) => `  ${ICONS[c.status]} ${c.message}`)
    .join('\n');
}

/**
 * Format audit result as a human-readable table.
 */
export function formatTable(result: AuditResult): string {
  const lines: string[] = [];

  lines.push('DNS Email Authentication Report');
  lines.push('================================');
  lines.push(`Domain:  ${result.domain}`);
  lines.push(`Grade:   ${result.grade} (${result.score}/100)`);
  lines.push('');

  // SPF
  lines.push('SPF Record:');
  lines.push(formatChecks(result.spf.checks));
  lines.push('');

  // DKIM
  lines.push('DKIM Records:');
  if (result.dkim.checks.length > 0) {
    lines.push(formatChecks(result.dkim.checks));
  }
  for (const sel of result.dkim.selectors) {
    if (sel.found || sel.checks.some((c) => c.status !== 'info')) {
      lines.push(formatChecks(sel.checks));
    }
  }
  // Show a summary of not-found selectors
  const notFound = result.dkim.selectors.filter((s) => !s.found);
  if (notFound.length > 0 && result.dkim.found) {
    const names = notFound.map((s) => s.selector).join(', ');
    lines.push(`  - Not found (not necessarily an issue): ${names}`);
  }
  lines.push('');

  // DMARC
  lines.push('DMARC Record:');
  lines.push(formatChecks(result.dmarc.checks));
  lines.push('');

  // BIMI
  lines.push('BIMI:');
  if (result.bimi) {
    lines.push(formatChecks(result.bimi.checks));
  } else {
    lines.push('  - Not checked');
  }
  lines.push('');

  // MTA-STS
  lines.push('MTA-STS:');
  if (result.mtaSts) {
    lines.push(formatChecks(result.mtaSts.checks));
  } else {
    lines.push('  - Not checked');
  }
  lines.push('');

  // MX
  if (result.mx) {
    lines.push('MX Records:');
    lines.push(formatChecks(result.mx.checks));
    lines.push('');
  }

  // Issues
  if (result.issues.length > 0) {
    lines.push('Issues (ordered by priority):');
    result.issues.forEach((issue, i) => {
      const label = SEVERITY_LABELS[issue.severity] || issue.severity.toUpperCase();
      lines.push(`  ${i + 1}. [${label}] ${issue.message}`);
      if (issue.fix) {
        lines.push(`     Fix: ${issue.fix}`);
      }
    });
    lines.push('');
  }

  lines.push(`Full website compliance scan \u2192 https://trustyourwebsite.com`);

  return lines.join('\n');
}
