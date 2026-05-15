#!/usr/bin/env node

import { writeFileSync } from 'node:fs';
import { auditDNSAuth } from './auditor.js';
import { formatTable } from './formatters/table.js';
import { formatJSON } from './formatters/json.js';
import type { CLIOptions } from './types.js';

function printUsage(): void {
  console.log(`
dns-auth-check — DNS email authentication auditor
https://trustyourwebsite.com

Usage:
  dns-auth-check <domain> [options]
  npx @trustyourwebsite/dns-auth-check <domain> [options]

Options:
  --format <json|text|table>    Output format (default: table)
  --dkim-selector <name>        DKIM selector to check (repeatable)
  --dkim-selectors <s1,s2,...>  Comma-separated DKIM selectors
  --check-mx                    Also check MX records and connectivity
  --output <file>               Save report to file
  --ci                          Exit code 1 if critical/high issues found
  --timeout <ms>                DNS query timeout (default: 5000)
  --help                        Show this help
  --version                     Show version

Examples:
  dns-auth-check trustyourwebsite.com
  dns-auth-check example.com --format json --check-mx
  dns-auth-check example.com --ci --dkim-selectors google,s1,default
  dns-auth-check example.com --output report.json --format json
`);
}

function parseArgs(args: string[]): { domain: string | null; options: CLIOptions } | null {
  const options: CLIOptions = {
    format: 'table',
    ci: false,
    checkMX: false,
  };

  let domain: string | null = null;
  const dkimSelectors: string[] = [];

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];

    if (arg === '--help' || arg === '-h') {
      printUsage();
      process.exit(0);
    }

    if (arg === '--version' || arg === '-v') {
      // Read version from package at build time isn't possible without deps,
      // so we hardcode it. Updated by prepublishOnly script.
      console.log('1.0.0');
      process.exit(0);
    }

    if (arg === '--format' && args[i + 1]) {
      const fmt = args[++i];
      if (fmt === 'json' || fmt === 'text' || fmt === 'table') {
        options.format = fmt;
      } else {
        console.error(`Unknown format: ${fmt}. Use json, text, or table.`);
        process.exit(1);
      }
      continue;
    }

    if (arg === '--dkim-selector' && args[i + 1]) {
      dkimSelectors.push(args[++i]);
      continue;
    }

    if (arg === '--dkim-selectors' && args[i + 1]) {
      dkimSelectors.push(...args[++i].split(',').map((s) => s.trim()).filter(Boolean));
      continue;
    }

    if (arg === '--check-mx') {
      options.checkMX = true;
      continue;
    }

    if (arg === '--output' && args[i + 1]) {
      options.output = args[++i];
      continue;
    }

    if (arg === '--ci') {
      options.ci = true;
      continue;
    }

    if (arg === '--timeout' && args[i + 1]) {
      options.timeout = parseInt(args[++i], 10);
      if (isNaN(options.timeout) || options.timeout <= 0) {
        console.error('Timeout must be a positive number (milliseconds).');
        process.exit(1);
      }
      continue;
    }

    if (arg.startsWith('-')) {
      console.error(`Unknown option: ${arg}`);
      printUsage();
      process.exit(1);
    }

    // Positional argument = domain
    if (!domain) {
      domain = arg;
    }
  }

  if (dkimSelectors.length > 0) {
    options.dkimSelectors = dkimSelectors;
  }

  return { domain, options };
}

async function main(): Promise<void> {
  const parsed = parseArgs(process.argv.slice(2));

  if (!parsed || !parsed.domain) {
    console.error('Error: domain argument is required.\n');
    printUsage();
    process.exit(1);
  }

  const { domain, options } = parsed;

  try {
    const result = await auditDNSAuth(domain, {
      dkimSelectors: options.dkimSelectors,
      checkMX: options.checkMX,
      timeout: options.timeout,
    });

    // Format output
    let output: string;
    if (options.format === 'json') {
      output = formatJSON(result);
    } else {
      // 'table' and 'text' both use table format
      output = formatTable(result);
    }

    // Write to file or stdout
    if (options.output) {
      writeFileSync(options.output, output, 'utf-8');
      console.log(`Report saved to ${options.output}`);
    } else {
      console.log(output);
    }

    // CI mode: exit 1 if critical or high issues
    if (options.ci) {
      const hasCritical = result.issues.some(
        (i) => i.severity === 'critical' || i.severity === 'high',
      );
      if (hasCritical) {
        process.exit(1);
      }
    }
  } catch (err) {
    console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  }
}

main();
