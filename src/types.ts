export type Grade = 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Status = 'pass' | 'warn' | 'fail' | 'info' | 'error';

export interface Issue {
  severity: Severity;
  message: string;
  fix?: string;
}

export interface SPFMechanism {
  qualifier: '+' | '-' | '~' | '?';
  type: string;
  value: string;
}

export interface SPFResult {
  found: boolean;
  dnsError?: boolean;
  record: string | null;
  domain: string | null;
  valid: boolean;
  mechanisms: SPFMechanism[];
  lookupCount: number;
  allQualifier: '+' | '-' | '~' | '?' | null;
  recordLength: number;
  multipleRecords: boolean;
  hasDeprecatedPtr: boolean;
  checks: CheckResult[];
}

export interface DKIMSelector {
  selector: string;
  found: boolean;
  dnsError?: boolean;
  record: string | null;
  keyType: string | null;
  keyLength: number | null;
  checks: CheckResult[];
}

export interface DKIMResult {
  selectorsChecked: string[];
  selectors: DKIMSelector[];
  found: boolean;
  dnsError?: boolean;
  checks: CheckResult[];
}

export interface DMARCTag {
  tag: string;
  value: string;
}

export interface DMARCResult {
  found: boolean;
  dnsError?: boolean;
  record: string | null;
  policy: string | null;
  subdomainPolicy: string | null;
  rua: string | null;
  ruf: string | null;
  pct: number | null;
  adkim: string | null;
  aspf: string | null;
  tags: DMARCTag[];
  checks: CheckResult[];
}

export interface BIMIResult {
  found: boolean;
  dnsError?: boolean;
  record: string | null;
  logoUrl: string | null;
  vmcUrl: string | null;
  checks: CheckResult[];
}

export interface MTASTSResult {
  found: boolean;
  dnsError?: boolean;
  record: string | null;
  policyMode: string | null;
  checks: CheckResult[];
}

export interface MXRecord {
  priority: number;
  exchange: string;
  provider: string | null;
}

export interface MXResult {
  found: boolean;
  dnsError?: boolean;
  records: MXRecord[];
  checks: CheckResult[];
}

export interface CheckResult {
  status: Status;
  message: string;
}

export interface AuditResult {
  domain: string;
  timestamp: string;
  grade: Grade;
  score: number;
  spf: SPFResult;
  dkim: DKIMResult;
  dmarc: DMARCResult;
  bimi: BIMIResult | null;
  mtaSts: MTASTSResult | null;
  mx: MXResult | null;
  issues: Issue[];
}

export interface AuditOptions {
  /** DKIM selectors to check (default: common selectors) */
  dkimSelectors?: string[];
  /** Also check MX records */
  checkMX?: boolean;
  /** DNS query timeout in milliseconds (default: 5000) */
  timeout?: number;
}

export interface CLIOptions extends AuditOptions {
  format: 'json' | 'text' | 'table';
  output?: string;
  ci: boolean;
}
