export { auditDNSAuth } from './auditor.js';
export { checkSPF } from './checks/spf.js';
export { checkDKIM } from './checks/dkim.js';
export { checkDMARC } from './checks/dmarc.js';
export { checkBIMI } from './checks/bimi.js';
export { checkMTASTS } from './checks/mta-sts.js';
export { checkMX } from './checks/mx.js';
export { gradeResult } from './grader.js';
export { formatTable } from './formatters/table.js';
export { formatJSON } from './formatters/json.js';

export type {
  AuditResult,
  AuditOptions,
  Grade,
  Severity,
  Status,
  Issue,
  SPFResult,
  SPFMechanism,
  DKIMResult,
  DKIMSelector,
  DMARCResult,
  DMARCTag,
  BIMIResult,
  MTASTSResult,
  MXResult,
  MXRecord,
  CheckResult,
  CLIOptions,
} from './types.js';
