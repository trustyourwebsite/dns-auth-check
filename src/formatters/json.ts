import type { AuditResult } from '../types.js';

/**
 * Format audit result as JSON string.
 */
export function formatJSON(result: AuditResult): string {
  return JSON.stringify(result, null, 2);
}
