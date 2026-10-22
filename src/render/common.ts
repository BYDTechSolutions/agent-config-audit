import { PRIORITIES, type Finding, type Priority, type Report, type Surface } from '../types.js';

/** Findings bucketed by priority, in priority order. */
export function byPriority(report: Report): { priority: Priority; findings: Finding[] }[] {
  return PRIORITIES.map((priority) => ({ priority, findings: report.findings.filter((f) => f.priority === priority) }));
}

/** Counts per priority. */
export function counts(report: Report): Record<Priority, number> {
  const out: Record<Priority, number> = { 'fix-now': 0, 'should-fix': 0, review: 0 };
  for (const f of report.findings) out[f.priority]++;
  return out;
}

/** `file:line`, or `file`. */
export function location(f: Finding): string {
  return f.line ? `${f.file}:${f.line}` : f.file;
}

/** `250 ms` or `1.2 s`. */
export function duration(ms: number): string {
  return ms >= 1000 ? `${(ms / 1000).toFixed(1)} s` : `${ms} ms`;
}

/** Surfaces that start a process or run a command, then the rest. */
export function splitInventory(inv: Surface[]): { runs: Surface[]; loads: Surface[] } {
  return { runs: inv.filter((s) => s.runs), loads: inv.filter((s) => !s.runs) };
}

/** Printed when there are no findings. Never "safe", never "secure". */
export const CLEAN = 'No findings for the rules in this version; this is not a malware check.';

/** The closing line for a report with no findings: says when a baseline hid some. */
export function cleanLine(suppressed: number): string {
  return suppressed ? `No findings outside the baseline (${suppressed} hidden) for the rules in this version; this is not a malware check.` : CLEAN;
}

/** Printed under every report that has findings. */
export const NOT_A_VERDICT = 'Findings are leads for human review, not a verdict. This is not a malware check.';
