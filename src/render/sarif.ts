/**
 * SARIF 2.1.0 for GitHub code scanning. Each rule carries `security-severity`
 * (a string, as GitHub requires) and tags with the AST ID first, then ASI, LLM,
 * MCP and CWE, then `security`, kept within GitHub's 10-tag display limit.
 * Results carry a stable fingerprint that does not change when lines move.
 */
import { AST_VERSION } from '../facts/taxonomy.js';
import { RULE_LIST } from '../rules.js';
import type { Report, Rule, Severity } from '../types.js';
import { cleanLine, NOT_A_VERDICT } from './common.js';

/** GitHub: over 9.0 critical, 7.0–8.9 high, 4.0–6.9 medium, 0.1–3.9 low. */
export const SECURITY_SEVERITY: Record<Exclude<Severity, 'none'>, string> = { critical: '9.3', high: '8.0', medium: '5.5', low: '3.0' };

const LEVEL: Record<Severity, 'error' | 'warning' | 'note'> = { critical: 'error', high: 'error', medium: 'warning', low: 'note', none: 'note' };

/** SARIF tags for a rule, AST first, at most 10. */
export function sarifTags(r: Rule): string[] {
  if (r.severity === 'none') return ['maintainability', 'context-hygiene'];
  const t = r.tags;
  const tags = [
    ...(t.ast ? [`owasp-ast10:${t.ast}`] : []),
    ...(t.asi ?? []).map((x) => `owasp-asi-2026:${x}`),
    ...(t.llm ?? []).map((x) => `owasp-llm-2025:${x}`),
    ...(t.mcp ?? []).map((x) => `owasp-mcp:${x}`),
    ...(t.cwe ?? []).map((n) => `external/cwe/cwe-${n}`),
  ].slice(0, 9);
  return [...tags, 'security'];
}

const pascal = (id: string) => id.split(/[/-]/).map((w) => w.charAt(0).toUpperCase() + w.slice(1)).join('');
const cap = (s: string, n: number) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

/** Renders a report as a SARIF 2.1.0 log. */
export function formatSarif(report: Report): string {
  const index = new Map(RULE_LIST.map((r, i) => [r.id, i]));
  const rules = RULE_LIST.map((r) => ({
    id: r.id,
    name: pascal(r.id),
    shortDescription: { text: cap(r.title, 1024) },
    fullDescription: { text: cap(r.why, 1024) },
    help: {
      text: `${r.why}\n\nFix: ${r.fix}\n\nSource: ${r.source.title} ${r.source.url}`,
      markdown: `${r.why}\n\n**Fix:** ${r.fix}\n\n**Source:** [${r.source.title}](${r.source.url})`,
    },
    helpUri: r.source.url,
    defaultConfiguration: { level: LEVEL[r.severity] },
    properties: {
      tags: sarifTags(r),
      precision: r.severity === 'none' ? 'medium' : 'high',
      ...(r.severity !== 'none' ? { 'security-severity': SECURITY_SEVERITY[r.severity] } : {}),
    },
  }));
  const results = report.findings.map((f) => {
    const r = RULE_LIST[index.get(f.id) as number] as Rule;
    return {
      ruleId: f.id,
      ruleIndex: index.get(f.id),
      level: LEVEL[r.severity],
      message: { text: `${f.title}. ${f.observed}` },
      locations: [{ physicalLocation: { artifactLocation: { uri: encodeURI(f.file) }, region: { startLine: f.line ?? 1, startColumn: 1 } } }],
      partialFingerprints: { primaryLocationLineHash: `${f.fingerprint.slice(0, 16)}:1` },
      fingerprints: { 'agentConfigAudit/v1': f.fingerprint },
      properties: { priority: f.priority, ...(f.key ? { key: f.key } : {}) },
    };
  });
  const log = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'agent-config-audit',
            semanticVersion: report.tool.version,
            version: report.tool.version,
            informationUri: report.tool.url,
            rules,
          },
        },
        automationDetails: { id: 'agent-config-audit/' },
        results,
        properties: {
          taxonomy: AST_VERSION,
          statement: report.findings.length ? NOT_A_VERDICT : cleanLine(report.suppressed),
          notAssessed: [...report.coverage.ast.filter((a) => a.status === 'not-assessed').map((a) => `${a.id} ${a.title}: ${a.how}`), ...report.coverage.notAssessed.map((n) => `${n.what}: ${n.why}`)],
          unread: report.coverage.unread,
        },
      },
    ],
  };
  return `${JSON.stringify(log, null, 2)}\n`;
}
