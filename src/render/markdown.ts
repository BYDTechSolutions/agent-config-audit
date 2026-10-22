import { FAMILY_NAMES, PRIORITY_NAMES, type Report } from '../types.js';
import { byPriority, CLEAN, counts, location, NOT_A_VERDICT } from './common.js';

const cell = (s: string) => s.replace(/\|/g, '\\|').replace(/\n/g, ' ');

/** Renders a report as GitHub-flavored Markdown (for a PR comment, an issue or a file). */
export function formatMarkdown(report: Report): string {
  const c = counts(report);
  const out: string[] = [];
  out.push(`# Agent config audit: \`${report.root}\``, '');
  out.push(`${report.stats.filesRead} agent files read, ${report.inventory.length} surfaces (${report.inventory.filter((s) => s.runs).length} run code). **${c['fix-now']} fix now**, **${c['should-fix']} should fix**, ${c.review} review${report.suppressed ? `, ${report.suppressed} in baseline` : ''}.`, '');
  if (!report.findings.length) out.push(`**${CLEAN}**`, '');

  let n = 0;
  for (const { priority, findings } of byPriority(report)) {
    if (!findings.length) continue;
    out.push(`## ${PRIORITY_NAMES[priority]} (${findings.length})`, '');
    for (const f of findings) {
      n++;
      out.push(`### ${n}. ${f.title}`, '');
      out.push(`\`${location(f)}\`${f.key ? ` · \`${f.key}\`` : ''} · ${FAMILY_NAMES[f.family]} · ${f.tags.join(', ')} · rule \`${f.id}\``, '');
      out.push(`- **Saw:** ${f.observed}`);
      for (const d of f.details ?? []) out.push(`  - ${d}`);
      out.push(`- **Why:** ${f.why}`);
      out.push(`- **Fix:** ${f.fix}`);
      out.push(`- **Source:** [${f.source.title}](${f.source.url})`, '');
    }
  }

  out.push(`## What an agent will load or run (${report.inventory.length})`, '');
  if (report.inventory.length) {
    out.push('| Kind | Name | File | Runs code | Read by | Summary |', '|---|---|---|---|---|---|');
    for (const s of report.inventory) out.push(`| ${s.kind} | ${cell(s.name)} | \`${cell(s.path)}\` | ${s.runs ? 'yes' : ''} | ${cell(s.tools.join(', '))} | ${cell(s.summary)} |`);
  } else out.push('Nothing found.');
  out.push('');

  if (report.coverage.unread.length) {
    out.push(`## Not checked: needs human review (${report.coverage.unread.length})`, '');
    for (const u of report.coverage.unread) out.push(`- \`${u.path}\`: ${u.detail}`);
    out.push('');
  }

  out.push('## Coverage', '', '| OWASP AST | Status | How |', '|---|---|---|');
  for (const a of report.coverage.ast) out.push(`| ${a.id} ${a.title} | ${a.status.replace(/-/g, ' ')} | ${cell(a.how)} |`);
  out.push('', ...report.coverage.notAssessed.map((n) => `- **Not assessed: ${n.what}.** ${n.why}`), '');
  for (const note of report.notes) out.push(`> ${note}`, '');
  if (report.findings.length) out.push(`_${NOT_A_VERDICT}_`, '');
  out.push(`<sub>${report.tool.name} ${report.tool.version} · ${report.tool.url} · ${report.startedAt.replace(/\.\d+Z$/, 'Z')}</sub>`, '');
  return out.join('\n');
}
