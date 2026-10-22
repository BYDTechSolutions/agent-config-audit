import { FAMILY_NAMES, PRIORITY_NAMES, type Priority, type Report, type Surface } from '../types.js';
import { byPriority, cleanLine, counts, duration, location, NOT_A_VERDICT, splitInventory } from './common.js';

/** Options for {@link formatText}. */
export interface TextOptions {
  /** ANSI colors. Default `false`. */
  color?: boolean;
  /** Wrap width. Default `100`. */
  width?: number;
  /** List every surface, not only the ones that run. Default `false`. */
  fullInventory?: boolean;
}

function wrap(text: string, width: number, indent: string, firstIndent = indent): string {
  const words = text.replace(/\s+/g, ' ').trim().split(' ');
  const lines: string[] = [];
  let line = firstIndent;
  let has = false;
  for (const word of words) {
    if (has && line.length + 1 + word.length > width) {
      lines.push(line);
      line = indent + word;
    } else line += (has ? ' ' : '') + word;
    has = true;
  }
  lines.push(line);
  return lines.join('\n');
}

const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? '' : 's'}`;
const pad = (s: string, n: number) => (s.length >= n ? `${s} ` : s + ' '.repeat(n - s.length));

/** Renders a report for a terminal: findings grouped by priority, then the inventory and coverage. */
export function formatText(report: Report, options: TextOptions = {}): string {
  const width = Math.max(60, options.width ?? 100);
  const on = options.color ?? false;
  const esc = (c: string) => (s: string) => (on ? `\u001b[${c}m${s}\u001b[0m` : s);
  const bold = esc('1');
  const dim = esc('2');
  const colorOf: Record<Priority, (s: string) => string> = { 'fix-now': esc('1;31'), 'should-fix': esc('1;33'), review: esc('1;36') };
  const c = counts(report);
  const { runs, loads } = splitInventory(report.inventory);
  const out: string[] = [];

  out.push(bold(`Agent config audit: ${report.root}`));
  out.push(
    `${dim(`${plural(report.stats.filesRead, 'agent file')} read · ${plural(report.inventory.length, 'surface')} (${runs.length} run${runs.length === 1 ? 's' : ''} code) · ${duration(report.durationMs)}`)}  ` +
      `${colorOf['fix-now'](`${c['fix-now']} fix now`)} · ${colorOf['should-fix'](`${c['should-fix']} should fix`)} · ${colorOf.review(`${c.review} review`)}${report.suppressed ? dim(` · ${report.suppressed} in baseline`) : ''}`,
  );

  let n = 0;
  for (const { priority, findings } of byPriority(report)) {
    if (!findings.length) continue;
    out.push('', colorOf[priority](`${PRIORITY_NAMES[priority].toUpperCase()} (${findings.length})`));
    for (const f of findings) {
      n++;
      out.push('');
      out.push(wrap(bold(`${n}. ${f.title}`), width + (on ? 8 : 0), '     ', '  '));
      out.push(dim(`     ${location(f)}${f.key ? `  ${f.key}` : ''}  [${[...f.tags, FAMILY_NAMES[f.family]].join(' · ')}]`));
      out.push(wrap(`Saw: ${f.observed}`, width, '          ', '     '));
      for (const d of f.details ?? []) out.push(wrap(`- ${d}`, width, '         ', '       '));
      out.push(wrap(`Why: ${f.why}`, width, '          ', '     '));
      out.push(wrap(`Fix: ${f.fix}`, width, '          ', '     '));
      out.push(dim(`     Source: ${f.source.title} <${f.source.url}>`));
    }
  }

  const row = (s: Surface) => `  ${pad(s.kind, 13)}${pad(s.name, 26)}${pad(s.path, 34)}${s.summary}`;
  out.push('', bold(`WHAT AN AGENT WILL LOAD OR RUN (${report.inventory.length})`));
  if (!report.inventory.length) out.push('  Nothing found.');
  if (runs.length) {
    out.push(dim('  Runs code:'));
    for (const s of runs.slice(0, 40)) out.push(row(s));
    if (runs.length > 40) out.push(dim(`  … and ${runs.length - 40} more (see --format json)`));
  }
  if (loads.length) {
    if (options.fullInventory) {
      out.push(dim('  Loads:'));
      for (const s of loads) out.push(row(s));
    } else {
      const byKind = new Map<string, number>();
      for (const s of loads) byKind.set(s.kind, (byKind.get(s.kind) ?? 0) + 1);
      out.push(wrap(`${dim('Loads:')} ${[...byKind].map(([k, v]) => `${v} ${k}`).join(', ')} ${dim('(full list: --format json or md)')}`, width + (on ? 16 : 0), '    ', '  '));
    }
  }

  const unread = report.coverage.unread;
  if (unread.length) {
    out.push('', bold(`NOT CHECKED: NEEDS HUMAN REVIEW (${unread.length})`));
    for (const u of unread.slice(0, 30)) out.push(wrap(`- ${u.path}: ${u.detail}`, width, '    ', '  '));
    if (unread.length > 30) out.push(dim(`  … and ${unread.length - 30} more`));
  }

  out.push('', bold('COVERAGE') + dim('  (details: --format md or json)'));
  const partly = report.coverage.ast.filter((a) => a.status !== 'not-assessed');
  const not = report.coverage.ast.filter((a) => a.status === 'not-assessed');
  out.push(wrap(`Checked in part: ${partly.map((a) => `${a.id}${a.status === 'inventory-only' ? ' (inventory only)' : ''}`).join(', ')}.`, width, '    ', '  '));
  out.push(wrap(`Not assessed: ${[...not.map((a) => `${a.id} ${a.title} (${a.short ?? a.how})`), ...report.coverage.notAssessed.filter((n) => n.what !== 'malware').map((n) => n.what)].join(', ')}.`, width, '    ', '  '));
  for (const note of report.notes) out.push(wrap(`Note: ${note}`, width, '    ', '  '));
  out.push('', report.findings.length ? dim(NOT_A_VERDICT) : bold(cleanLine(report.suppressed)));
  out.push(dim(`${report.tool.name} ${report.tool.version} · ${report.tool.url}`));
  return `${out.join('\n')}\n`;
}
