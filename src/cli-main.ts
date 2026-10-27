/*
 * The CLI, as a function: arguments and I/O in, exit code out. `cli.ts` wires
 * it to the real process; tests call it directly.
 */
import { readFile, writeFile } from 'node:fs/promises';
import { extname, join, resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { auditRepo } from './audit.js';
import { AuditError } from './errors.js';
import { compareLocks, countKinds, createLock, formatDiff, formatLock, LOCKFILE_NAME, parseLock, type Lockfile } from './lock.js';
import { counts } from './render/common.js';
import { FORMATS, formatReport, type ReportFormat } from './render/index.js';
import { sarifTags } from './render/sarif.js';
import { RULE_LIST } from './rules.js';
import { FAMILIES, FAMILY_NAMES, type Family, type Priority } from './types.js';
import { VERSION } from './version.js';

/** What the CLI reads from and writes to. */
export interface CliIo {
  stdout: (text: string) => void;
  stderr: (text: string) => void;
  env: Record<string, string | undefined>;
  stdoutIsTTY: boolean;
  columns?: number;
  cwd?: string;
  readFile?: (path: string) => Promise<string>;
  writeFile?: (path: string, data: string) => Promise<void>;
}

export const HELP = `Usage:
  agent-config-audit [dir] [options]          audit the agent config in dir (default: .)
  agent-config-audit lock [dir] [options]     write ${LOCKFILE_NAME} (a reviewed snapshot)
  agent-config-audit diff [dir] [options]     show what changed since ${LOCKFILE_NAME}; exit 1 if anything did

Lists everything an AI coding agent will load or run from this repository
(hooks, MCP servers, skills, plugins, rules files, env overrides), flags what is
risky against the OWASP Agentic Skills Top 10, and says what it cannot assess.
Offline; it never runs, imports or fetches anything it finds. It is not a
malware check, and it never says "safe".

Examples:
  npx @bydtech/agent-config-audit
  npx @bydtech/agent-config-audit --fail-on fix-now            # CI gate
  npx @bydtech/agent-config-audit --format sarif --out agent-config.sarif
  npx @bydtech/agent-config-audit lock && git add ${LOCKFILE_NAME}
  npx @bydtech/agent-config-audit diff                          # in CI: exit 1 on drift

Options:
  -f, --format <fmt>       text (default), json, md or sarif
  -o, --out <file>         write the output to a file, format from .json/.md/.sarif (anything
                           else is text); repeat to write several formats at once
      --fail-on <level>    exit 1 if any finding is at this level or above: fix-now or should-fix
      --baseline <file>    hide findings already in this file (an earlier --format json or sarif output)
      --only <families>    comma-separated: ${FAMILIES.join(', ')}
      --exclude <paths>    comma-separated path prefixes to skip (.git and node_modules always are)
      --lock <file>        lockfile for lock/diff (default: <dir>/${LOCKFILE_NAME})
      --max-file-bytes <n> larger files are not read and are listed for human review (default 1048576)
      --all                list every surface in the text report, not only those that run code
      --list-rules         print every rule with its OWASP tags and source, then exit
      --no-color           plain text output (also honors NO_COLOR)
  -h, --help               show this help
  -v, --version            show the version

Exit codes: 0 done, 1 --fail-on threshold met or diff found changes, 2 bad usage or an error.
`;

const FAIL_LEVELS: Record<string, Priority[]> = { 'fix-now': ['fix-now'], 'should-fix': ['fix-now', 'should-fix'] };

/** Reads fingerprints from a JSON report, a SARIF log, or `{ "fingerprints": [...] }`. */
export function baselineFingerprints(text: string): string[] {
  let v: unknown;
  try {
    v = JSON.parse(text);
  } catch {
    throw new AuditError('The baseline file is not valid JSON. Create one with --format json --out <file>.');
  }
  const o = v as { findings?: { fingerprint?: string }[]; fingerprints?: string[]; runs?: { results?: { fingerprints?: Record<string, string> }[] }[] };
  if (Array.isArray(o.fingerprints)) return o.fingerprints.filter((x) => typeof x === 'string');
  if (Array.isArray(o.findings)) return o.findings.map((f) => f.fingerprint).filter((x): x is string => typeof x === 'string');
  if (Array.isArray(o.runs)) return o.runs.flatMap((r) => (r.results ?? []).map((x) => x.fingerprints?.['agentConfigAudit/v1'])).filter((x): x is string => typeof x === 'string');
  throw new AuditError('The baseline file has no findings, SARIF results or fingerprints.');
}

/** Runs the CLI. Returns the exit code. */
export async function main(argv: string[], io: CliIo): Promise<number> {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      strict: true,
      options: {
        format: { type: 'string', short: 'f' },
        out: { type: 'string', short: 'o', multiple: true },
        'fail-on': { type: 'string' },
        baseline: { type: 'string' },
        only: { type: 'string' },
        exclude: { type: 'string' },
        lock: { type: 'string' },
        'max-file-bytes': { type: 'string' },
        all: { type: 'boolean' },
        'list-rules': { type: 'boolean' },
        'no-color': { type: 'boolean' },
        help: { type: 'boolean', short: 'h' },
        version: { type: 'boolean', short: 'v' },
      },
    });
  } catch (error) {
    io.stderr(`agent-config-audit: ${(error as Error).message}\nRun agent-config-audit --help for usage.\n`);
    return 2;
  }
  const { values, positionals } = parsed;
  const usage = (message: string) => {
    io.stderr(`agent-config-audit: ${message}\nRun agent-config-audit --help for usage.\n`);
    return 2;
  };
  if (values.help) {
    io.stdout(HELP);
    return 0;
  }
  if (values.version) {
    io.stdout(`${VERSION}\n`);
    return 0;
  }

  const outs = values.out ?? [];
  let format: ReportFormat = 'text';
  if (values.format) {
    if (!FORMATS.includes(values.format as ReportFormat)) return usage(`--format must be one of ${FORMATS.join(', ')}.`);
    if (outs.length > 1) return usage('--format works with one --out. With several, each file\'s extension picks its format (.json, .md, .sarif, anything else is text).');
    format = values.format as ReportFormat;
  } else if (outs.length === 1) {
    format = formatFromExtension(outs[0] as string);
  }
  const formatOf = (file: string): ReportFormat => (values.format ? format : formatFromExtension(file));
  const color = format === 'text' && !outs.length && io.stdoutIsTTY && !values['no-color'] && !io.env.NO_COLOR;
  const cwd = io.cwd ?? process.cwd();
  const read = io.readFile ?? ((p: string) => readFile(p, 'utf8'));
  const write = io.writeFile ?? ((p: string, d: string) => writeFile(p, d, 'utf8'));
  /** Prints the output, or writes it to each --out file in that file's format. */
  const emit = async (render: (fmt: ReportFormat) => string, summary: string): Promise<boolean> => {
    if (!outs.length) {
      io.stdout(render(format));
      return true;
    }
    for (const file of outs) {
      const path = resolve(cwd, file);
      const fmt = formatOf(file);
      try {
        await write(path, render(fmt));
      } catch (error) {
        io.stderr(`agent-config-audit: could not write ${path}: ${(error as Error).message}\n`);
        return false;
      }
      io.stdout(`${summary.replace('{path}', path).replace('{format}', fmt)}\n`);
    }
    return true;
  };

  if (values['list-rules']) {
    if (format === 'json') {
      io.stdout(`${JSON.stringify(RULE_LIST, null, 2)}\n`);
    } else if (format === 'md' || format === 'sarif') {
      const rows = RULE_LIST.map((r) => `| \`${r.id}\` | ${r.priority} | ${[r.tags.ast, ...(r.tags.asi ?? []), ...(r.tags.llm ?? []), ...(r.tags.mcp ?? []), ...(r.tags.cwe ?? []).map((n) => `CWE-${n}`)].filter(Boolean).join(', ') || 'context hygiene'} | ${r.title} | [source](${r.source.url}) |`);
      io.stdout(['| Rule | Priority | Tags | Looks for | Source |', '|---|---|---|---|---|', ...rows, ''].join('\n'));
    } else {
      const lines = [`${RULE_LIST.length} rules (${VERSION})`, ''];
      for (const fam of FAMILIES) {
        const rs = RULE_LIST.filter((r) => r.family === fam);
        lines.push(`${FAMILY_NAMES[fam]} (${fam}, ${rs.length})`);
        for (const r of rs) lines.push(`  ${r.id.padEnd(34)} ${r.priority.padEnd(11)} ${r.title}`, `  ${' '.repeat(34)} ${' '.repeat(11)} ${sarifTags(r).filter((t) => t !== 'security').map((t) => t.replace(/^[^:]+:/, '').replace('external/cwe/cwe-', 'CWE-')).join(' · ')} · ${r.source.url}`);
        lines.push('');
      }
      io.stdout(lines.join('\n'));
    }
    return 0;
  }

  const command = positionals[0] === 'lock' || positionals[0] === 'diff' ? positionals[0] : 'audit';
  const dirs = command === 'audit' ? positionals : positionals.slice(1);
  if (dirs.length > 1) return usage('Give at most one directory.');
  const dir = dirs[0] ?? '.';
  const absDir = resolve(cwd, dir);

  let only: Family[] | undefined;
  if (values.only) {
    only = values.only.split(',').map((s) => s.trim()).filter(Boolean) as Family[];
    const unknown = only.filter((f) => !FAMILIES.includes(f));
    if (unknown.length) return usage(`Unknown famil${unknown.length > 1 ? 'ies' : 'y'}: ${unknown.join(', ')}. Families: ${FAMILIES.join(', ')}.`);
  }
  const exclude = values.exclude ? values.exclude.split(',').map((s) => s.trim()).filter(Boolean) : undefined;
  let maxFileBytes: number | undefined;
  if (values['max-file-bytes'] !== undefined) {
    const n = Number(values['max-file-bytes']);
    if (!Number.isInteger(n) || n < 1024) return usage('--max-file-bytes must be a whole number, 1024 or more.');
    maxFileBytes = n;
  }
  const failOn = values['fail-on'];
  if (failOn && !FAIL_LEVELS[failOn]) return usage('--fail-on must be fix-now or should-fix.');
  const lockPath = values.lock ? resolve(cwd, values.lock) : join(absDir, LOCKFILE_NAME);

  try {
    if (command === 'lock') {
      const lock = await createLock(absDir, { exclude, maxFileBytes });
      let previous: Lockfile | null = null;
      try {
        previous = parseLock(await read(lockPath));
      } catch {
        previous = null;
      }
      const n = Object.keys(lock.entries).length;
      const breakdown = countKinds(lock);
      const diff = previous ? compareLocks(previous, lock) : null;
      if (diff?.clean) {
        io.stdout(`${LOCKFILE_NAME} is up to date (${n} entries).\n`);
        return 0;
      }
      await write(lockPath, formatLock(lock));
      io.stdout(`${previous ? 'Updated' : 'Wrote'} ${lockPath}: ${n} entries (${breakdown || 'nothing found'}).\n`);
      if (diff) io.stdout(`\n${formatDiff(diff, { color }).replace(/\n\nReview these changes[^\n]*\n$/, '\n')}`);
      if (!previous) io.stdout(`Commit it, then run \`agent-config-audit diff\` in CI to catch any later change.\n`);
      return 0;
    }

    if (command === 'diff') {
      let text: string;
      try {
        text = await read(lockPath);
      } catch {
        io.stderr(`agent-config-audit: no lockfile at ${lockPath}. Run \`agent-config-audit lock${dir === '.' ? '' : ` ${dir}`}\` first, review it and commit it.\n`);
        return 2;
      }
      const lock = parseLock(text);
      const current = await createLock(absDir, { exclude, maxFileBytes });
      const diff = compareLocks(lock, current);
      const render = (fmt: ReportFormat) => (fmt === 'json' ? `${JSON.stringify(diff, null, 2)}\n` : formatDiff(diff, { color }));
      if (!(await emit(render, `Wrote the diff to {path}: ${diff.changes.length} change(s).`))) return 2;
      return diff.clean ? 0 : 1;
    }

    let baseline: string[] | undefined;
    if (values.baseline) {
      let text: string;
      try {
        text = await read(resolve(cwd, values.baseline));
      } catch {
        return usage(`Cannot read the baseline file ${values.baseline}.`);
      }
      baseline = baselineFingerprints(text);
    }
    const report = await auditRepo(absDir, { only, exclude, baseline, maxFileBytes });
    report.root = dir;
    const render = (fmt: ReportFormat) => formatReport(report, fmt, { color, width: Math.min(120, io.columns ?? 100), fullInventory: values.all });
    const c = counts(report);
    if (!(await emit(render, `Wrote {format} report to {path}: ${c['fix-now']} fix now, ${c['should-fix']} should fix, ${c.review} review.`))) return 2;
    if (failOn) {
      const hits = report.findings.filter((f) => (FAIL_LEVELS[failOn] as Priority[]).includes(f.priority)).length;
      if (hits) {
        io.stderr(`agent-config-audit: ${hits} finding(s) at ${failOn}${failOn === 'should-fix' ? ' or above' : ''} (--fail-on).\n`);
        return 1;
      }
    }
    return 0;
  } catch (error) {
    if (error instanceof AuditError) {
      io.stderr(`agent-config-audit: ${error.message}\n`);
      return 2;
    }
    io.stderr(`agent-config-audit: unexpected error: ${(error as Error).stack ?? error}\n`);
    return 2;
  }
}

/** The format a file name asks for: .json, .md, .sarif, anything else text. */
function formatFromExtension(file: string): ReportFormat {
  const ext = extname(file).toLowerCase();
  return ext === '.json' ? 'json' : ext === '.md' || ext === '.markdown' ? 'md' : ext === '.sarif' ? 'sarif' : 'text';
}
