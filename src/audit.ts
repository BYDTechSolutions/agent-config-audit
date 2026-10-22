/**
 * `auditRepo`: discover every agent surface, run the rules, and return a
 * report. Offline; nothing found is executed, imported or fetched.
 */
import { stat } from 'node:fs/promises';
import { resolve } from 'node:path';
import { makeFinding, type Emit } from './checks/emit.js';
import { execChecks } from './checks/exec.js';
import { hygieneChecks, unscannableChecks } from './checks/hygiene.js';
import { mcpChecks } from './checks/mcp.js';
import { skillChecks } from './checks/skill.js';
import { textChecks } from './checks/text.js';
import { discover } from './discover.js';
import { AuditError } from './errors.js';
import { buildCoverage, buildInventory } from './inventory.js';
import type { Model } from './model.js';
import { FAMILIES, PRIORITIES, type AuditOptions, type Finding, type Report } from './types.js';
import { PACKAGE_NAME, REPO_URL, VERSION } from './version.js';

/** Throws {@link AuditError} unless `dir` is a directory. */
export async function assertDirectory(dir: string): Promise<string> {
  const abs = resolve(dir);
  let s;
  try {
    s = await stat(abs);
  } catch {
    throw new AuditError(`No such directory: ${dir}`);
  }
  if (!s.isDirectory()) throw new AuditError(`Not a directory: ${dir}`);
  return abs;
}

/** Runs every check on a model and returns the findings, de-duplicated and sorted. */
export function runChecks(model: Model): Finding[] {
  const findings: Finding[] = [];
  const emit: Emit = (id, input) => findings.push(makeFinding(id, input));
  for (const check of [execChecks, mcpChecks, textChecks, skillChecks, unscannableChecks, hygieneChecks]) check(model, emit);

  // One finding per fingerprint; a credential already reported by a config rule is not repeated as a generic one.
  const seen = new Set<string>();
  const configSecretLines = new Set(findings.filter((f) => f.id === 'mcp/inline-secret' || f.id === 'secrets/env-literal').map((f) => `${f.file}:${f.line}`));
  const out = findings.filter((f) => {
    if (seen.has(f.fingerprint)) return false;
    seen.add(f.fingerprint);
    if (f.id === 'secrets/hardcoded' && configSecretLines.has(`${f.file}:${f.line}`)) return false;
    return true;
  });
  const pr = (f: Finding) => PRIORITIES.indexOf(f.priority);
  const fam = (f: Finding) => FAMILIES.indexOf(f.family);
  return out.sort((a, b) => pr(a) - pr(b) || fam(a) - fam(b) || (a.file < b.file ? -1 : a.file > b.file ? 1 : 0) || (a.line ?? 0) - (b.line ?? 0) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
}

/**
 * Audits the agent configuration in `dir`: Claude Code settings, hooks, skills,
 * commands, subagents and plugins; MCP configs for Claude Code, Cursor, VS Code,
 * Gemini CLI and Codex; Cursor, Copilot, Devin Desktop and Antigravity rules;
 * AGENTS.md, CLAUDE.md and GEMINI.md at every level.
 *
 * The report has no score and never says "safe": it lists what is there, what
 * can run, what is unpinned or hidden, and what this version cannot assess.
 */
export async function auditRepo(dir = '.', options: AuditOptions = {}): Promise<Report> {
  const started = Date.now();
  const root = await assertDirectory(dir);
  const model = await discover(root, options);
  const families = options.only?.length ? FAMILIES.filter((f) => options.only?.includes(f)) : [...FAMILIES];
  let findings = runChecks(model).filter((f) => families.includes(f.family));
  const baseline = new Set(options.baseline ?? []);
  const before = findings.length;
  if (baseline.size) findings = findings.filter((f) => !baseline.has(f.fingerprint));
  const inventory = buildInventory(model);
  const notes: string[] = [];
  if (model.walkTruncated) notes.push(`Stopped listing files after ${model.filesSeen.toLocaleString('en-US')} (maxFiles). Files after that were not checked.`);
  if (!model.files.length) notes.push('No agent configuration was found here. Looked for Claude Code (.claude/, CLAUDE.md, .mcp.json), Cursor (.cursor/), VS Code (.vscode/mcp.json), GitHub Copilot (.github/), Gemini CLI (.gemini/, GEMINI.md), Codex (.codex/, AGENTS.md), Devin Desktop/Windsurf and Antigravity rules, Agent Skills (SKILL.md) and Claude Code plugins.');
  return {
    tool: { name: PACKAGE_NAME, version: VERSION, url: REPO_URL },
    root: dir,
    startedAt: new Date(started).toISOString(),
    durationMs: Date.now() - started,
    families,
    findings,
    suppressed: before - findings.length,
    inventory,
    coverage: buildCoverage(model),
    stats: { filesSeen: model.filesSeen, filesRead: model.files.filter((f) => f.text !== undefined).length, surfaces: inventory.length },
    notes,
  };
}
