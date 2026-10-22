/**
 * Skill metadata against the Agent Skills spec, YAML type tags in any
 * frontmatter, and declared versus observed capability.
 */
import type { Model } from '../model.js';
import type { FmValue } from '../parse/frontmatter.js';
import { code } from '../text/safe.js';
import type { Emit } from './emit.js';
import { isBroadAllow } from './exec.js';

/** Fields the Agent Skills spec defines. */
export const SPEC_FIELDS = ['name', 'description', 'license', 'compatibility', 'metadata', 'allowed-tools'];
/** Further fields Claude Code documents for skills (frontmatter reference). */
export const CLAUDE_CODE_FIELDS = ['when_to_use', 'argument-hint', 'arguments', 'disable-model-invocation', 'user-invocable', 'disallowed-tools', 'model', 'effort', 'context', 'agent', 'background', 'hooks', 'paths', 'shell'];

const NAME = /^[\p{Ll}\p{Nd}]+(?:-[\p{Ll}\p{Nd}]+)*$/u;
const SCRIPT_EXT = /\.(?:sh|bash|zsh|fish|ps1|psm1|bat|cmd|py|js|mjs|cjs|ts|rb|pl|php|lua)$/i;
const NETWORK = /\b(?:curl|wget|Invoke-WebRequest|iwr|requests\.(?:get|post|put)|urllib\.request|http\.client|fetch\(|axios\.|net\.connect|socket\.connect)\b/;
const READ_ONLY_CLAIM = /\bread[- ]only\b|\bdoes(?: not|n['’]t) (?:run|execute|modify|write|change|access the network)\b|\bno (?:shell|network|code execution|side effects|commands)\b|\bnever (?:runs|executes|modifies|writes|changes)\b|\bwithout (?:running|executing) (?:any )?(?:code|commands)\b/i;

/** Tool names in an `allowed-tools` value (space-separated string or list). */
export function allowedTools(v: FmValue | undefined): string[] | null {
  if (v === undefined || v === null) return null;
  if (Array.isArray(v)) return v.map((x) => String(x).trim()).filter(Boolean);
  const s = String(v);
  return [...s.matchAll(/[A-Za-z_][\w:.-]*(?:\([^)]*\))?/g)].map((m) => m[0]);
}

export function skillChecks(model: Model, emit: Emit): void {
  for (const sk of model.skills) {
    const { fm, file } = sk;
    const dirName = sk.dir.slice(sk.dir.lastIndexOf('/') + 1);
    if (!fm.present) {
      emit('skill/no-frontmatter', { file, line: 1, title: `${file} has no frontmatter`, observed: 'The file does not start with a `---` YAML block.' });
      continue;
    }
    const closeErr = fm.errors.find((e) => e.includes('never closed'));
    if (closeErr) {
      emit('unscannable/parse-error', { file, line: 1, title: `Frontmatter of ${file} could not be read`, observed: closeErr });
      continue;
    }
    for (const e of fm.errors) emit('skill/invalid-field', { file, line: Number(/line (\d+)/.exec(e)?.[1] ?? 1), title: `Frontmatter problem in ${file}`, observed: e, evidence: e });

    const name = fm.data.name;
    const nameLine = fm.keyLines.name ?? 1;
    if (typeof name !== 'string' || !name.trim()) {
      emit('skill/invalid-name', { file, line: nameLine, title: `Skill in ${sk.dir} has no name`, observed: name === undefined ? 'No `name` field.' : `name = ${code(String(name), 40)}`, fix: `Add \`name: ${dirName}\`.`, evidence: 'missing' });
    } else {
      const problems: string[] = [];
      if (name.length > 64) problems.push(`is ${name.length} characters (max 64)`);
      if (!NAME.test(name)) problems.push('must use lowercase letters, digits and single hyphens, not starting or ending with a hyphen');
      if (name !== dirName) problems.push(`does not match its folder \`${dirName}\``);
      if (problems.length) emit('skill/invalid-name', { file, line: nameLine, title: `Skill name ${code(name, 40)} ${problems[0]}`, observed: `name = ${code(name, 70)}: ${problems.join('; ')}`, evidence: name });
    }

    const desc = fm.data.description;
    if (typeof desc !== 'string' || !desc.trim()) {
      emit('skill/invalid-field', { file, line: fm.keyLines.description ?? 1, title: `Skill ${code(String(name ?? dirName), 40)} has no description`, observed: desc === undefined ? 'No `description` field.' : 'The description is empty or not text.', fix: 'Add a description (1–1024 characters) that says what the skill does and when to use it.', evidence: 'description' });
    } else if (desc.length > 1024) {
      emit('skill/invalid-field', { file, line: fm.keyLines.description, title: `Skill description is ${desc.length} characters`, observed: `description is ${desc.length} characters (max 1024)`, evidence: 'description-length' });
    }
    const compat = fm.data.compatibility;
    if (compat !== undefined && (typeof compat !== 'string' || compat.length > 500)) {
      emit('skill/invalid-field', { file, line: fm.keyLines.compatibility, title: 'Skill `compatibility` is malformed', observed: typeof compat !== 'string' ? 'compatibility is not a string' : `compatibility is ${compat.length} characters (max 500)`, evidence: 'compatibility' });
    }
    const meta = fm.data.metadata;
    if (meta !== undefined && meta !== null) {
      const bad = typeof meta !== 'object' || Array.isArray(meta) ? ['(not a map)'] : Object.entries(meta).filter(([, v]) => typeof v !== 'string').map(([k]) => k);
      if (bad.length) emit('skill/invalid-field', { file, line: fm.keyLines.metadata, title: 'Skill `metadata` has non-string values', observed: `metadata keys with non-string values: ${bad.map((k) => code(k, 30)).join(', ')}`, fix: 'Quote the values so each is a string.', evidence: 'metadata' });
    }
    const unknown = Object.keys(fm.data).filter((k) => !SPEC_FIELDS.includes(k) && !CLAUDE_CODE_FIELDS.includes(k));
    if (unknown.length) emit('skill/unknown-field', { file, line: fm.keyLines[unknown[0] as string], title: `Skill frontmatter has field${unknown.length > 1 ? 's' : ''} no tool documents: ${unknown.slice(0, 4).join(', ')}`, observed: `fields: ${unknown.map((k) => code(k, 30)).join(', ')}`, evidence: unknown.sort().join(',') });

    // Declared versus observed capability.
    const tools = allowedTools(fm.data['allowed-tools']);
    const body = fm.body;
    const inlineShell = /!`[^`\n]+`|^```!/m.test(body);
    const scripts = sk.files.filter((p) => SCRIPT_EXT.test(p) || /^#!/.test(model.byPath.get(p)?.text?.slice(0, 2) ?? ''));
    const networkFiles = sk.files.filter((p) => NETWORK.test(model.byPath.get(p)?.text ?? ''));
    const toolLine = fm.keyLines['allowed-tools'];
    if (tools) {
      const broad = tools.filter(isBroadAllow);
      if (broad.length) emit('skill/allowed-tools-broad', { file, line: toolLine, key: 'allowed-tools', title: `Skill ${code(String(name ?? dirName), 40)} pre-approves ${code(broad[0] as string, 30)}`, observed: `allowed-tools includes ${broad.map((b) => code(b, 30)).join(', ')}`, evidence: broad.join(',') });
      const declaresShell = tools.some((t) => /^(?:Bash|PowerShell)\b/.test(t));
      if (!declaresShell && (inlineShell || scripts.length)) {
        emit('skill/allowed-tools-understated', {
          file,
          line: toolLine,
          key: 'allowed-tools',
          title: `Skill ${code(String(name ?? dirName), 40)} declares ${code(tools.join(' '), 40)} but ships shell`,
          observed: `allowed-tools = ${code(tools.join(' '), 80)}; ${[inlineShell ? 'inline `!` shell in SKILL.md' : '', scripts.length ? `${scripts.length} script file(s): ${scripts.slice(0, 3).map((p) => p.slice(sk.dir.length + 1)).join(', ')}` : ''].filter(Boolean).join('; ')}`,
          evidence: tools.join(' '),
        });
      }
    }
    if (typeof desc === 'string' && READ_ONLY_CLAIM.test(desc) && (inlineShell || scripts.length || networkFiles.length)) {
      const claim = (READ_ONLY_CLAIM.exec(desc) as RegExpExecArray)[0];
      const seen = [inlineShell ? 'inline `!` shell' : '', scripts.length ? `scripts (${scripts.slice(0, 3).map((p) => p.slice(sk.dir.length + 1)).join(', ')})` : '', networkFiles.length ? `network calls in ${networkFiles.slice(0, 3).map((p) => p.slice(sk.dir.length + 1)).join(', ')}` : ''].filter(Boolean);
      emit('skill/claims-read-only', { file, line: fm.keyLines.description, title: `Skill ${code(String(name ?? dirName), 40)} says ${code(claim, 30)} but ships ${seen[0]}`, observed: `description says ${code(claim, 40)}; the skill has ${seen.join(', ')}`, evidence: claim });
    }
  }

  // YAML type tags and allowed-tools in every frontmatter (skills, commands, agents, rules).
  for (const [file, fm] of model.frontmatter) {
    for (const t of fm.tags) emit('skill/unsafe-yaml', { file, line: t.line, title: `YAML type tag ${code(t.text, 40)} in ${file}`, observed: `frontmatter line ${t.line} uses ${code(t.text, 60)}`, evidence: t.text });
    if (model.byPath.get(file)?.role === 'command') {
      const broad = (allowedTools(fm.data['allowed-tools']) ?? []).filter(isBroadAllow);
      if (broad.length) emit('skill/allowed-tools-broad', { file, line: fm.keyLines['allowed-tools'], key: 'allowed-tools', title: `Command pre-approves ${code(broad[0] as string, 30)}`, observed: `allowed-tools includes ${broad.map((b) => code(b, 30)).join(', ')}`, evidence: broad.join(',') });
    }
  }
}
