/**
 * Files this run could not check, and context hygiene: size budgets each tool
 * documents, AGENTS.md hidden by CLAUDE files, dead paths, directory trees.
 */
import type { Model, ScannedFile } from '../model.js';
import { code } from '../text/safe.js';
import type { Emit } from './emit.js';

const MEDIA = /\.(?:png|jpe?g|gif|webp|bmp|ico|tiff?|heic|avif|pdf|mp3|wav|ogg|m4a|flac|mp4|mov|webm|mkv|avi|woff2?|ttf|otf|eot)$/i;

export function unscannableChecks(model: Model, emit: Emit): void {
  for (const f of model.files) {
    const u = f.unread;
    if (!u) continue;
    const base = { file: f.path, observed: `${u.detail}${f.tools.length ? `; read by ${f.tools.join(', ')}` : ''}`, evidence: u.reason };
    if (u.reason === 'binary' && MEDIA.test(f.path)) emit('unscannable/media', { ...base, title: `${f.path} was not checked (media file)` });
    else if (u.reason === 'binary') emit('unscannable/binary', { ...base, title: `${f.path} is binary: needs human review` });
    else if (u.reason === 'archive') emit('unscannable/archive', { ...base, title: `${f.path} is an archive: needs human review` });
    else if (u.reason === 'bytecode') emit('unscannable/bytecode', { ...base, title: `${f.path} is compiled bytecode: needs human review` });
    else if (u.reason === 'too-large') emit('unscannable/too-large', { ...base, title: `${f.path} is too large to check: needs human review` });
    else if (u.reason === 'symlink') emit('unscannable/symlink', { ...base, title: `${f.path} is a symlink that was not followed` });
    else emit('unscannable/parse-error', { ...base, title: `${f.path} could not be ${u.reason === 'parse-error' ? 'parsed' : 'read'}: needs human review`, ...(u.reason === 'parse-error' ? { line: Number(/line (\d+)/.exec(u.detail)?.[1] ?? 0) || undefined } : {}) });
  }
}

const countLines = (t: string) => (t.endsWith('\n') ? t.split('\n').length - 1 : t.split('\n').length);
const dirOf = (p: string) => (p.includes('/') ? p.slice(0, p.lastIndexOf('/')) : '');
const join = (dir: string, name: string) => (dir ? `${dir}/${name}` : name);

/** Directories from `dir` up to the repo root, nearest first. */
function upward(dir: string): string[] {
  const out = [dir];
  for (let d = dir; d; ) {
    d = dirOf(d);
    out.push(d);
  }
  return out;
}

/** Extensions tried for module-style references such as `src/lib/copy`. */
const MODULE_EXT = ['', '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.json', '.md', '/index.ts', '/index.tsx', '/index.js'];
const INSTRUCTION_ROLES = new Set(['instructions', 'skill', 'command', 'agent']);
const SKIP_SEGMENTS = new Set(['node_modules', 'dist', 'build', '.next', 'coverage', 'out', 'target', '.turbo', '.cache', 'vendor']);
const CODE_EXT = /\.(?:md|mdc|ts|tsx|js|jsx|mjs|cjs|json|jsonc|ya?ml|toml|py|sh|css|scss|html|sql|go|rs|rb|java|kt|swift|txt|env\.example|lock)$/i;

/** Paths an instruction file points at: `@imports`, relative Markdown links, and backticked repo paths. */
export function referencedRepoPaths(text: string): { path: string; index: number; kind: 'import' | 'link' | 'code' }[] {
  const out: { path: string; index: number; kind: 'import' | 'link' | 'code' }[] = [];
  // Blank out fenced code blocks: they hold commands and examples, not references.
  const prose = text.replace(/^(```|~~~)[^\n]*\n[\s\S]*?^\1[^\n]*$/gm, (m) => m.replace(/[^\n]/g, ' '));
  for (const m of prose.matchAll(/(?:^|\s)@((?:\.{1,2}\/)?[\w.-]+(?:\/[\w.-]+)*\.[A-Za-z]{1,8})(?=$|[\s),;:])/gm)) out.push({ path: m[1] as string, index: (m.index ?? 0) + m[0].indexOf('@'), kind: 'import' });
  for (const m of prose.matchAll(/\]\(\s*<?([^)\s>#?]+)(?:[#?][^)\s]*)?>?(?:\s+"[^"]*")?\s*\)/g)) {
    const p = m[1] as string;
    if (/^[a-z][a-z0-9+.-]*:/i.test(p) || p.startsWith('/') || p.startsWith('#')) continue;
    out.push({ path: decodeURI(p), index: m.index ?? 0, kind: 'link' });
  }
  for (const m of prose.matchAll(/`([^`\s]+)`/g)) {
    const p = m[1] as string;
    if (/[*?[\]{}<>$|"'=:,;()!]/.test(p) || p.startsWith('-') || p.startsWith('/') || p.startsWith('~') || p.startsWith('@') || p.includes('://') || p.includes('...')) continue;
    if (!(p.includes('/') || CODE_EXT.test(p))) continue;
    if (/^\.?\.?\/?$/.test(p) || /^v?\d+(?:\.\d+)+/.test(p)) continue;
    out.push({ path: p, index: m.index ?? 0, kind: 'code' });
  }
  return out;
}

export function hygieneChecks(model: Model, emit: Emit): void {
  const read = (f: ScannedFile) => f.text ?? '';
  for (const f of model.files) {
    if (f.text === undefined) continue;
    const t = f.text;
    const lines = countLines(t);
    const bytes = Buffer.byteLength(t, 'utf8');
    if ((f.kind === 'claude-md' || f.kind === 'claude-local') && lines > 200) emit('hygiene/claude-md-size', { file: f.path, title: `${f.path} is ${lines} lines`, observed: `${lines} lines (Claude Code's guidance: under 200)`, evidence: 'size' });
    if (f.role === 'skill' && lines > 500) emit('hygiene/skill-size', { file: f.path, title: `${f.path} is ${lines} lines`, observed: `${lines} lines (spec guidance: under 500)`, evidence: 'size' });
    if (f.kind === 'cursor-rule' && lines > 500) emit('hygiene/cursor-rule-size', { file: f.path, title: `${f.path} is ${lines} lines`, observed: `${lines} lines (Cursor's guidance: under 500)`, evidence: 'size' });
    if ((f.kind === 'copilot' || f.kind === 'copilot-path') && lines > 1000) emit('hygiene/copilot-size', { file: f.path, title: `${f.path} is ${lines} lines`, observed: `${lines} lines (GitHub's guidance: about 1,000 at most)`, evidence: 'size' });
    if (f.kind === 'windsurf-rule' && t.length > 12_000) emit('hygiene/windsurf-rule-size', { file: f.path, title: `${f.path} is ${t.length.toLocaleString('en-US')} characters`, observed: `${t.length.toLocaleString('en-US')} characters (limit: 12,000 per workspace rule file)`, evidence: 'size' });
    if (f.kind === 'antigravity-rule' && bytes > 24_000) emit('hygiene/antigravity-rule-size', { file: f.path, title: `${f.path} is ${bytes.toLocaleString('en-US')} bytes`, observed: `${bytes.toLocaleString('en-US')} bytes (limit: 24,000 per file)`, evidence: 'size' });
    if (f.kind === 'cursor-rule-ignored') emit('hygiene/cursor-rule-ignored', { file: f.path, title: `${f.path} is ignored by Cursor (not .mdc)`, observed: 'A `.md` file inside `.cursor/rules`.', evidence: 'ext' });
  }

  // AGENTS.md: Codex's 32 KiB budget, per file and down the directory chain.
  const agents = model.files.filter((f) => f.path.endsWith('AGENTS.md') && f.kind === 'agents-md' && f.text !== undefined);
  for (const f of agents) {
    const own = Buffer.byteLength(read(f), 'utf8');
    const chain = upward(dirOf(f.path)).map((d) => model.byPath.get(join(d, 'AGENTS.md'))).filter((x): x is ScannedFile => !!x && x.text !== undefined);
    const total = chain.reduce((n, x) => n + Buffer.byteLength(read(x), 'utf8'), 0);
    if (own > 32_768) emit('hygiene/agents-md-size', { file: f.path, title: `${f.path} is ${(own / 1024).toFixed(1)} KiB`, observed: `${own.toLocaleString('en-US')} bytes; Codex reads at most 32 KiB of AGENTS.md files by default`, evidence: 'own' });
    else if (chain.length > 1 && total > 32_768) emit('hygiene/agents-md-size', { file: f.path, title: `${f.path} and the AGENTS.md files above it total ${(total / 1024).toFixed(1)} KiB`, observed: `${chain.map((x) => x.path).join(' + ')} = ${total.toLocaleString('en-US')} bytes; Codex stops adding files at 32 KiB`, evidence: 'chain' });
  }

  // Claude Code skips an AGENTS.md when its directory has a CLAUDE.md, .claude/CLAUDE.md or CLAUDE.local.md.
  // (Files further up count too at session start; only the same directory is checked here, where the docs leave no doubt.)
  for (const f of agents) {
    const dirs = [dirOf(f.path)];
    const claudeMd = dirs.flatMap((d) => [join(d, 'CLAUDE.md'), join(d, '.claude/CLAUDE.md')]).filter((p) => model.paths.has(p));
    const local = dirs.map((d) => join(d, 'CLAUDE.local.md')).filter((p) => model.paths.has(p));
    if (!claudeMd.length && !local.length) continue;
    const imports = claudeMd.some((p) => {
      const cf = model.byPath.get(p);
      if (cf?.linkTarget?.endsWith('AGENTS.md')) return true;
      return /(?:^|\s)@(?:\.\/)?(?:[\w.-]+\/)*AGENTS\.md\b/m.test(cf?.text ?? '');
    });
    if (imports) continue;
    if (!claudeMd.length) {
      emit('hygiene/agents-md-hidden-by-local', { file: local[0] as string, title: `${local[0]} stops Claude Code from reading ${f.path}`, observed: `${local[0]} exists and no CLAUDE.md imports ${f.path}, so Claude Code reads only the CLAUDE.local.md`, evidence: f.path });
    } else {
      emit('hygiene/agents-md-not-imported', { file: claudeMd[0] as string, title: `Claude Code reads ${claudeMd[0]}, not ${f.path}`, observed: `${claudeMd.join(', ')}${local.length ? ` and ${local.join(', ')}` : ''} exist without an \`@AGENTS.md\` import, so Claude Code skips ${f.path}`, evidence: f.path });
    }
  }

  // Dead references and directory trees in instruction files.
  const basenames = new Set([...model.paths].map((p) => p.slice(p.lastIndexOf('/') + 1)));
  const exists = (p: string) => model.paths.has(p) || model.dirs.has(p);
  const baseOf = (x: string) => x.slice(x.lastIndexOf('/') + 1);
  const byBase = new Map<string, string[]>();
  for (const x of [...model.paths, ...model.dirs]) {
    const list = byBase.get(baseOf(x));
    if (list) list.push(x);
    else byBase.set(baseOf(x), [x]);
  }
  for (const f of model.files) {
    if (f.text === undefined || !INSTRUCTION_ROLES.has(f.role) || !/\.(?:md|mdc)$/i.test(f.path)) continue;
    const dir = dirOf(f.path);
    const dead: { path: string; line: number }[] = [];
    const seen = new Set<string>();
    const lineAt = (i: number) => f.text!.slice(0, i).split('\n').length;
    for (const r of referencedRepoPaths(f.text)) {
      const p = r.path.replace(/\/+$/, '').replace(/^\.\//, '');
      if (!p || seen.has(p) || p.split('/').some((s) => SKIP_SEGMENTS.has(s))) continue;
      seen.add(p);
      const norm = (base: string) => {
        const parts: string[] = [];
        for (const s of (base ? `${base}/${p}` : p).split('/')) {
          if (s === '..') parts.pop();
          else if (s && s !== '.') parts.push(s);
        }
        return parts.join('/');
      };
      const candidates = [norm(dir), norm('')];
      if (candidates.some((c) => MODULE_EXT.some((e) => exists(c + e)))) continue;
      // Paths written relative to some sub-project ("`src/lib/copy`" in a monorepo's notes): any file that ends with it counts.
      if (MODULE_EXT.some((e) => (byBase.get(baseOf(`${p}${e}`)) ?? []).some((x) => x.endsWith(`/${p}${e}`))) || (byBase.get(baseOf(p)) ?? []).some((d) => d.endsWith(`/${p}`))) continue;
      if (r.kind === 'code' && p.startsWith('..')) continue;
      if (r.kind === 'code') {
        if (!p.includes('/')) {
          if (basenames.has(p)) continue;
          if (!CODE_EXT.test(p)) continue;
        } else {
          // Only paths that start in this repo: the first segment must exist next to the file or at the root.
          const first = p.split('/')[0] as string;
          if (first !== '..' && !exists(join(dir, first)) && !exists(first)) continue;
        }
      }
      dead.push({ path: p, line: lineAt(r.index) });
    }
    if (dead.length) {
      emit('hygiene/dead-reference', {
        file: f.path,
        line: (dead[0] as { line: number }).line,
        title: `${f.path} points at ${dead.length === 1 ? code((dead[0] as { path: string }).path, 60) : `${dead.length} paths`} that do${dead.length === 1 ? 'es' : ''} not exist`,
        observed: dead.slice(0, 5).map((d) => `${code(d.path, 60)} (line ${d.line})`).join(', ') + (dead.length > 5 ? `, and ${dead.length - 5} more` : ''),
        evidence: dead.map((d) => d.path).sort().join(','),
        details: dead.length > 5 ? dead.map((d) => `line ${d.line}: ${d.path}`) : undefined,
      });
    }
    const tree = f.text.split('\n').filter((l) => /^[\s│|]*(?:├──|└──|\|--|`--)\s/.test(l)).length;
    if (tree >= 8 && f.role === 'instructions') emit('hygiene/directory-tree', { file: f.path, title: `${f.path} contains a ${tree}-line directory tree`, observed: `${tree} lines drawn with ├── / └──`, evidence: 'tree' });
  }
}
