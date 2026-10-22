/**
 * `agent-config.lock`: a reviewed snapshot of every agent surface. Each entry
 * has a content hash and a short, readable descriptor, so `diff` can say what
 * changed in plain words ("MCP server `x` command changed from … to …"). The
 * file is sorted, stable JSON with no timestamps, so it diffs cleanly in review.
 * Secret values are never stored: only their hashes.
 */
import { createHash } from 'node:crypto';
import { assertDirectory } from './audit.js';
import { describeSource } from './checks/exec.js';
import { discover, type DiscoverOptions } from './discover.js';
import { AuditError } from './errors.js';
import { readBytes } from './fs/walk.js';
import type { Model } from './model.js';
import { isObject, isString, stringArray } from './parse/json.js';
import { extractUrls } from './text/patterns.js';
import { safe } from './text/safe.js';
import { SECRET_KEY } from './text/secrets.js';
import { PACKAGE_NAME } from './version.js';

/** The lockfile's default name, at the repository root. */
export const LOCKFILE_NAME = 'agent-config.lock';

/** One locked surface. Fields beyond `kind`, `path` and `sha256` depend on the kind. */
export interface LockEntry {
  kind: 'file' | 'skill' | 'hook' | 'helper' | 'mcp-server' | 'env' | 'setting' | 'plugin-source';
  path: string;
  sha256: string;
  name?: string;
  [field: string]: string | string[] | Record<string, string> | boolean | undefined;
}

export interface Lockfile {
  lockfileVersion: 1;
  generator: string;
  entries: Record<string, LockEntry>;
}

/** A change between a lockfile and the repository today. */
export interface LockChange {
  type: 'added' | 'removed' | 'changed';
  key: string;
  kind: LockEntry['kind'];
  /** One plain sentence. */
  message: string;
  /** Further sentences for the same entry (e.g. each file a skill gained). */
  details?: string[];
}

export interface LockDiff {
  changes: LockChange[];
  /** True when nothing changed. */
  clean: boolean;
}

const sha = (s: string | Buffer) => createHash('sha256').update(s).digest('hex');
const short = (s: string) => `sha256:${sha(s).slice(0, 16)}`;
const urlsOf = (text: string) => [...new Set(extractUrls(text).map((u) => safe(u.url, 300)))].sort();

/** Builds the lockfile for a model. */
export async function lockFromModel(model: Model): Promise<Lockfile> {
  const entries: Record<string, LockEntry> = {};
  const skillDirs = new Set(model.skills.map((s) => s.dir));
  const inSkill = (p: string) => [...skillDirs].some((d) => p.startsWith(`${d}/`));

  const fileHash = async (path: string): Promise<string> => {
    const f = model.byPath.get(path);
    if (f?.sha256) return f.sha256;
    if (f?.linkTarget) return sha(`symlink:${f.linkTarget}`);
    if (f?.unread?.reason === 'symlink') return sha(`symlink:${f.unread.detail}`);
    try {
      return sha(await readBytes(model.root, path));
    } catch {
      return sha(`unreadable:${path}`);
    }
  };

  for (const f of model.files) {
    if (inSkill(f.path) || f.role === 'skill') continue;
    entries[`file:${f.path}`] = {
      kind: 'file',
      path: f.path,
      role: f.role,
      sha256: await fileHash(f.path),
      ...(f.linkTarget ? { linkTarget: f.linkTarget } : {}),
      ...(f.unread ? { unread: f.unread.reason } : {}),
      ...(f.text ? { urls: urlsOf(f.text) } : {}),
    };
  }

  for (const sk of model.skills) {
    const files: Record<string, string> = {};
    const urls = new Set<string>();
    for (const p of sk.files) {
      const h = await fileHash(p);
      files[p.slice(sk.dir.length + 1)] = h.slice(0, 16);
      for (const u of urlsOf(model.byPath.get(p)?.text ?? '')) urls.add(u);
    }
    const tree = Object.keys(files).sort().map((k) => `${k}\0${files[k]}`).join('\n');
    const name = typeof sk.fm.data.name === 'string' ? sk.fm.data.name : sk.dir.slice(sk.dir.lastIndexOf('/') + 1);
    const at = sk.fm.data['allowed-tools'];
    entries[`skill:${sk.dir}`] = {
      kind: 'skill',
      path: sk.dir,
      name: safe(name, 80),
      sha256: sha(tree),
      files,
      ...(at !== undefined && at !== null ? { allowedTools: safe(Array.isArray(at) ? at.join(' ') : String(at), 300) } : {}),
      urls: [...urls].sort(),
    };
  }

  const counters = new Map<string, number>();
  for (const h of model.hooks) {
    const base = `hook:${h.file}:${h.event}:${h.matcher ?? '*'}`;
    const n = counters.get(base) ?? 0;
    counters.set(base, n + 1);
    const text = h.command ?? h.url ?? h.type;
    entries[`${base}:${n}`] = {
      kind: 'hook',
      path: h.file,
      name: h.event,
      tool: h.tool,
      type: h.type,
      ...(h.matcher !== undefined ? { matcher: safe(h.matcher, 100) } : {}),
      ...(h.command ? { command: safe(h.command, 300) } : {}),
      ...(h.url ? { url: safe(h.url, 300) } : {}),
      sha256: sha(text),
    };
  }
  for (const h of model.helpers) {
    entries[`helper:${h.file}:${h.key}`] = { kind: 'helper', path: h.file, name: h.key, command: safe(h.command, 300), sha256: sha(h.command) };
  }

  for (const s of model.servers) {
    const env: Record<string, string> = {};
    for (const k of Object.keys(s.env).sort()) env[k] = short(s.env[k] as string);
    const headers: Record<string, string> = {};
    for (const k of Object.keys(s.headers).sort()) headers[k] = short(s.headers[k] as string);
    const spec = JSON.stringify({ transport: s.transport, command: s.command ?? '', args: s.args, url: s.url ?? '', env: s.env, headers: s.headers, headersHelper: s.headersHelper ?? '', trust: s.trust ?? null });
    entries[`mcp:${s.file}:${s.name}`] = {
      kind: 'mcp-server',
      path: s.file,
      name: safe(s.name, 100),
      tool: s.tool,
      transport: s.transport,
      ...(s.command ? { command: safe(s.command, 300) } : {}),
      args: s.args.map((a) => safe(a, 300)),
      ...(s.url ? { url: safe(s.url, 300) } : {}),
      env,
      headers,
      ...(s.headersHelper ? { headersHelper: safe(s.headersHelper, 300) } : {}),
      ...(s.trust !== undefined ? { trust: s.trust } : {}),
      sha256: sha(spec),
    };
  }

  for (const st of model.settings) {
    if (isObject(st.json.env)) {
      for (const [k, v] of Object.entries(st.json.env)) {
        const value = String(v);
        entries[`env:${st.file}:${k}`] = { kind: 'env', path: st.file, name: k, value: SECRET_KEY.test(k) ? short(value) : safe(value, 300), sha256: sha(value) };
      }
    }
    const settings: [string, unknown][] = [];
    if (isObject(st.json.permissions)) {
      const p = st.json.permissions;
      settings.push(['permissions', { allow: stringArray(p.allow), ask: stringArray(p.ask), deny: stringArray(p.deny), defaultMode: isString(p.defaultMode) ? p.defaultMode : '' }]);
    }
    for (const key of ['enableAllProjectMcpServers', 'enabledMcpjsonServers', 'disabledMcpjsonServers', 'enabledPlugins', 'extraKnownMarketplaces', 'disableAllHooks']) {
      if (key in st.json) settings.push([key, st.json[key]]);
    }
    for (const [key, value] of settings) {
      const json = stableStringify(value);
      entries[`setting:${st.file}:${key}`] = { kind: 'setting', path: st.file, name: key, value: safe(json, 1000), sha256: sha(json) };
    }
  }

  for (const m of model.marketplaces) {
    if (!isObject(m.json) || !Array.isArray(m.json.plugins)) continue;
    for (const p of m.json.plugins) {
      if (!isObject(p) || !isString(p.name)) continue;
      const src = describeSource(p.source);
      entries[`plugin-source:${m.file}:${p.name}`] = { kind: 'plugin-source', path: m.file, name: safe(p.name, 100), source: safe(src, 300), sha256: sha(stableStringify(p.source ?? null)) };
    }
  }

  const sorted: Record<string, LockEntry> = {};
  for (const k of Object.keys(entries).sort()) sorted[k] = entries[k] as LockEntry;
  return { lockfileVersion: 1, generator: PACKAGE_NAME, entries: sorted };
}

/** Builds the lockfile for the repository in `dir`. */
export async function createLock(dir = '.', options: DiscoverOptions = {}): Promise<Lockfile> {
  const root = await assertDirectory(dir);
  return lockFromModel(await discover(root, options));
}

/** JSON with object keys sorted at every level. */
export function stableStringify(value: unknown, indent?: number): string {
  const norm = (v: unknown): unknown => {
    if (Array.isArray(v)) return v.map(norm);
    if (v && typeof v === 'object') {
      const out: Record<string, unknown> = {};
      for (const k of Object.keys(v as object).sort()) out[k] = norm((v as Record<string, unknown>)[k]);
      return out;
    }
    return v;
  };
  return JSON.stringify(norm(value), null, indent);
}

/** The lockfile as written to disk: sorted, two-space JSON with a final newline. */
export function formatLock(lock: Lockfile): string {
  return `${stableStringify(lock, 2)}\n`;
}

/** Parses and validates a lockfile's text. */
export function parseLock(text: string): Lockfile {
  let v: unknown;
  try {
    v = JSON.parse(text);
  } catch (error) {
    throw new AuditError(`The lockfile is not valid JSON: ${(error as Error).message}`);
  }
  if (!v || typeof v !== 'object' || (v as Lockfile).lockfileVersion !== 1 || typeof (v as Lockfile).entries !== 'object') {
    throw new AuditError('Not an agent-config.lock file (expected lockfileVersion 1 and an entries object).');
  }
  return v as Lockfile;
}

const KIND_NAMES: Record<LockEntry['kind'], string> = {
  file: 'file',
  skill: 'skill',
  hook: 'hook',
  helper: 'helper command',
  'mcp-server': 'MCP server',
  env: 'env variable',
  setting: 'setting',
  'plugin-source': 'plugin source',
};

const q = (s: unknown) => `\`${String(s ?? '')}\``;

function label(e: LockEntry): string {
  switch (e.kind) {
    case 'file':
      return `file ${q(e.path)}`;
    case 'skill':
      return `skill ${q(e.name)} (${e.path})`;
    case 'hook':
      return `${e.tool ?? ''} hook ${q(e.name)}${e.matcher ? ` [matcher ${q(e.matcher)}]` : ''} in ${e.path}`.trim();
    case 'mcp-server':
      return `MCP server ${q(e.name)} in ${e.path}`;
    case 'env':
      return `env ${q(e.name)} in ${e.path}`;
    default:
      return `${KIND_NAMES[e.kind]} ${q(e.name)} in ${e.path}`;
  }
}

function describeNew(e: LockEntry): string {
  switch (e.kind) {
    case 'mcp-server':
      return e.url ? `${e.transport} ${q(e.url)}` : `${e.transport} ${q([e.command, ...((e.args as string[]) ?? [])].filter(Boolean).join(' '))}`;
    case 'hook':
      return e.command ? `runs ${q(e.command)}` : e.url ? `posts to ${q(e.url)}` : `${e.type} hook`;
    case 'helper':
      return `runs ${q(e.command)}`;
    case 'skill':
      return `${Object.keys((e.files as Record<string, string>) ?? {}).length} file(s)${e.allowedTools ? `, allowed-tools ${q(e.allowedTools)}` : ''}`;
    case 'env':
    case 'setting':
      return `= ${q(e.value)}`;
    case 'plugin-source':
      return `from ${q(e.source)}`;
    default:
      return e.unread ? `(not readable: ${e.unread})` : '';
  }
}

function diffRecord(name: string, before: Record<string, string> = {}, after: Record<string, string> = {}): string[] {
  const out: string[] = [];
  for (const k of Object.keys(after)) if (!(k in before)) out.push(`gained ${name} ${q(k)}`);
  for (const k of Object.keys(before)) if (!(k in after)) out.push(`lost ${name} ${q(k)}`);
  for (const k of Object.keys(after)) if (k in before && before[k] !== after[k]) out.push(`${name} ${q(k)} changed`);
  return out;
}

function describeChange(a: LockEntry, b: LockEntry): string[] {
  const out: string[] = [];
  const field = (f: string, what = f) => {
    const x = stableStringify(a[f] ?? null);
    const y = stableStringify(b[f] ?? null);
    if (x !== y) {
      const fmt = (v: unknown) => (v === undefined || v === null ? '(none)' : Array.isArray(v) ? q(v.join(' ')) : q(v));
      out.push(`${what} changed from ${fmt(a[f])} to ${fmt(b[f])}`);
    }
  };
  switch (b.kind) {
    case 'mcp-server':
      field('transport');
      field('command');
      field('args');
      field('url');
      field('headersHelper');
      field('trust');
      out.push(...diffRecord('env', a.env as Record<string, string>, b.env as Record<string, string>).map((s) => s.replace(/changed$/, 'value changed')));
      out.push(...diffRecord('header', a.headers as Record<string, string>, b.headers as Record<string, string>).map((s) => s.replace(/changed$/, 'value changed')));
      break;
    case 'hook':
      field('type');
      field('command');
      field('url');
      if (!out.length) out.push('command changed (beyond the first 300 characters stored in the lock)');
      break;
    case 'helper':
      field('command');
      if (!out.length) out.push('command changed (beyond the first 300 characters stored in the lock)');
      break;
    case 'skill':
      field('name');
      field('allowedTools', 'allowed-tools');
      out.push(...diffRecord('file', a.files as Record<string, string>, b.files as Record<string, string>));
      break;
    case 'env':
      if (String(a.value ?? '').startsWith('sha256:') || String(b.value ?? '').startsWith('sha256:')) out.push('value changed');
      else field('value');
      break;
    case 'setting':
      field('value');
      break;
    case 'plugin-source':
      field('source');
      break;
    case 'file':
      out.push('content changed');
      if (a.linkTarget !== b.linkTarget) out.push(`link target changed from ${q(a.linkTarget ?? '(none)')} to ${q(b.linkTarget ?? '(none)')}`);
      break;
  }
  if (b.kind === 'file' || b.kind === 'skill') {
    const before = new Set((a.urls as string[]) ?? []);
    const after = new Set((b.urls as string[]) ?? []);
    for (const u of after) if (!before.has(u)) out.push(`now references ${q(u)}`);
    for (const u of before) if (!after.has(u)) out.push(`no longer references ${q(u)}`);
  }
  return out;
}

/** Compares two lockfiles. */
export function compareLocks(before: Lockfile, after: Lockfile): LockDiff {
  const changes: LockChange[] = [];
  const keys = [...new Set([...Object.keys(before.entries), ...Object.keys(after.entries)])].sort();
  for (const key of keys) {
    const a = before.entries[key];
    const b = after.entries[key];
    if (!a && b) {
      const what = describeNew(b);
      changes.push({ type: 'added', key, kind: b.kind, message: `New ${label(b)}${what ? `: ${what}` : ''}` });
    } else if (a && !b) {
      changes.push({ type: 'removed', key, kind: a.kind, message: `Removed ${label(a)}` });
    } else if (a && b && stableStringify(a) !== stableStringify(b)) {
      const parts = describeChange(a, b);
      const [first, ...rest] = parts.length ? parts : ['changed'];
      changes.push({ type: 'changed', key, kind: b.kind, message: `${label(b).replace(/^./, (c) => c.toUpperCase())} ${first}`, ...(rest.length ? { details: rest } : {}) });
    }
  }
  // A config file's "content changed" says nothing new when an entry parsed from it already explains the change.
  const explained = new Set(changes.filter((c) => c.kind !== 'file').map((c) => (after.entries[c.key] ?? before.entries[c.key])?.path));
  const kept = changes.filter((c) => !(c.kind === 'file' && c.type === 'changed' && !c.details?.length && explained.has(after.entries[c.key]?.path)));
  return { changes: kept, clean: kept.length === 0 };
}

/** `3 MCP servers`, `1 file`: for summaries. */
export function countKinds(lock: Lockfile): string {
  const names: Record<LockEntry['kind'], [string, string]> = {
    file: ['file', 'files'],
    skill: ['skill', 'skills'],
    hook: ['hook', 'hooks'],
    helper: ['helper command', 'helper commands'],
    'mcp-server': ['MCP server', 'MCP servers'],
    env: ['env variable', 'env variables'],
    setting: ['setting', 'settings'],
    'plugin-source': ['plugin source', 'plugin sources'],
  };
  const counts = new Map<LockEntry['kind'], number>();
  for (const e of Object.values(lock.entries)) counts.set(e.kind, (counts.get(e.kind) ?? 0) + 1);
  return [...counts].sort((a, b) => b[1] - a[1]).map(([k, n]) => `${n} ${names[k][n === 1 ? 0 : 1]}`).join(', ');
}

/** Compares a lockfile with the repository in `dir` today. */
export async function diffLock(dir: string, lock: Lockfile, options: DiscoverOptions = {}): Promise<LockDiff> {
  return compareLocks(lock, await createLock(dir, options));
}

/** Renders a diff for a terminal or a log. */
export function formatDiff(diff: LockDiff, options: { color?: boolean } = {}): string {
  const on = options.color ?? false;
  const esc = (c: string) => (s: string) => (on ? `\u001b[${c}m${s}\u001b[0m` : s);
  const green = esc('32');
  const red = esc('31');
  const yellow = esc('33');
  if (diff.clean) return `${green('No changes')} since ${LOCKFILE_NAME}.\n`;
  const lines = [`${diff.changes.length} change${diff.changes.length === 1 ? '' : 's'} since ${LOCKFILE_NAME}:`, ''];
  for (const c of diff.changes) {
    const mark = c.type === 'added' ? green('+') : c.type === 'removed' ? red('-') : yellow('~');
    lines.push(`${mark} ${c.message}`);
    for (const d of c.details ?? []) lines.push(`    ${d}`);
  }
  lines.push('', `Review these changes, then run \`agent-config-audit lock\` to approve them.`);
  return `${lines.join('\n')}\n`;
}
