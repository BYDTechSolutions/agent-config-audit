/**
 * Finds every agent surface in a repository, reads each file as bytes, and
 * parses configs into a {@link Model}. Nothing found is ever run, imported or
 * fetched: commands are kept as text.
 */
import { createHash } from 'node:crypto';
import { inspect } from './fs/content.js';
import { linkTarget, readBytes, sizeOf, walk } from './fs/walk.js';
import type { HookDef, InstructionKind, McpServer, Model, Role, ScannedFile, Skill } from './model.js';
import { parseFrontmatter, type Frontmatter } from './parse/frontmatter.js';
import { formatPath, isObject, isString, JsonSyntaxError, parseJson, stringArray, type Json, type JsonDoc, type JsonObject, type JsonPath } from './parse/json.js';
import { parseToml, TomlSyntaxError, type TomlTable, type TomlValue } from './parse/toml.js';

const base = (p: string) => p.slice(p.lastIndexOf('/') + 1);
const dirOf = (p: string) => (p.includes('/') ? p.slice(0, p.lastIndexOf('/')) : '');
const has = (p: string, seg: string) => p === seg || p.startsWith(`${seg}/`) || p.includes(`/${seg}/`) || p.endsWith(`/${seg}`);

/** Directories (anywhere in the tree) whose every file belongs to an agent surface. */
const SURFACE_DIRS = ['.claude/commands', '.claude/agents', '.claude/rules', '.claude/skills', '.cursor/rules', '.github/instructions', '.github/prompts', '.github/agents', '.github/chatmodes', '.windsurf/rules', '.devin/rules', '.agents/rules', '.agent/rules', '.agents/skills', '.agent/skills', '.gemini/skills'];

/** Plugin component directories (relative to a plugin root). */
const PLUGIN_DIRS = ['.claude-plugin', 'hooks', 'bin', 'commands', 'agents', 'skills', 'output-styles'];

function skillTools(dir: string): string[] {
  if (has(dir, '.claude/skills')) return ['Claude Code'];
  if (has(dir, '.agents/skills')) return ['Gemini CLI', 'Antigravity', 'OpenClaw'];
  if (has(dir, '.agent/skills')) return ['Antigravity'];
  if (has(dir, '.gemini/skills')) return ['Gemini CLI'];
  if (/(^|\/)skills\/[^/]+$/.test(dir)) return ['OpenClaw', 'Claude Code plugins', 'Agent Skills'];
  return ['Agent Skills'];
}

const AGENTS_MD_READERS = ['Codex', 'Cursor', 'GitHub Copilot', 'Claude Code', 'Devin Desktop', 'Antigravity'];

/** Classifies one path. `null` means it is not an agent surface and is never read. */
export function classify(path: string, skillDirs: string[], pluginRoots: string[]): { role: Role; kind?: InstructionKind; tools: string[] } | null {
  const b = base(path);
  if (b === 'SKILL.md') return { role: 'skill', tools: skillTools(dirOf(path)) };
  if (skillDirs.some((d) => path.startsWith(`${d}/`))) return { role: 'skill-file', tools: skillTools(skillDirs.find((d) => path.startsWith(`${d}/`)) as string) };
  if (/(^|\/)\.claude\/settings(\.local)?\.json$/.test(path)) return { role: 'claude-settings', tools: ['Claude Code'] };
  if (b === '.mcp.json') return { role: 'mcp-config', tools: ['Claude Code'] };
  if (/(^|\/)\.cursor\/mcp\.json$/.test(path)) return { role: 'mcp-config', tools: ['Cursor'] };
  if (/(^|\/)\.vscode\/mcp\.json$/.test(path)) return { role: 'mcp-config', tools: ['VS Code'] };
  if (/(^|\/)\.gemini\/settings\.json$/.test(path)) return { role: 'gemini-settings', tools: ['Gemini CLI'] };
  if (/(^|\/)\.codex\/config\.toml$/.test(path)) return { role: 'codex-config', tools: ['Codex'] };
  if (/(^|\/)\.cursor\/hooks\.json$/.test(path)) return { role: 'cursor-hooks', tools: ['Cursor'] };
  if (/(^|\/)\.claude-plugin\/plugin\.json$/.test(path)) return { role: 'plugin-manifest', tools: ['Claude Code'] };
  if (/(^|\/)\.claude-plugin\/marketplace\.json$/.test(path)) return { role: 'marketplace', tools: ['Claude Code'] };
  const plugin = pluginRoots.find((r) => (r ? path.startsWith(`${r}/`) : true) && PLUGIN_DIRS.some((d) => path.startsWith(r ? `${r}/${d}/` : `${d}/`)));
  if (plugin !== undefined) {
    const rel = plugin ? path.slice(plugin.length + 1) : path;
    if (rel === 'hooks/hooks.json') return { role: 'plugin-hooks', tools: ['Claude Code'] };
    if (rel.startsWith('commands/') && b.endsWith('.md')) return { role: 'command', tools: ['Claude Code'] };
    if (rel.startsWith('agents/') && b.endsWith('.md')) return { role: 'agent', tools: ['Claude Code'] };
    return { role: 'plugin-file', tools: ['Claude Code'] };
  }
  if (has(path, '.claude/commands') && b.endsWith('.md')) return { role: 'command', tools: ['Claude Code'] };
  if (has(path, '.claude/agents') && b.endsWith('.md')) return { role: 'agent', tools: ['Claude Code'] };
  if (/(^|\/)\.github\/agents\/[^/]+\.md$/.test(path) || /(^|\/)\.github\/chatmodes\/[^/]+\.chatmode\.md$/.test(path)) return { role: 'agent', tools: ['GitHub Copilot'] };
  if (b === 'CLAUDE.md') return { role: 'instructions', kind: 'claude-md', tools: ['Claude Code'] };
  if (b === 'CLAUDE.local.md') return { role: 'instructions', kind: 'claude-local', tools: ['Claude Code'] };
  if (b === 'AGENTS.md' || b === 'AGENTS.override.md') return { role: 'instructions', kind: 'agents-md', tools: b === 'AGENTS.md' ? AGENTS_MD_READERS : ['Codex'] };
  if (b === 'GEMINI.md') return { role: 'instructions', kind: 'gemini-md', tools: ['Gemini CLI', 'Antigravity', 'GitHub Copilot'] };
  if (/(^|\/)\.github\/copilot-instructions\.md$/.test(path)) return { role: 'instructions', kind: 'copilot', tools: ['GitHub Copilot'] };
  if (has(path, '.github/instructions') && b.endsWith('.instructions.md')) return { role: 'instructions', kind: 'copilot-path', tools: ['GitHub Copilot'] };
  if (has(path, '.github/prompts') && b.endsWith('.prompt.md')) return { role: 'instructions', kind: 'copilot-prompt', tools: ['GitHub Copilot'] };
  if (has(path, '.claude/rules') && b.endsWith('.md')) return { role: 'instructions', kind: 'claude-rule', tools: ['Claude Code'] };
  if (has(path, '.cursor/rules') && b.endsWith('.mdc')) return { role: 'instructions', kind: 'cursor-rule', tools: ['Cursor'] };
  if (has(path, '.cursor/rules') && b.endsWith('.md')) return { role: 'instructions', kind: 'cursor-rule-ignored', tools: [] };
  if ((has(path, '.windsurf/rules') || has(path, '.devin/rules')) && b.endsWith('.md')) return { role: 'instructions', kind: 'windsurf-rule', tools: ['Devin Desktop'] };
  if (b === '.windsurfrules') return { role: 'instructions', kind: 'windsurf-legacy', tools: ['Devin Desktop'] };
  if ((has(path, '.agents/rules') || has(path, '.agent/rules')) && b.endsWith('.md')) return { role: 'instructions', kind: 'antigravity-rule', tools: ['Antigravity'] };
  if (SURFACE_DIRS.some((d) => has(path, d))) return { role: 'surface-file', tools: [] };
  return null;
}

/** Path-like tokens in a command that may name a file in this repository. */
export function referencedPaths(command: string): string[] {
  const out = new Set<string>();
  const cleaned = command.replace(/["']?\$\{?(?:CLAUDE_PROJECT_DIR|CLAUDE_PLUGIN_ROOT|workspaceFolder|PWD)\}?["']?\/?/g, '').replace(/\$\{workspaceFolder\}\/?/g, '');
  for (const tok of cleaned.split(/[\s;&|()<>"'=]+/)) {
    const t = tok.replace(/^\.\//, '');
    if (!t || t.startsWith('-') || t.startsWith('/') || t.startsWith('~') || t.includes('://') || t.includes('$')) continue;
    if (/\.(?:sh|bash|zsh|py|js|mjs|cjs|ts|rb|pl|ps1|php|lua)$/.test(t) || t.includes('/')) out.add(t.replace(/\/+$/, ''));
  }
  return [...out];
}

const sha256 = (b: Buffer | string) => createHash('sha256').update(b).digest('hex');

/** Options `discover` uses. */
export interface DiscoverOptions {
  exclude?: string[];
  maxFiles?: number;
  maxFileBytes?: number;
}

/** Walks, classifies, reads and parses. */
export async function discover(root: string, options: DiscoverOptions = {}): Promise<Model> {
  const maxBytes = options.maxFileBytes ?? 1_048_576;
  const w = await walk(root, { exclude: options.exclude, maxFiles: options.maxFiles });
  const paths = new Set(w.entries.map((e) => e.path));
  const dirs = new Set<string>(['']);
  for (const p of paths) for (let d = dirOf(p); d && !dirs.has(d); d = dirOf(d)) dirs.add(d);
  const skillDirs = w.entries.filter((e) => base(e.path) === 'SKILL.md' && e.type === 'file').map((e) => dirOf(e.path)).filter(Boolean).sort((a, b) => b.length - a.length);
  const pluginRoots = w.entries.filter((e) => /(^|\/)\.claude-plugin\/(plugin|marketplace)\.json$/.test(e.path)).map((e) => dirOf(dirOf(e.path)));

  const model: Model = {
    root,
    files: [],
    byPath: new Map(),
    paths,
    dirs,
    settings: [],
    hooks: [],
    helpers: [],
    servers: [],
    skills: [],
    plugins: [],
    marketplaces: [],
    jsonDocs: new Map(),
    frontmatter: new Map(),
    walkTruncated: w.truncated,
    filesSeen: w.entries.length,
  };

  const readFile = async (path: string, role: Role, tools: string[], kind?: InstructionKind, symlink = false): Promise<ScannedFile> => {
    const f: ScannedFile = { path, role, tools, ...(kind ? { kind } : {}) };
    if (symlink) {
      let target: string | null = null;
      try {
        target = await linkTarget(root, path);
      } catch {
        target = null;
      }
      if (target && paths.has(target)) f.linkTarget = target;
      else f.unread = { path, reason: 'symlink', detail: target ? `symbolic link to ${target}, which is not a file in this repository` : 'symbolic link to a path outside the repository (not followed)' };
    } else {
      try {
        const size = await sizeOf(root, path);
        if (size > maxBytes) {
          f.unread = { path, reason: 'too-large', detail: `${size.toLocaleString('en-US')} bytes, over the ${maxBytes.toLocaleString('en-US')}-byte limit` };
          f.bytes = size;
        } else {
          const buf = await readBytes(root, path);
          f.sha256 = sha256(buf);
          f.bytes = buf.length;
          const c = inspect(path, buf);
          if (c.kind === 'text') f.text = c.text;
          else f.unread = { path, reason: c.reason, detail: c.detail };
        }
      } catch (error) {
        f.unread = { path, reason: 'unreadable', detail: (error as NodeJS.ErrnoException).code ?? 'could not read' };
      }
    }
    model.files.push(f);
    model.byPath.set(path, f);
    return f;
  };

  for (const e of w.entries) {
    const c = classify(e.path, skillDirs, pluginRoots);
    if (!c) continue;
    await readFile(e.path, c.role, c.tools, c.kind, e.type === 'symlink');
  }

  // A link to another file in the repo: scan that file in its own right.
  for (const f of [...model.files]) {
    if (f.linkTarget && !model.byPath.has(f.linkTarget)) await readFile(f.linkTarget, f.role, f.tools, f.kind);
  }

  const parseError = (f: ScannedFile, error: unknown) => {
    const msg = error instanceof JsonSyntaxError || error instanceof TomlSyntaxError ? error.message : String(error);
    f.unread = { path: f.path, reason: 'parse-error', detail: msg };
  };
  const json = (f: ScannedFile): JsonDoc | null => {
    if (f.text === undefined) return null;
    try {
      const doc = parseJson(f.text, { jsonc: true });
      model.jsonDocs.set(f.path, doc);
      return doc;
    } catch (error) {
      parseError(f, error);
      return null;
    }
  };

  for (const f of [...model.files]) {
    if (f.text === undefined) continue;
    switch (f.role) {
      case 'claude-settings': {
        const doc = json(f);
        if (!doc || !isObject(doc.value)) break;
        const s = doc.value;
        model.settings.push({ file: f.path, local: f.path.endsWith('settings.local.json'), json: s, doc });
        collectClaudeHooks(model, f.path, 'Claude Code', s.hooks, ['hooks'], doc, 'settings');
        for (const key of ['apiKeyHelper', 'awsAuthRefresh', 'awsCredentialExport', 'gcpAuthRefresh', 'otelHeadersHelper']) {
          const v = s[key];
          if (isString(v) && v.trim()) model.helpers.push({ file: f.path, key, command: v, line: doc.lineOf([key]) });
        }
        for (const key of ['statusLine', 'subagentStatusLine', 'fileSuggestion']) {
          const v = s[key];
          if (isObject(v) && isString(v.command)) model.helpers.push({ file: f.path, key: `${key}.command`, command: v.command, line: doc.lineOf([key, 'command']) ?? doc.lineOf([key]) });
        }
        break;
      }
      case 'mcp-config': {
        const doc = json(f);
        if (!doc || !isObject(doc.value)) break;
        const key = f.tools[0] === 'VS Code' ? 'servers' : 'mcpServers';
        collectServers(model, f.path, f.tools[0] as string, doc.value[key], [key], doc);
        break;
      }
      case 'gemini-settings': {
        const doc = json(f);
        if (!doc || !isObject(doc.value)) break;
        collectServers(model, f.path, 'Gemini CLI', doc.value.mcpServers, ['mcpServers'], doc);
        collectClaudeHooks(model, f.path, 'Gemini CLI', doc.value.hooks, ['hooks'], doc, 'gemini');
        break;
      }
      case 'cursor-hooks': {
        const doc = json(f);
        if (!doc || !isObject(doc.value) || !isObject(doc.value.hooks)) break;
        for (const [event, list] of Object.entries(doc.value.hooks)) {
          if (!Array.isArray(list)) continue;
          list.forEach((h, i) => {
            if (isObject(h) && isString(h.command)) {
              const p = ['hooks', event, i, 'command'];
              model.hooks.push({ file: f.path, tool: 'Cursor', event, type: 'command', command: h.command, line: doc.lineOf(p), key: formatPath(p), origin: 'cursor' });
            }
          });
        }
        break;
      }
      case 'plugin-hooks': {
        const doc = json(f);
        if (!doc || !isObject(doc.value)) break;
        collectClaudeHooks(model, f.path, 'Claude Code', doc.value.hooks, ['hooks'], doc, 'plugin');
        break;
      }
      case 'plugin-manifest': {
        const doc = json(f);
        if (!doc) break;
        model.plugins.push({ file: f.path, json: doc.value, doc });
        if (isObject(doc.value)) {
          if (isObject(doc.value.hooks)) collectClaudeHooks(model, f.path, 'Claude Code', doc.value.hooks, ['hooks'], doc, 'plugin', true);
          if (isObject(doc.value.mcpServers)) collectServers(model, f.path, 'Claude Code', doc.value.mcpServers, ['mcpServers'], doc);
        }
        break;
      }
      case 'marketplace': {
        const doc = json(f);
        if (doc) model.marketplaces.push({ file: f.path, json: doc.value, doc });
        break;
      }
      case 'codex-config': {
        try {
          const t = parseToml(f.text);
          const servers = t.value.mcp_servers;
          if (servers && typeof servers === 'object' && !Array.isArray(servers)) {
            for (const [name, raw] of Object.entries(servers)) {
              if (!raw || typeof raw !== 'object' || Array.isArray(raw)) continue;
              model.servers.push(codexServer(f.path, name, raw, t.lines.get(`mcp_servers.${name}`)));
            }
          }
        } catch (error) {
          parseError(f, error);
        }
        break;
      }
      case 'skill':
      case 'command':
      case 'agent':
      case 'instructions': {
        if (f.role === 'instructions' && !(f.kind === 'cursor-rule' || f.kind === 'copilot-path' || f.kind === 'copilot-prompt' || f.kind === 'claude-rule' || f.kind === 'windsurf-rule' || f.kind === 'antigravity-rule')) break;
        const fm = parseFrontmatter(f.text);
        model.frontmatter.set(f.path, fm);
        if (fm.present && 'hooks' in fm.data) collectFrontmatterHooks(model, f.path, fm);
        break;
      }
      default:
        break;
    }
  }

  // Skills: one entry per SKILL.md, with every file under its directory.
  for (const f of model.files.filter((x) => x.role === 'skill')) {
    const dir = dirOf(f.path);
    const files = [...paths].filter((p) => p.startsWith(`${dir}/`)).sort();
    const fm = model.frontmatter.get(f.path) ?? parseFrontmatter(f.text ?? '');
    const skill: Skill = { dir, file: f.path, tools: f.tools, fm, files };
    model.skills.push(skill);
  }

  // Scripts that hooks, helpers and MCP servers run from this repository are part of the surface too.
  const commands = [
    ...model.hooks.filter((h) => h.command).map((h) => ({ command: h.command as string, tools: [h.tool] })),
    ...model.helpers.map((h) => ({ command: h.command, tools: ['Claude Code'] })),
    ...model.servers.map((s) => ({ command: [s.command ?? '', ...s.args].join(' '), tools: [s.tool] })),
  ];
  for (const { command, tools } of commands) {
    for (const ref of referencedPaths(command)) {
      if (!paths.has(ref) || model.byPath.has(ref)) continue;
      await readFile(ref, 'surface-file', tools, undefined, w.entries.find((e) => e.path === ref)?.type === 'symlink');
    }
  }

  model.files.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  return model;
}

function collectClaudeHooks(model: Model, file: string, tool: string, hooks: Json | undefined, path: JsonPath, doc: JsonDoc, origin: HookDef['origin'], inline = false): void {
  void inline;
  if (!isObject(hooks)) return;
  for (const [event, groups] of Object.entries(hooks)) {
    if (!Array.isArray(groups)) continue;
    groups.forEach((g, gi) => {
      if (!isObject(g)) return;
      const matcher = isString(g.matcher) ? g.matcher : undefined;
      const list = Array.isArray(g.hooks) ? g.hooks : [];
      list.forEach((h, hi) => {
        if (!isObject(h)) return;
        const type = isString(h.type) ? h.type : 'command';
        const hp = [...path, event, gi, 'hooks', hi];
        let command: string | undefined;
        if (isString(h.command)) command = [h.command, ...stringArray(h.args)].join(' ');
        const url = isString(h.url) ? h.url : undefined;
        if (!command && !url && type !== 'prompt' && type !== 'agent' && type !== 'mcp_tool') return;
        const keyPath = command ? [...hp, 'command'] : url ? [...hp, 'url'] : hp;
        model.hooks.push({
          file,
          tool,
          event,
          ...(matcher !== undefined ? { matcher } : {}),
          type,
          ...(command ? { command } : {}),
          ...(url ? { url } : {}),
          line: doc.lineOf(keyPath) ?? doc.lineOf(hp),
          key: formatPath(keyPath),
          origin,
        });
      });
    });
  }
}

function collectFrontmatterHooks(model: Model, file: string, fm: Frontmatter): void {
  const lines = fm.raw.split('\n');
  const start = (fm.keyLines.hooks ?? 2) - 2;
  let event = 'hooks';
  for (let i = start + 1; i < lines.length; i++) {
    const l = lines[i] as string;
    if (/^\S/.test(l)) break;
    const ev = /^\s{1,4}([A-Za-z]+)\s*:\s*$/.exec(l);
    if (ev) event = ev[1] as string;
    const m = /^\s*-?\s*command\s*:\s*(.+)$/.exec(l);
    if (m) {
      const raw = (m[1] as string).trim().replace(/^(["'])(.*)\1$/, '$2');
      model.hooks.push({ file, tool: 'Claude Code', event, type: 'command', command: raw, line: i + 2, key: `frontmatter hooks.${event}`, origin: 'frontmatter' });
    }
  }
}

function stringMap(v: Json | undefined): Record<string, string> {
  const out: Record<string, string> = Object.create(null);
  if (!isObject(v)) return out;
  for (const [k, val] of Object.entries(v)) if (isString(val) || typeof val === 'number' || typeof val === 'boolean') out[k] = String(val);
  return out;
}

function collectServers(model: Model, file: string, tool: string, servers: Json | undefined, path: JsonPath, doc: JsonDoc): void {
  if (!isObject(servers)) return;
  for (const [name, s] of Object.entries(servers)) {
    if (!isObject(s)) continue;
    const url = isString(s.url) ? s.url : isString(s.httpUrl) ? s.httpUrl : isString(s.serverUrl) ? s.serverUrl : undefined;
    const type = isString(s.type) ? s.type : undefined;
    const transport: McpServer['transport'] =
      type === 'stdio' || type === 'local' ? 'stdio' : type === 'http' || type === 'streamable-http' ? 'http' : type === 'sse' ? 'sse' : type === 'ws' ? 'ws' : url ? 'http' : isString(s.command) ? 'stdio' : 'unknown';
    model.servers.push({
      file,
      tool,
      name,
      transport,
      ...(isString(s.command) ? { command: s.command } : {}),
      args: stringArray(s.args),
      env: stringMap(s.env),
      ...(url ? { url } : {}),
      headers: stringMap(s.headers),
      ...(isString(s.headersHelper) ? { headersHelper: s.headersHelper } : {}),
      ...(typeof s.trust === 'boolean' ? { trust: s.trust } : {}),
      line: doc.lineOf([...path, name]),
      path: [...path, name],
      doc,
    });
  }
}

function tomlStrings(v: TomlValue | undefined): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
}
function tomlMap(v: TomlValue | undefined): Record<string, string> {
  const out: Record<string, string> = Object.create(null);
  if (!v || typeof v !== 'object' || Array.isArray(v)) return out;
  for (const [k, val] of Object.entries(v as TomlTable)) if (typeof val === 'string' || typeof val === 'number' || typeof val === 'boolean') out[k] = String(val);
  return out;
}

function codexServer(file: string, name: string, raw: TomlTable, line: number | undefined): McpServer {
  const url = typeof raw.url === 'string' ? raw.url : undefined;
  return {
    file,
    tool: 'Codex',
    name,
    transport: url ? 'http' : typeof raw.command === 'string' ? 'stdio' : 'unknown',
    ...(typeof raw.command === 'string' ? { command: raw.command } : {}),
    args: tomlStrings(raw.args),
    env: tomlMap(raw.env),
    ...(url ? { url } : {}),
    headers: tomlMap(raw.http_headers),
    ...(line ? { line } : {}),
    path: ['mcp_servers', name],
  };
}

export { sha256 };
export type { JsonObject };
