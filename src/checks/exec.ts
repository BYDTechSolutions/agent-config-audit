/**
 * Execution surfaces: hooks, helper commands, env overrides, permission
 * settings, MCP auto-approval, inline skill shell, and plugin sources.
 */
import { SOURCES } from '../facts/sources.js';
import type { Model } from '../model.js';
import { isObject, isString, stringArray, type JsonObject } from '../parse/json.js';
import { code, lineIndex } from '../text/safe.js';
import { looksLikeLiteralSecret, redact, SECRET_KEY } from '../text/secrets.js';
import type { Emit } from './emit.js';

/** Env variables that send API traffic or credentials somewhere else (Claude Code env-vars page). */
export const ENDPOINT_VARS = new Set(['ANTHROPIC_BASE_URL', 'ANTHROPIC_BEDROCK_BASE_URL', 'ANTHROPIC_VERTEX_BASE_URL', 'ANTHROPIC_CUSTOM_HEADERS', 'HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy']);

/** Env variables that load or wrap code in child processes. */
export const LOADER_VARS = new Set(['LD_PRELOAD', 'LD_AUDIT', 'LD_LIBRARY_PATH', 'CLAUDE_CODE_SHELL_PREFIX']);

const NODE_PRELOAD = /(?:^|\s)(?:-r|--require|--import|--loader|--experimental-loader|--inspect(?:-brk)?)(?:[=\s]|$)/;
const BROAD_INTERPRETER = /^(?:Bash|PowerShell)\(\s*(?:sudo\s+)?(?:python[0-9.]*|node|bash|sh|zsh|fish|perl|ruby|php|deno|bun|bunx|npx|uvx|pwsh|powershell|eval|exec|source|curl|wget)\b\s*(?::\*|\*)\s*\)$/;

/** True when a permission rule matches any command, or any program an interpreter can run. */
export function isBroadAllow(entry: string): boolean {
  const e = entry.trim();
  return e === 'Bash' || e === 'PowerShell' || /^(?:Bash|PowerShell)\(\s*\*?\s*\)$/.test(e) || BROAD_INTERPRETER.test(e);
}

const where = (local: boolean) => (local ? ' (personal settings.local.json; shared only if committed)' : '');

export function execChecks(model: Model, emit: Emit): void {
  for (const s of model.settings) {
    const { file, json, doc, local } = s;
    const env = json.env;
    if (isObject(env)) {
      for (const [name, raw] of Object.entries(env)) {
        if (!isString(raw) && typeof raw !== 'number' && typeof raw !== 'boolean') continue;
        const value = String(raw);
        const line = doc.lineOf(['env', name]);
        const key = `env.${name}`;
        const secretish = SECRET_KEY.test(name) || name === 'ANTHROPIC_CUSTOM_HEADERS';
        const shown = secretish ? redact(value) : code(value, 100);
        if (ENDPOINT_VARS.has(name)) {
          emit('exec/env-endpoint', { file, line, key, title: `Project env sets ${name}`, observed: `${key} = ${shown}${where(local)}`, source: name.includes('PROXY') ? SOURCES.ccNetwork : SOURCES.ccEnvVars });
        } else if (LOADER_VARS.has(name) || (name === 'NODE_OPTIONS' && NODE_PRELOAD.test(value))) {
          emit('exec/env-loader', { file, line, key, title: `Project env sets ${name}`, observed: `${key} = ${shown}${where(local)}`, source: name === 'NODE_OPTIONS' ? SOURCES.nodeOptions : name.startsWith('LD_') ? SOURCES.ldso : SOURCES.ccEnvVars });
        } else if (name === 'NODE_EXTRA_CA_CERTS') {
          emit('exec/env-tls', { file, line, key, title: `Project env sets ${name}`, observed: `${key} = ${shown}${where(local)}` });
        }
        if (SECRET_KEY.test(name) && looksLikeLiteralSecret(value)) {
          emit('secrets/env-literal', { file, line, key, title: `Settings env sets ${name} to a literal value`, observed: `${key} = ${redact(value)}${where(local)}`, evidence: key });
        }
      }
    }

    const perms = json.permissions;
    if (isObject(perms)) {
      if (perms.defaultMode === 'bypassPermissions') {
        emit('exec/bypass-permissions', { file, line: doc.lineOf(['permissions', 'defaultMode']), key: 'permissions.defaultMode', observed: `permissions.defaultMode = "bypassPermissions"${where(local)}` });
      }
      stringArray(perms.allow).forEach((entry, i) => {
        if (isBroadAllow(entry)) {
          emit('exec/broad-allow', { file, line: doc.lineOf(['permissions', 'allow', i]), key: `permissions.allow[${i}]`, title: `Permission rule ${code(entry, 60)} allows arbitrary commands`, observed: `permissions.allow contains ${code(entry, 80)}${where(local)}`, evidence: entry });
        }
      });
    }

    if (json.enableAllProjectMcpServers === true) {
      emit('exec/mcp-auto-approve', { file, line: doc.lineOf(['enableAllProjectMcpServers']), key: 'enableAllProjectMcpServers', observed: `enableAllProjectMcpServers = true${where(local)}` });
    }
    const enabled = stringArray(json.enabledMcpjsonServers);
    if (enabled.length) {
      emit('exec/mcp-auto-approve', { file, line: doc.lineOf(['enabledMcpjsonServers']), key: 'enabledMcpjsonServers', observed: `enabledMcpjsonServers = [${enabled.map((n) => code(n, 40)).join(', ')}]${where(local)}` });
    }
    if (json.disableAllHooks === false && !local) {
      emit('exec/hooks-reenabled', { file, line: doc.lineOf(['disableAllHooks']), key: 'disableAllHooks', observed: 'disableAllHooks = false' });
    }

    const plugins = isObject(json.enabledPlugins) ? Object.entries(json.enabledPlugins).filter(([, v]) => v === true).map(([k]) => k) : [];
    const markets = isObject(json.extraKnownMarketplaces) ? Object.entries(json.extraKnownMarketplaces).map(([name, v]) => `${name} (${describeSource(isObject(v) ? v.source : undefined)})`) : [];
    if (plugins.length || markets.length) {
      const parts = [plugins.length ? `enabledPlugins: ${plugins.map((p) => code(p, 60)).join(', ')}` : '', markets.length ? `extraKnownMarketplaces: ${markets.join(', ')}` : ''].filter(Boolean);
      emit('exec/plugins-enabled', { file, line: doc.lineOf([plugins.length ? 'enabledPlugins' : 'extraKnownMarketplaces']), key: plugins.length ? 'enabledPlugins' : 'extraKnownMarketplaces', observed: `${parts.join('; ')}${where(local)}` });
    }
  }

  for (const h of model.hooks) {
    const source = h.tool === 'Cursor' ? SOURCES.cursorHooks : h.tool === 'Gemini CLI' ? SOURCES.geminiHooks : undefined;
    const why =
      h.tool === 'Cursor'
        ? 'Cursor runs the commands in a project `.cursor/hooks.json` on agent events, so whoever changes this file changes what runs on every developer\'s machine.'
        : h.tool === 'Gemini CLI'
          ? 'Gemini CLI hooks execute arbitrary code with your user privileges, and its docs warn that project-level hooks are particularly risky when opening untrusted projects.'
          : h.origin === 'frontmatter'
            ? 'Hooks in skill frontmatter run while the skill is active; Claude Code uses a project skill\'s hooks even in `claude -p` and SDK runs on a folder nobody trusted.'
            : undefined;
    const label = `${h.event}${h.matcher ? ` (matcher ${code(h.matcher, 40)})` : ''}`;
    if (h.type === 'http' && h.url) {
      emit('exec/hook-http', { file: h.file, line: h.line, key: h.key, title: `Hook ${h.event} posts to ${code(h.url, 60)}`, observed: `${label} sends each event to ${code(h.url, 120)}`, evidence: `${h.key}=${h.url}` });
    } else if (h.command) {
      emit('exec/hook-command', {
        file: h.file,
        line: h.line,
        key: h.key,
        title: `${h.tool} hook ${h.event} runs a command`,
        observed: `${label} runs ${code(h.command, 140)}`,
        evidence: `${h.key}=${h.command}`,
        ...(why ? { why } : {}),
        ...(source ? { source } : {}),
      });
    }
  }

  for (const h of model.helpers) {
    const isUi = /^(?:statusLine|subagentStatusLine|fileSuggestion)\./.test(h.key);
    emit(isUi ? 'exec/statusline-command' : 'exec/helper-command', { file: h.file, line: h.line, key: h.key, title: `${h.key} runs a command`, observed: `${h.key} = ${code(h.command, 140)}`, evidence: `${h.key}=${h.command}` });
  }

  // Inline shell in Claude Code skills and commands: !`cmd` and ```! blocks.
  for (const f of model.files) {
    if ((f.role !== 'skill' && f.role !== 'command') || f.text === undefined) continue;
    const at = lineIndex(f.text);
    for (const m of f.text.matchAll(/!`([^`\n]+)`/g)) {
      emit('exec/inline-shell', { file: f.path, line: at(m.index ?? 0), title: `${f.role === 'skill' ? 'Skill' : 'Command'} runs ${code(m[1] as string, 60)} when invoked`, observed: `!\`…\` block runs ${code(m[1] as string, 140)}`, evidence: m[1] as string });
    }
    for (const m of f.text.matchAll(/^```!\s*\n([\s\S]*?)^```/gm)) {
      const body = (m[1] as string).trim();
      emit('exec/inline-shell', { file: f.path, line: at(m.index ?? 0), title: `${f.role === 'skill' ? 'Skill' : 'Command'} runs a shell block when invoked`, observed: `\`\`\`! block runs ${code(body, 140)}`, evidence: body });
    }
  }

  for (const m of model.marketplaces) {
    if (!isObject(m.json)) continue;
    const plugins = Array.isArray(m.json.plugins) ? m.json.plugins : [];
    plugins.forEach((p, i) => {
      if (!isObject(p)) return;
      const name = isString(p.name) ? p.name : `#${i}`;
      const src = p.source;
      if (!isObject(src)) return;
      const line = m.doc.lineOf(['plugins', i, 'source']);
      const key = `plugins[${i}].source`;
      const kind = isString(src.source) ? src.source : '';
      if (kind === 'command' && isString(src.command)) {
        emit('exec/plugin-command-source', { file: m.file, line, key, title: `Plugin ${code(name, 40)} comes from a shell command`, observed: `source.command = ${code(src.command, 140)}`, evidence: `${name}:${src.command}` });
      } else if (['github', 'url', 'git-subdir'].includes(kind) && !(isString(src.sha) && /^[0-9a-f]{40}$/.test(src.sha))) {
        emit('refs/plugin-unpinned', { file: m.file, line, key, title: `Plugin ${code(name, 40)} is not pinned to a commit`, observed: `${describeSource(src)} has no \`sha\``, evidence: name });
      } else if (kind === 'npm' && !(isString(src.version) && /^\d+\.\d+\.\d+(?:[-+][\w.]+)?$/.test(src.version))) {
        emit('refs/plugin-unpinned', { file: m.file, line, key, title: `Plugin ${code(name, 40)} is not pinned to an exact version`, observed: `npm package ${code(String(src.package ?? '?'), 60)} version ${code(String(src.version ?? '(none)'), 30)}`, evidence: name });
      } else if (kind === 'archive' && !isString(src.sha256)) {
        emit('refs/plugin-unpinned', { file: m.file, line, key, title: `Plugin ${code(name, 40)} archive has no sha256`, observed: `archive ${code(String(src.url ?? '?'), 100)} without \`sha256\``, evidence: name });
      }
    });
  }
}

/** `github org/repo@ref` and friends, for messages and the lockfile. */
export function describeSource(src: JsonObject[string] | undefined): string {
  if (isString(src)) return src;
  if (!isObject(src)) return 'unknown source';
  const kind = isString(src.source) ? src.source : '?';
  const where = isString(src.repo) ? src.repo : isString(src.url) ? src.url : isString(src.package) ? src.package : isString(src.path) ? src.path : isString(src.command) ? src.command : '';
  const pin = isString(src.sha) ? `@${src.sha.slice(0, 12)}` : isString(src.ref) ? `#${src.ref}` : isString(src.version) ? `@${src.version}` : '';
  return `${kind} ${where}${pin}`.trim();
}
