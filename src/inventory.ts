/**
 * The inventory ("AI bill of materials"): every surface an agent will load or
 * run, in one list, and the coverage statement every report carries.
 */
import { AST } from './facts/taxonomy.js';
import type { Model } from './model.js';
import { isObject, stringArray } from './parse/json.js';
import { code, safe } from './text/safe.js';
import { redact, SECRET_KEY } from './text/secrets.js';
import type { Coverage, Surface } from './types.js';
import { allowedTools } from './checks/skill.js';

export function buildInventory(model: Model): Surface[] {
  const out: Surface[] = [];
  for (const s of model.settings) {
    const keys = Object.keys(s.json);
    out.push({ kind: 'settings', path: s.file, name: s.file.slice(s.file.lastIndexOf('/') + 1), tools: ['Claude Code'], runs: false, summary: safe(`keys: ${keys.join(', ') || '(none)'}`, 200) });
    if (isObject(s.json.env)) {
      for (const [k, v] of Object.entries(s.json.env)) {
        out.push({ kind: 'env', path: s.file, name: k, tools: ['Claude Code'], runs: false, summary: `${k} = ${SECRET_KEY.test(k) ? redact(String(v)) : code(String(v), 80)}` });
      }
    }
    if (isObject(s.json.permissions)) {
      const p = s.json.permissions;
      const allow = stringArray(p.allow);
      out.push({ kind: 'permissions', path: s.file, name: 'permissions', tools: ['Claude Code'], runs: false, summary: safe(`${allow.length} allow, ${stringArray(p.ask).length} ask, ${stringArray(p.deny).length} deny${typeof p.defaultMode === 'string' ? `, defaultMode ${p.defaultMode}` : ''}`) });
    }
  }
  for (const h of model.hooks) {
    out.push({ kind: 'hook', path: h.file, name: `${h.event}${h.matcher ? ` [${h.matcher}]` : ''}`, tools: [h.tool], runs: true, summary: h.command ? `runs ${code(h.command, 120)}` : h.url ? `posts to ${code(h.url, 120)}` : `${h.type} hook` });
  }
  for (const h of model.helpers) out.push({ kind: 'helper', path: h.file, name: h.key, tools: ['Claude Code'], runs: true, summary: `runs ${code(h.command, 120)}` });
  for (const s of model.servers) {
    const launch = [s.command ?? '', ...s.args].join(' ').trim();
    out.push({ kind: 'mcp-server', path: s.file, name: s.name, tools: [s.tool], runs: s.transport === 'stdio' || (!s.url && !!s.command), summary: s.url ? `${s.transport} ${code(s.url, 120)}` : `${s.transport} ${code(launch, 120)}` });
  }
  for (const sk of model.skills) {
    const name = typeof sk.fm.data.name === 'string' ? sk.fm.data.name : sk.dir.slice(sk.dir.lastIndexOf('/') + 1);
    const tools = allowedTools(sk.fm.data['allowed-tools']);
    const inline = /!`[^`\n]+`|^```!/m.test(sk.fm.body);
    const scripts = sk.files.filter((p) => /\.(?:sh|bash|zsh|ps1|py|js|mjs|cjs|ts|rb|pl)$/i.test(p));
    out.push({ kind: 'skill', path: sk.file, name, tools: sk.tools, runs: inline || scripts.length > 0, summary: safe(`${sk.files.length} file${sk.files.length === 1 ? '' : 's'}${scripts.length ? `, ${scripts.length} script${scripts.length === 1 ? '' : 's'}` : ''}${inline ? ', inline shell' : ''}${tools ? `; allowed-tools: ${tools.join(' ')}` : ''}`, 200) });
  }
  for (const f of model.files) {
    if (f.role === 'command' || f.role === 'agent') out.push({ kind: f.role, path: f.path, name: f.path.slice(f.path.lastIndexOf('/') + 1).replace(/\.md$/, ''), tools: f.tools, runs: false, summary: f.unread ? `not read: ${f.unread.detail}` : `${f.bytes ?? 0} bytes` });
    if (f.role === 'instructions') {
      const kind = f.kind === 'copilot-prompt' ? 'prompt' : f.kind === 'agents-md' || f.kind === 'claude-md' || f.kind === 'claude-local' || f.kind === 'gemini-md' || f.kind === 'copilot' ? 'instructions' : 'rules';
      out.push({ kind, path: f.path, name: f.path.slice(f.path.lastIndexOf('/') + 1), tools: f.tools, runs: false, summary: f.linkTarget ? `symlink to ${f.linkTarget}` : f.unread ? `not read: ${f.unread.detail}` : `${(f.text ?? '').split('\n').length} lines` });
    }
  }
  for (const p of model.plugins) {
    const name = isObject(p.json) && typeof p.json.name === 'string' ? p.json.name : p.file;
    const version = isObject(p.json) && typeof p.json.version === 'string' ? ` ${p.json.version}` : '';
    out.push({ kind: 'plugin', path: p.file, name, tools: ['Claude Code'], runs: true, summary: safe(`plugin ${name}${version}`) });
  }
  for (const m of model.marketplaces) {
    const n = isObject(m.json) && Array.isArray(m.json.plugins) ? m.json.plugins.length : 0;
    out.push({ kind: 'marketplace', path: m.file, name: isObject(m.json) && typeof m.json.name === 'string' ? m.json.name : m.file, tools: ['Claude Code'], runs: false, summary: `${n} plugin${n === 1 ? '' : 's'} listed` });
  }
  return out.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
}

const SHORT: Record<string, string> = {
  AST06: 'a property of where the agent runs',
  AST08: 'archives, bytecode and text in images are not opened',
};

/** What this version can and cannot say, per OWASP AST risk, plus the files it could not read. */
export function buildCoverage(model: Model): Coverage {
  const how: Record<string, [Coverage['ast'][number]['status'], string]> = {
    AST01: ['partly-checked', 'Download-and-run, persistence writes, secret-file reads, concealment and permission-bypass phrasing in skills, rules, hooks and MCP launches. Malicious intent written in plain language without these patterns is not detected.'],
    AST02: ['partly-checked', 'Every hook, helper command, env override, MCP launch and plugin source in repository config, the paths OWASP calls config-file hijacking.'],
    AST03: ['partly-checked', 'Permission modes and allow rules, skill allowed-tools, MCP filesystem roots and container privileges, and declared versus observed capability.'],
    AST04: ['partly-checked', 'Hidden Unicode, padding, base64 blobs, YAML type tags, duplicate and prototype keys, and skill frontmatter against the Agent Skills spec.'],
    AST05: ['partly-checked', 'URLs that can change after review (branch refs, releases/latest, paste sites, shorteners, bare IPs) and instructions to follow remote content. The content behind a URL is never fetched.'],
    AST06: ['not-assessed', 'Isolation is a property of where the agent runs (containers, sandboxing, network policy), not of the repository.'],
    AST07: ['partly-checked', 'Unpinned MCP packages, images and plugin sources; `lock` and `diff` show any change since the last approved lock.'],
    AST08: ['not-assessed', 'This is a property of the scanner itself. This tool reads every file in agent surfaces without truncation and lists the files it could not read below, but it does not open archives, decompile bytecode or read text in images, and pattern rules miss attacks phrased in new words.'],
    AST09: ['inventory-only', 'The inventory and lockfile list what the repository supplies; approvals, audit trails and revocation are processes outside the repository.'],
    AST10: ['partly-checked', 'Frontmatter fields no tool documents are flagged; metadata lost when a skill is ported is not simulated.'],
  };
  return {
    ast: Object.entries(AST).map(([id, a]) => {
      const [status, text] = how[id] as [Coverage['ast'][number]['status'], string];
      return { id, title: a.title, status, how: text, ...(SHORT[id] ? { short: SHORT[id] } : {}) };
    }),
    notAssessed: [
      { what: 'malware', why: 'This is not a malware check. An empty report is not a clean bill of health.' },
      { what: 'what MCP servers do', why: 'Their tool descriptions need the server running, and this tool never starts one.' },
      { what: 'runtime behavior', why: 'Nothing found is executed, so what hooks, scripts and servers do when they run is not observed.' },
      { what: 'content behind URLs', why: 'Nothing is fetched.' },
      { what: 'config outside this directory', why: 'User and machine settings (~/.claude, ~/.cursor, ~/.codex, managed settings), IDE settings, and MCP servers set in a hosting service (for example GitHub Copilot cloud agent repository settings).' },
      { what: 'dependencies of skill scripts', why: 'Packages that skill scripts install (package.json, requirements.txt) and their install scripts.' },
    ],
    unread: model.files.filter((f) => f.unread).map((f) => f.unread as NonNullable<typeof f.unread>),
  };
}
