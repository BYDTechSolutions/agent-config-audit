import { symlink } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { auditRepo, type Finding, type Report } from '../src/index.js';
import { claudeSettingsRepo, cleanRepo, instructionsRepo, mcpRepo, pluginRepo, skillsRepo } from './fixtures/repos.js';
import { materialize } from './helpers.js';

const ids = (r: Report) => r.findings.map((f) => f.id);
const find = (r: Report, id: string, pred: (f: Finding) => boolean = () => true) => r.findings.filter((f) => f.id === id && pred(f));

describe('Claude Code settings', async () => {
  const report = await auditRepo(await materialize(claudeSettingsRepo()));

  it('flags env overrides that redirect traffic or inject code', () => {
    expect(find(report, 'exec/env-endpoint')[0]).toMatchObject({ file: '.claude/settings.json', key: 'env.ANTHROPIC_BASE_URL', priority: 'fix-now' });
    expect(find(report, 'exec/env-loader')[0]?.key).toBe('env.NODE_OPTIONS');
    expect(find(report, 'exec/env-tls')).toHaveLength(1);
    expect(find(report, 'secrets/env-literal')[0]?.key).toBe('env.ANTHROPIC_API_KEY');
    // LOG_LEVEL is an ordinary variable.
    expect(report.findings.some((f) => f.key === 'env.LOG_LEVEL')).toBe(false);
  });

  it('names the file, line and key of each finding', () => {
    const f = find(report, 'exec/env-endpoint')[0] as Finding;
    expect(f.line).toBeGreaterThan(1);
    expect(f.tags[0]).toBe('AST02');
    expect(f.source.url).toMatch(/^https:\/\/code\.claude\.com\/docs\//);
  });

  it('flags helper commands, permission bypass, broad allows, MCP auto-approval and hooks turned back on', () => {
    expect(find(report, 'exec/helper-command')[0]?.key).toBe('apiKeyHelper');
    expect(find(report, 'exec/statusline-command')).toHaveLength(1);
    expect(find(report, 'exec/bypass-permissions')).toHaveLength(1);
    const broad = find(report, 'exec/broad-allow').map((f) => f.observed);
    expect(broad.some((o) => o.includes('`Bash`'))).toBe(true);
    expect(broad.some((o) => o.includes('Bash(python *)'))).toBe(true);
    expect(broad.some((o) => o.includes('Bash(*)') && o.includes('settings.local.json'))).toBe(true);
    expect(broad.some((o) => o.includes('npm run test'))).toBe(false);
    expect(find(report, 'exec/mcp-auto-approve')).toHaveLength(2);
    expect(find(report, 'exec/hooks-reenabled')).toHaveLength(1);
    expect(find(report, 'exec/plugins-enabled')[0]?.observed).toContain('formatter@acme-tools');
  });

  it('lists every hook and scans hook commands for download-and-run', () => {
    const hooks = find(report, 'exec/hook-command');
    // The PreToolUse hook is reported once, by the stronger download-and-run finding on the same line.
    expect(hooks.map((h) => h.key)).toEqual(['hooks.PostToolUse[0].hooks[0].command']);
    expect(find(report, 'exec/hook-http')[0]?.observed).toContain('https://hooks.example.net/stop');
    const dl = find(report, 'prose/download-exec')[0] as Finding;
    expect(dl).toMatchObject({ file: '.claude/settings.json', priority: 'fix-now' });
    expect(dl.title).toContain('hook PreToolUse');
  });

  it('builds an inventory of what runs', () => {
    const runs = report.inventory.filter((s) => s.runs).map((s) => `${s.kind}:${s.name}`);
    expect(runs).toContain('hook:PreToolUse [Bash]');
    expect(runs).toContain('helper:apiKeyHelper');
    expect(report.inventory.find((s) => s.kind === 'env' && s.name === 'ANTHROPIC_API_KEY')?.summary).toMatch(/^ANTHROPIC_API_KEY = sk-a…Pp \(\d+ chars\)$/);
  });
});

describe('MCP configs across clients', async () => {
  const report = await auditRepo(await materialize(mcpRepo()));
  const named = (id: string) => find(report, id).map((f) => /server `([^`]+)`/.exec(f.title)?.[1]);

  it('flags unpinned launchers and leaves pinned ones alone', () => {
    expect(named('mcp/unpinned-package').sort()).toEqual(['docs', 'fs', 'playwright', 'uv']);
    const fs = find(report, 'mcp/unpinned-package', (f) => f.title.includes('`fs`'))[0] as Finding;
    expect(fs.observed).toContain('npx -y');
    expect(fs.key).toBe('mcpServers.fs.args');
  });

  it('flags plain HTTP, privileged containers, unpinned images, broad roots, shell launches and trust', () => {
    expect(named('mcp/plain-http')).toEqual(['remote']);
    expect(find(report, 'mcp/docker-privileged')[0]?.title).toMatch(/--privileged.*docker\.sock/);
    expect(named('mcp/docker-unpinned')).toEqual(['docker']);
    expect(named('mcp/broad-filesystem')).toEqual(['fs']);
    expect(named('mcp/shell-wrapper')).toEqual(['shell']);
    expect(find(report, 'prose/download-exec')[0]?.title).toContain('MCP server shell');
    expect(find(report, 'mcp/trust-all')[0]?.file).toBe('.gemini/settings.json');
    expect(named('mcp/repo-script')).toEqual(['local']);
  });

  it('flags inline credentials, not references to variables or inputs', () => {
    const secrets = find(report, 'mcp/inline-secret');
    expect(secrets.map((f) => f.file).sort()).toEqual(['.cursor/mcp.json', '.mcp.json']);
    expect(secrets.find((f) => f.file === '.mcp.json')?.key).toBe('mcpServers.token.env.GITHUB_TOKEN');
    expect(secrets.find((f) => f.file === '.cursor/mcp.json')?.key).toBe('mcpServers.linear.headers.Authorization');
    // Not repeated as a generic secret.
    expect(find(report, 'secrets/hardcoded')).toHaveLength(0);
  });

  it('reads VS Code JSONC (comments, trailing commas, `servers`) and Codex TOML', () => {
    expect(report.inventory.filter((s) => s.kind === 'mcp-server').map((s) => `${s.tools[0]}:${s.name}`)).toEqual(
      expect.arrayContaining(['VS Code:playwright', 'VS Code:api', 'Codex:docs', 'Cursor:linear', 'Gemini CLI:files']),
    );
    expect(ids(report)).not.toContain('unscannable/parse-error');
  });
});

describe('skills', async () => {
  const report = await auditRepo(await materialize(skillsRepo()));
  const inFile = (id: string, dir: string) => find(report, id, (f) => f.file.startsWith(`.claude/skills/${dir}/`));

  it('passes a well-formed skill', () => {
    expect(report.findings.filter((f) => f.file.includes('/good-skill/'))).toEqual([]);
  });

  it('checks frontmatter against the Agent Skills spec', () => {
    expect(inFile('skill/invalid-name', 'bad-name')[0]?.observed).toMatch(/single hyphens.*does not match its folder `bad-name`/);
    expect(inFile('skill/invalid-field', 'bad-name')[0]?.title).toContain('no description');
    expect(inFile('skill/no-frontmatter', 'nofm')).toHaveLength(1);
    expect(inFile('skill/unsafe-yaml', 'yaml')[0]).toMatchObject({ priority: 'fix-now', line: 5 });
    expect(inFile('skill/unknown-field', 'yaml')[0]?.observed).toContain('risk_tier');
  });

  it('compares declared and observed capability', () => {
    expect(inFile('skill/claims-read-only', 'readonly')[0]?.observed).toContain('scripts/install.sh');
    expect(inFile('skill/allowed-tools-understated', 'readonly')).toHaveLength(1);
    expect(inFile('skill/allowed-tools-broad', 'prose')[0]?.observed).toContain('`Bash`');
    expect(find(report, 'skill/allowed-tools-broad', (f) => f.file === '.claude/commands/deploy.md')).toHaveLength(1);
    expect(inFile('exec/inline-shell', 'prose')[0]?.observed).toContain('git branch --show-current');
    expect(find(report, 'exec/inline-shell', (f) => f.file === '.claude/commands/deploy.md')).toHaveLength(1);
  });

  it('flags hidden Unicode, padding and base64, and escapes them', () => {
    const bidi = inFile('hidden/bidi-control', 'hidden')[0] as Finding;
    expect(bidi.priority).toBe('fix-now');
    expect(bidi.details?.join(' ')).toContain('<U+202E>');
    const tags = inFile('hidden/tag-characters', 'hidden')[0] as Finding;
    expect(tags.details?.join(' ')).toContain('spells "run rm"');
    const zw = inFile('hidden/invisible-char', 'hidden')[0] as Finding;
    expect(zw.title).toMatch(/^1 invisible character/); // the emoji ZWJ sequence is not counted
    expect(inFile('hidden/padding', 'hidden')[0]?.title).toContain('150 blank lines');
    expect(inFile('hidden/base64-blob', 'hidden')[0]?.observed).toContain('decodes to text starting');
    for (const f of report.findings) expect(JSON.stringify(f)).not.toMatch(/[‪-‮⁦-⁩​\u{E0000}-\u{E007F}]/u);
  });

  it('flags dangerous instructions in prose and scripts', () => {
    expect(inFile('prose/download-exec', 'prose')[0]?.line).toBe(9);
    expect(inFile('prose/download-then-run', 'readonly')[0]?.file).toBe('.claude/skills/readonly/scripts/install.sh');
    expect(inFile('prose/conceal', 'prose')).toHaveLength(1);
    expect(inFile('prose/override-instructions', 'prose')).toHaveLength(1);
    expect(inFile('prose/persistence-write', 'prose')[0]?.title).toContain('shell profile');
    expect(inFile('prose/secret-exfil', 'prose')[0]?.priority).toBe('fix-now');
    expect(inFile('prose/disable-safety', 'prose')).toHaveLength(1);
  });

  it('classifies URLs that can change after review', () => {
    expect(inFile('refs/fetch-instructions', 'prose')).toHaveLength(1);
    expect(inFile('refs/paste-site', 'prose')[0]?.observed).toContain('gist');
    expect(inFile('refs/mutable-raw', 'prose')[0]?.observed).toContain('ref `main`');
    expect(inFile('refs/releases-latest', 'prose')).toHaveLength(1);
    expect(inFile('refs/shortener', 'prose')).toHaveLength(1);
  });

  it('reports binaries, archives and bytecode as needing human review, never passed', () => {
    expect(inFile('unscannable/binary', 'binary')[0]?.file).toBe('.claude/skills/binary/payload.bin');
    expect(inFile('unscannable/archive', 'binary')[0]?.file).toBe('.claude/skills/binary/context.docx');
    expect(inFile('unscannable/bytecode', 'binary')[0]?.file).toBe('.claude/skills/binary/helper.pyc');
    expect(inFile('unscannable/media', 'binary')[0]?.priority).toBe('review');
    expect(report.coverage.unread.map((u) => u.reason).sort()).toEqual(['archive', 'binary', 'binary', 'bytecode']);
  });
});

describe('instruction files and context hygiene', async () => {
  const dir = await materialize(instructionsRepo());
  await symlink('AGENTS.md', join(dir, 'linked/CLAUDE.md'));
  await symlink('/etc/hosts', join(dir, '.cursor/rules/outside.mdc'));
  const report = await auditRepo(dir);

  it('flags size budgets each tool documents', () => {
    expect(find(report, 'hygiene/claude-md-size')[0]?.file).toBe('pkg/CLAUDE.md');
    expect(find(report, 'hygiene/cursor-rule-size')[0]?.file).toBe('.cursor/rules/style.mdc');
    expect(find(report, 'hygiene/windsurf-rule-size')[0]?.file).toBe('.windsurf/rules/big.md');
    expect(find(report, 'hygiene/antigravity-rule-size')[0]?.file).toBe('.agents/rules/huge.md');
    expect(find(report, 'hygiene/agents-md-size')[0]?.file).toBe('big/AGENTS.md');
    expect(find(report, 'hygiene/cursor-rule-ignored')[0]?.file).toBe('.cursor/rules/notes.md');
  });

  it('notices CLAUDE.local.md hiding AGENTS.md, and CLAUDE.md that does not import it', () => {
    expect(find(report, 'hygiene/agents-md-hidden-by-local')[0]).toMatchObject({ file: 'CLAUDE.local.md', priority: 'should-fix' });
    expect(find(report, 'hygiene/agents-md-not-imported').map((f) => f.file)).toEqual(['pkg/CLAUDE.md']);
  });

  it('treats a CLAUDE.md symlink to AGENTS.md as an import, and does not follow links out of the repo', () => {
    expect(report.findings.some((f) => f.file.startsWith('linked/'))).toBe(false);
    const link = find(report, 'unscannable/symlink')[0] as Finding;
    expect(link.file).toBe('.cursor/rules/outside.mdc');
    expect(link.observed).toContain('outside the repository');
    expect(report.coverage.unread.some((u) => u.reason === 'symlink')).toBe(true);
  });

  it('finds dead references and directory trees', () => {
    const dead = find(report, 'hygiene/dead-reference')[0] as Finding;
    expect(dead.file).toBe('AGENTS.md');
    expect(dead.observed).toContain('docs/missing-guide.md');
    expect(dead.observed).toContain('nope.md');
    expect(dead.observed).not.toContain('docs/setup.md');
    expect(dead.observed).not.toContain('scripts/check.sh');
    expect(find(report, 'hygiene/directory-tree')[0]?.file).toBe('AGENTS.md');
  });

  it('flags bidi characters in Copilot instructions', () => {
    expect(find(report, 'hidden/bidi-control')[0]?.file).toBe('.github/copilot-instructions.md');
  });

  it('does not mistake long plain text for base64', () => {
    expect(find(report, 'hidden/base64-blob')).toEqual([]);
  });
});

describe('plugins and marketplaces', async () => {
  const report = await auditRepo(await materialize(pluginRepo()));
  it('flags unpinned and command plugin sources, plugin hooks and binaries in bin/', () => {
    expect(find(report, 'refs/plugin-unpinned').map((f) => /`([^`]+)`/.exec(f.title)?.[1]).sort()).toEqual(['branch', 'npm-range']);
    expect(find(report, 'exec/plugin-command-source')[0]?.observed).toContain('acme-ide claude-plugin-path');
    expect(find(report, 'exec/hook-command')[0]?.file).toBe('plugins/local/hooks/hooks.json');
    expect(find(report, 'unscannable/binary')[0]?.file).toBe('plugins/local/bin/tool');
  });
});

describe('a clean repo', async () => {
  const report = await auditRepo(await materialize(cleanRepo()));
  it('has no findings, still lists its surfaces, and says what it cannot assess', () => {
    expect(report.findings).toEqual([]);
    expect(report.inventory.map((s) => s.kind).sort()).toEqual(['instructions', 'mcp-server']);
    expect(report.coverage.ast.find((a) => a.id === 'AST06')?.status).toBe('not-assessed');
    expect(report.coverage.ast.find((a) => a.id === 'AST08')?.status).toBe('not-assessed');
    expect(report.coverage.notAssessed.map((n) => n.why).join(' ')).toMatch(/not a malware check/);
  });
});

describe('options', async () => {
  const dir = await materialize({ ...mcpRepo(), ...skillsRepo() });
  it('--only keeps the chosen families', async () => {
    const r = await auditRepo(dir, { only: ['mcp'] });
    expect(new Set(r.findings.map((f) => f.family))).toEqual(new Set(['mcp']));
    expect(r.families).toEqual(['mcp']);
  });
  it('a baseline hides known findings by fingerprint', async () => {
    const first = await auditRepo(dir);
    const second = await auditRepo(dir, { baseline: first.findings.map((f) => f.fingerprint) });
    expect(second.findings).toEqual([]);
    expect(second.suppressed).toBe(first.findings.length);
  });
  it('exclude skips path prefixes', async () => {
    const r = await auditRepo(dir, { exclude: ['.claude/skills'] });
    expect(r.findings.some((f) => f.file.startsWith('.claude/skills/'))).toBe(false);
  });
  it('a file over the size limit is reported, not read', async () => {
    const d = await materialize({ 'AGENTS.md': `${'a'.repeat(5000)}\n` });
    const r = await auditRepo(d, { maxFileBytes: 1024 });
    expect(find(r, 'unscannable/too-large')[0]?.file).toBe('AGENTS.md');
  });
  it('rejects a missing directory', async () => {
    await expect(auditRepo(join(dir, 'nope'))).rejects.toThrow(/No such directory/);
  });
});
