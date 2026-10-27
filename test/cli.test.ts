import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { RULE_LIST } from '../src/index.js';
import { cleanRepo, mcpRepo, skillsRepo } from './fixtures/repos.js';
import { cli, materialize } from './helpers.js';

describe('cli', () => {
  it('prints help, version and the rule list', async () => {
    const h = await cli(['--help']);
    expect(h.code).toBe(0);
    expect(h.out).toContain('agent-config-audit lock [dir]');
    const v = await cli(['-v']);
    expect(v.out).toMatch(/^\d+\.\d+\.\d+\n$/);
    const l = await cli(['--list-rules']);
    expect(l.code).toBe(0);
    for (const r of RULE_LIST) expect(l.out).toContain(r.id);
    const lj = JSON.parse((await cli(['--list-rules', '--format', 'json'])).out);
    expect(lj).toHaveLength(RULE_LIST.length);
  });

  it('audits the current directory by default', async () => {
    const dir = await materialize(cleanRepo());
    const r = await cli([], { cwd: dir });
    expect(r.code).toBe(0);
    expect(r.out).toContain('Agent config audit: .');
    expect(r.out).toContain('No findings for the rules in this version; this is not a malware check.');
  });

  it('--fail-on sets the exit code', async () => {
    const dir = await materialize(mcpRepo());
    expect((await cli([dir])).code).toBe(0);
    const r = await cli([dir, '--fail-on', 'fix-now']);
    expect(r.code).toBe(1);
    expect(r.err).toMatch(/finding\(s\) at fix-now/);
    const clean = await materialize(cleanRepo());
    expect((await cli([clean, '--fail-on', 'should-fix'])).code).toBe(0);
  });

  it('writes formats to --out, inferring the format from the extension', async () => {
    const dir = await materialize(mcpRepo());
    const r = await cli([dir, '--out', 'report.sarif'], { cwd: dir });
    expect(r.code).toBe(0);
    expect(r.out).toMatch(/Wrote sarif report to .*report\.sarif/);
    expect(JSON.parse(await readFile(join(dir, 'report.sarif'), 'utf8')).version).toBe('2.1.0');
    const j = await cli([dir, '--format', 'json']);
    expect(JSON.parse(j.out).findings.length).toBeGreaterThan(0);
  });

  it('several --out files write several formats from one audit, and --fail-on still applies', async () => {
    const dir = await materialize(mcpRepo());
    const r = await cli([dir, '-o', 'r.txt', '-o', 'r.md', '-o', 'r.sarif', '-o', 'r.json', '--fail-on', 'fix-now'], { cwd: dir });
    expect(r.code).toBe(1);
    expect(r.out).toMatch(/Wrote text report to .*r\.txt/);
    expect(r.out).toMatch(/Wrote md report to .*r\.md/);
    const read = (f: string) => readFile(join(dir, f), 'utf8');
    expect(await read('r.txt')).toContain('Agent config audit');
    expect(await read('r.txt')).not.toContain('\u001b[');
    expect(await read('r.md')).toMatch(/^# /m);
    expect(JSON.parse(await read('r.sarif')).version).toBe('2.1.0');
    expect(JSON.parse(await read('r.json')).findings.length).toBeGreaterThan(0);
    const bad = await cli([dir, '-f', 'json', '-o', 'a.json', '-o', 'b.md'], { cwd: dir });
    expect(bad.code).toBe(2);
    expect(bad.err).toContain('--format works with one --out');
  });

  it('--only and --baseline', async () => {
    const dir = await materialize({ ...mcpRepo(), ...skillsRepo() });
    const only = JSON.parse((await cli([dir, '--only', 'hidden', '--format', 'json'])).out);
    expect(new Set(only.findings.map((f: { family: string }) => f.family))).toEqual(new Set(['hidden']));
    await cli([dir, '--format', 'json', '--out', 'baseline.json'], { cwd: dir });
    const again = await cli([dir, '--baseline', 'baseline.json', '--fail-on', 'should-fix'], { cwd: dir });
    expect(again.code).toBe(0);
    expect(again.out).toMatch(/in baseline/);
    expect(again.out).toMatch(/No findings outside the baseline \(\d+ hidden\)/);
    // A SARIF log works as a baseline too.
    await cli([dir, '--format', 'sarif', '--out', 'b.sarif'], { cwd: dir });
    const fromSarif = JSON.parse((await cli([dir, '--baseline', 'b.sarif', '--format', 'json'], { cwd: dir })).out);
    expect(fromSarif.findings).toEqual([]);
  });

  it('lock then diff: exit 0 when unchanged, 1 when changed, 2 without a lock', async () => {
    const dir = await materialize(mcpRepo());
    const none = await cli(['diff', dir]);
    expect(none.code).toBe(2);
    expect(none.err).toMatch(/no lockfile.*Run `agent-config-audit lock/);
    const lock = await cli(['lock', dir]);
    expect(lock.code).toBe(0);
    expect(lock.out).toMatch(/Wrote .*agent-config\.lock: \d+ entries/);
    expect((await cli(['lock', dir])).out).toMatch(/is up to date/);
    expect((await cli(['diff', dir])).code).toBe(0);
    const mcp = JSON.parse(await readFile(join(dir, '.mcp.json'), 'utf8'));
    mcp.mcpServers.fs.command = 'pnpm';
    await writeFile(join(dir, '.mcp.json'), JSON.stringify(mcp));
    const d = await cli(['diff', dir]);
    expect(d.code).toBe(1);
    expect(d.out).toContain('MCP server `fs` in .mcp.json command changed from `npx` to `pnpm`');
    const dj = JSON.parse((await cli(['diff', dir, '--format', 'json'])).out);
    expect(dj.clean).toBe(false);
    const updated = await cli(['lock', dir]);
    expect(updated.out).toMatch(/Updated .*1 change/s);
  });

  it('rejects bad usage with exit code 2', async () => {
    expect((await cli(['--format', 'xml'])).code).toBe(2);
    expect((await cli(['--only', 'nope'])).code).toBe(2);
    expect((await cli(['--fail-on', 'review'])).code).toBe(2);
    expect((await cli(['--bogus'])).code).toBe(2);
    expect((await cli(['a', 'b'])).code).toBe(2);
    const missing = await cli(['/definitely/not/here']);
    expect(missing.code).toBe(2);
    expect(missing.err).toMatch(/No such directory/);
  });
});
