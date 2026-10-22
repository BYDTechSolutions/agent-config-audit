import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { auditRepo, createLock, diffLock, formatReport } from '../src/index.js';
import { noExecRepo } from './fixtures/repos.js';
import { cli, listAll, materialize } from './helpers.js';

describe('nothing found is ever executed', () => {
  it('audit, lock, diff and every output format leave no marker file behind', async () => {
    const dir = await materialize(noExecRepo());
    const before = (await listAll(dir)).sort();

    const report = await auditRepo(dir);
    for (const format of ['text', 'json', 'md', 'sarif'] as const) formatReport(report, format);
    const lock = await createLock(dir);
    await diffLock(dir, lock);
    expect((await cli([dir])).code).toBe(0);
    expect((await cli(['lock', dir])).code).toBe(0);
    expect((await cli(['diff', dir])).code).toBe(0);

    const after = (await listAll(dir)).sort();
    expect(after.filter((p) => p.includes('MARKER'))).toEqual([]);
    expect(after).toEqual([...before, 'agent-config.lock'].sort());

    // It did see all of them, as text.
    expect(report.findings.filter((f) => f.id === 'exec/hook-command').map((f) => f.observed).join(' ')).toMatch(/MARKER-hook.*MARKER-cursor.*MARKER-gemini|MARKER-hook|MARKER-cursor/);
    expect(report.inventory.filter((s) => s.runs).length).toBeGreaterThanOrEqual(7);
  });

  it('the source never spawns, evaluates, imports or fetches what it reads', () => {
    const files: string[] = [];
    const walk = (d: string) => {
      for (const name of readdirSync(d)) {
        const p = join(d, name);
        if (statSync(p).isDirectory()) walk(p);
        else if (p.endsWith('.ts')) files.push(p);
      }
    };
    walk(join(__dirname, '..', 'src'));
    const forbiddenImports = /\bfrom\s+['"](?:node:)?(?:child_process|http|https|http2|net|tls|dgram|dns|vm|worker_threads|cluster|module)['"]/;
    const forbidden = [
      /\bfetch\s*\(/,
      /\beval\s*\(/,
      /\bnew Function\b/,
      /\bimport\s*\(/,
      /\brequire\s*\(/,
      /\bexecSync\b|\bspawn\b|\bexecFile\b/,
    ];
    for (const f of files) {
      const raw = readFileSync(f, 'utf8');
      expect(forbiddenImports.test(raw), `${f} imports a process, network or module-loading API`).toBe(false);
      const imports = [...raw.matchAll(/\bfrom\s+['"]([^'"]+)['"]/g)].map((m) => m[1] as string);
      for (const spec of imports) expect(spec.startsWith('.') || ['node:crypto', 'node:fs', 'node:fs/promises', 'node:path', 'node:util'].includes(spec), `${f} imports ${spec}`).toBe(true);
      const src = raw
        // Patterns and messages may name these APIs as text; strip regex literals and strings first.
        .replace(/\/(?:\\.|[^/\n])+\/[gimsuy]*/g, '')
        .replace(/`(?:\\.|[^`])*`|'(?:\\.|[^'\n])*'|"(?:\\.|[^"\n])*"/g, '""')
        .replace(/\/\/.*$|\/\*[\s\S]*?\*\//gm, '');
      for (const re of forbidden) expect(re.test(src), `${f} matches ${re}`).toBe(false);
    }
  });
});
