import { mkdir, mkdtemp, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { afterAll } from 'vitest';
import { main, type CliIo } from '../src/cli-main.js';

/** A fixture repo: path → text (or bytes). */
export type Files = Record<string, string | Uint8Array>;

const made: string[] = [];
afterAll(async () => {
  for (const d of made) await rm(d, { recursive: true, force: true });
});

/**
 * Writes a fixture repo into a fresh temp directory. Fixtures live in
 * TypeScript, not as real `.claude/` or `SKILL.md` files in this repository, so
 * no agent working on this package ever loads them.
 */
export async function materialize(files: Files): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'aca-'));
  made.push(dir);
  for (const [path, content] of Object.entries(files)) {
    const full = join(dir, path);
    await mkdir(dirname(full), { recursive: true });
    await writeFile(full, content);
  }
  return dir;
}

/** Every file under a directory, relative. */
export async function listAll(dir: string, prefix = ''): Promise<string[]> {
  const out: string[] = [];
  for (const d of await readdir(join(dir, prefix), { withFileTypes: true })) {
    const p = prefix ? `${prefix}/${d.name}` : d.name;
    if (d.isDirectory()) out.push(...(await listAll(dir, p)));
    else out.push(p);
  }
  return out;
}

/** Runs the CLI in-process and captures its output. */
export async function cli(args: string[], options: { cwd?: string; files?: Map<string, string> } = {}) {
  const out: string[] = [];
  const err: string[] = [];
  const io: CliIo = {
    stdout: (t) => out.push(t),
    stderr: (t) => err.push(t),
    env: {},
    stdoutIsTTY: false,
    ...(options.cwd ? { cwd: options.cwd } : {}),
  };
  const code = await main(args, io);
  return { code, out: out.join(''), err: err.join('') };
}

/** Fake credentials, assembled at run time so no scanner mistakes this source for a leak. */
export const FAKE = {
  github: ['gh', 'p_', 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8'].join(''),
  anthropic: ['sk-', 'ant-', 'api03-', 'Zz9Yy8Xx7Ww6Vv5Uu4Tt3Ss2Rr1Qq0Pp'].join(''),
  slack: ['xo', 'xb-', '1234567890-abcdefghijKLMN'].join(''),
};
