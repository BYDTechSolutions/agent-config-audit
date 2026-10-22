/**
 * Lists a repository's files without following symlinks and without reading
 * anything. Reading happens later, only for files that belong to an agent
 * surface, and only as bytes: nothing found here is ever executed or imported.
 */
import { constants } from 'node:fs';
import { lstat, open, readdir, readlink } from 'node:fs/promises';
import { isAbsolute, join, posix, relative, sep } from 'node:path';

/** A path in the repo, relative and with forward slashes. */
export interface Entry {
  path: string;
  /** `file` or `symlink` (directories are walked, not listed). */
  type: 'file' | 'symlink';
}

/** Directories never walked. */
export const ALWAYS_SKIPPED = ['.git', 'node_modules'];

/** Directory paths never walked: Claude Code's own worktree checkouts are copies of the repo. */
export const SKIPPED_PATHS = ['.claude/worktrees'];

export interface WalkResult {
  entries: Entry[];
  /** True when `maxFiles` cut the walk short. */
  truncated: boolean;
  /** Directories that could not be listed. */
  unreadableDirs: string[];
}

/** Walks `root`, breadth first, skipping `.git`, `node_modules` and the `exclude` prefixes. */
export async function walk(root: string, options: { exclude?: string[]; maxFiles?: number } = {}): Promise<WalkResult> {
  const max = options.maxFiles ?? 200_000;
  const exclude = (options.exclude ?? []).map((p) => p.replace(/\\/g, '/').replace(/^\.\//, '').replace(/\/+$/, '')).filter(Boolean);
  const entries: Entry[] = [];
  const unreadableDirs: string[] = [];
  const queue: string[] = [''];
  let truncated = false;
  while (queue.length) {
    const rel = queue.shift() as string;
    let names;
    try {
      names = await readdir(join(root, rel), { withFileTypes: true });
    } catch {
      unreadableDirs.push(rel || '.');
      continue;
    }
    names.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const d of names) {
      const path = rel ? `${rel}/${d.name}` : d.name;
      if (exclude.some((p) => path === p || path.startsWith(`${p}/`))) continue;
      if (d.isDirectory()) {
        if (!ALWAYS_SKIPPED.includes(d.name) && !SKIPPED_PATHS.some((s) => path === s || path.endsWith(`/${s}`))) queue.push(path);
        continue;
      }
      if (entries.length >= max) {
        truncated = true;
        break;
      }
      if (d.isSymbolicLink()) {
        entries.push({ path, type: 'symlink' });
      } else if (d.isFile()) {
        entries.push({ path, type: 'file' });
      }
    }
    if (truncated) break;
  }
  return { entries, truncated, unreadableDirs };
}

/** Size in bytes, without following a symlink. */
export async function sizeOf(root: string, path: string): Promise<number> {
  return (await lstat(join(root, path))).size;
}

/** Reads one file as bytes. Never follows a symlink (callers skip them) and never interprets the content. */
export async function readBytes(root: string, path: string): Promise<Buffer> {
  // O_NOFOLLOW (where the platform has it) refuses a file swapped for a symlink after the walk.
  const handle = await open(join(root, path), constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    return await handle.readFile();
  } finally {
    await handle.close();
  }
}

/**
 * Where a symlink points, as a repo-relative path, or `null` when it points
 * outside the repository. Reads the link itself; never opens the target.
 */
export async function linkTarget(root: string, path: string): Promise<string | null> {
  const t = await readlink(join(root, path));
  if (isAbsolute(t)) {
    const rel = relative(root, t);
    return rel.startsWith('..') || isAbsolute(rel) ? null : rel.split(sep).join('/');
  }
  const dir = path.includes('/') ? path.slice(0, path.lastIndexOf('/')) : '';
  const joined = posix.normalize(posix.join(dir, t.split(sep).join('/')));
  return joined.startsWith('..') ? null : joined;
}
