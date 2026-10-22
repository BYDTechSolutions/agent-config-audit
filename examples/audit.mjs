// Audit a directory and check it against its lockfile.
// Run from a project that has the package installed:  node audit.mjs [dir]
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { auditRepo, diffLock, formatDiff, formatReport, parseLock } from '@bydtech/agent-config-audit';

const dir = process.argv[2] ?? '.';
const report = await auditRepo(dir);
process.stdout.write(formatReport(report, 'text'));

const urgent = report.findings.filter((f) => f.priority === 'fix-now');
for (const f of urgent) console.log(`fix now: ${f.file}:${f.line ?? 1} ${f.title}`);

try {
  const lock = parseLock(await readFile(join(dir, 'agent-config.lock'), 'utf8'));
  const diff = await diffLock(dir, lock);
  process.stdout.write(formatDiff(diff));
  process.exitCode = urgent.length || !diff.clean ? 1 : 0;
} catch {
  console.log('No agent-config.lock yet: run `npx @bydtech/agent-config-audit lock` and commit it.');
  process.exitCode = urgent.length ? 1 : 0;
}
