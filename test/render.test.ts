import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { auditRepo, CLEAN, formatReport, RULE_LIST } from '../src/index.js';
import { sarifTags, SECURITY_SEVERITY } from '../src/render/sarif.js';
import { claudeSettingsRepo, cleanRepo, mcpRepo, skillsRepo } from './fixtures/repos.js';
import { FAKE, materialize } from './helpers.js';

const FORMATS = ['text', 'json', 'md', 'sarif'] as const;

describe('output safety', async () => {
  const report = await auditRepo(await materialize({ ...claudeSettingsRepo(), ...mcpRepo(), ...skillsRepo() }));

  it('never prints a full secret in any format', () => {
    for (const format of FORMATS) {
      const out = formatReport(report, format);
      for (const secret of Object.values(FAKE)) expect(out, `${format} leaks a secret`).not.toContain(secret);
    }
    const text = formatReport(report, 'text');
    expect(text).toMatch(/GITHUB_TOKEN = ghp_…r8 \(\d+ chars\)/);
  });

  it('never prints invisible characters raw, only as U+ escapes', () => {
    for (const format of FORMATS) {
      const out = formatReport(report, format);
      expect(out, format).not.toMatch(/[‪-‮⁦-⁩​\u{E0000}-\u{E007F}]/u);
    }
    expect(formatReport(report, 'text')).toContain('<U+202E>');
  });

  it('text groups findings by priority and ends with the not-a-verdict line', () => {
    const text = formatReport(report, 'text');
    const a = text.indexOf('FIX NOW');
    const b = text.indexOf('SHOULD FIX');
    const c = text.indexOf('REVIEW (');
    expect(a).toBeGreaterThan(0);
    expect(b).toBeGreaterThan(a);
    expect(c).toBeGreaterThan(b);
    expect(text).toContain('WHAT AN AGENT WILL LOAD OR RUN');
    expect(text).toContain('NOT CHECKED: NEEDS HUMAN REVIEW');
    expect(text).toContain('Not assessed: AST06 Weak Isolation');
    expect(text).toContain('This is not a malware check.');
  });

  it('markdown has the findings, inventory table and coverage table', () => {
    const md = formatReport(report, 'md');
    expect(md).toMatch(/^# Agent config audit/);
    expect(md).toContain('## Fix now (');
    expect(md).toContain('| Kind | Name | File | Runs code | Read by | Summary |');
    expect(md).toContain('| AST06 Weak Isolation | not assessed |');
  });
});

describe('a clean report', async () => {
  const report = await auditRepo(await materialize(cleanRepo()));
  it('says "no findings… not a malware check" and never "safe" or "secure"', () => {
    for (const format of FORMATS) {
      const out = formatReport(report, format);
      expect(out).not.toMatch(/\bsafe\b|\bsecure\b/i);
    }
    expect(formatReport(report, 'text')).toContain(CLEAN);
    expect(formatReport(report, 'md')).toContain(CLEAN);
  });
});

describe('SARIF', async () => {
  const dir = await materialize({ ...claudeSettingsRepo(), ...mcpRepo(), ...skillsRepo() });
  const report = await auditRepo(dir);
  const sarif = JSON.parse(formatReport(report, 'sarif'));
  const run = sarif.runs[0];

  it('is SARIF 2.1.0 with one result per finding and rule metadata for every rule', () => {
    expect(sarif.version).toBe('2.1.0');
    expect(run.tool.driver.rules).toHaveLength(RULE_LIST.length);
    expect(run.results).toHaveLength(report.findings.length);
    expect(run.automationDetails.id).toBe('agent-config-audit/');
  });

  it('security rules carry a string security-severity in GitHub\'s ranges and tags with AST first', () => {
    for (const r of run.tool.driver.rules) {
      expect(r.shortDescription.text.length).toBeLessThanOrEqual(1024);
      expect(r.fullDescription.text.length).toBeLessThanOrEqual(1024);
      expect(r.help.text).toBeTruthy();
      expect(r.properties.tags.length).toBeLessThanOrEqual(10);
      if (r.id.startsWith('hygiene/')) {
        expect(r.properties['security-severity']).toBeUndefined();
        expect(r.defaultConfiguration.level).toBe('note');
        continue;
      }
      const sev = r.properties['security-severity'];
      expect(typeof sev).toBe('string');
      expect(Number(sev)).toBeGreaterThan(0);
      expect(Number(sev)).toBeLessThanOrEqual(10);
      expect(r.properties.tags[0]).toMatch(/^owasp-ast10:AST\d\d$/);
      expect(r.properties.tags).toContain('security');
    }
    expect(Number(SECURITY_SEVERITY.critical)).toBeGreaterThan(9.0);
    expect(sarifTags(RULE_LIST.find((r) => r.id === 'mcp/inline-secret')!)).toEqual(['owasp-ast10:AST03', 'owasp-asi-2026:ASI03', 'owasp-llm-2025:LLM02', 'owasp-mcp:MCP01', 'external/cwe/cwe-798', 'security']);
  });

  it('results have a relative location, a line and stable fingerprints', () => {
    for (const r of run.results) {
      const loc = r.locations[0].physicalLocation;
      expect(loc.artifactLocation.uri).not.toMatch(/^\//);
      expect(loc.region.startLine).toBeGreaterThanOrEqual(1);
      expect(r.partialFingerprints.primaryLocationLineHash).toMatch(/^[0-9a-f]{16}:1$/);
      expect(run.tool.driver.rules[r.ruleIndex].id).toBe(r.ruleId);
    }
  });

  it('fingerprints survive lines moving', async () => {
    const path = join(dir, '.claude/skills/prose/SKILL.md');
    const text = await readFile(path, 'utf8');
    await writeFile(path, text.replace('## Prerequisites', '## Intro\n\nSome words.\n\n## Prerequisites'));
    const moved = await auditRepo(dir);
    const before = report.findings.find((f) => f.id === 'prose/download-exec' && f.file.includes('prose'))!;
    const after = moved.findings.find((f) => f.id === 'prose/download-exec' && f.file.includes('prose'))!;
    expect(after.line).toBe((before.line as number) + 4);
    expect(after.fingerprint).toBe(before.fingerprint);
  });
});
