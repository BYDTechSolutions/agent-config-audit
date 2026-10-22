/**
 * The shapes `auditRepo` takes and returns. Everything here is plain data, so a
 * report survives `JSON.stringify` and can be rendered later, anywhere.
 */

/** Rule families, in report order. */
export type Family = 'exec' | 'mcp' | 'secrets' | 'hidden' | 'prose' | 'refs' | 'skill' | 'unscannable' | 'hygiene';

/** Every family, in report order. */
export const FAMILIES: readonly Family[] = ['exec', 'mcp', 'secrets', 'hidden', 'prose', 'refs', 'skill', 'unscannable', 'hygiene'];

/** Human names for the families. */
export const FAMILY_NAMES: Record<Family, string> = {
  exec: 'Execution surfaces',
  mcp: 'MCP servers',
  secrets: 'Secrets',
  hidden: 'Hidden content',
  prose: 'Dangerous instructions',
  refs: 'External references',
  skill: 'Skill metadata',
  unscannable: 'Unscannable files',
  hygiene: 'Context hygiene',
};

/**
 * How soon a finding deserves attention.
 *
 * - `fix-now`: something an agent can run or leak today, or content hidden from human review.
 * - `should-fix`: a real risk with a known fix, or a file this tool could not check.
 * - `review`: something that runs or loads, worth a human look; often fine once understood.
 */
export type Priority = 'fix-now' | 'should-fix' | 'review';

/** Priorities from most to least urgent. */
export const PRIORITIES: readonly Priority[] = ['fix-now', 'should-fix', 'review'];

/** Human names for the priorities. */
export const PRIORITY_NAMES: Record<Priority, string> = {
  'fix-now': 'Fix now',
  'should-fix': 'Should fix',
  review: 'Review',
};

/** Severity for SARIF (`security-severity`). `none` is for non-security rules (context hygiene). */
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'none';

/** A primary source a rule relies on: the vendor or standard's own page. */
export interface Source {
  title: string;
  url: string;
}

/** Standard IDs a rule maps to. The AST ID comes first everywhere it is printed. */
export interface RuleTags {
  /** OWASP Agentic Skills Top 10 (v1, 2026), e.g. `AST02`. */
  ast?: string;
  /** OWASP Top 10 for Agentic Applications 2026, e.g. `ASI05`. */
  asi?: string[];
  /** OWASP Top 10 for LLM Applications 2025, e.g. `LLM01`. */
  llm?: string[];
  /** OWASP MCP Top 10 (2025 beta), e.g. `MCP01`. */
  mcp?: string[];
  /** CWE numbers, e.g. `798`. */
  cwe?: number[];
}

/** One deterministic check. */
export interface Rule {
  /** Stable id, `family/name`, e.g. `mcp/unpinned-package`. */
  id: string;
  family: Family;
  priority: Priority;
  severity: Severity;
  /** One line: what the rule looks for. */
  title: string;
  /** Why it matters, in one or two sentences. */
  why: string;
  /** The usual fix. Findings may give a more specific one. */
  fix: string;
  tags: RuleTags;
  /** The documentation the rule is built on. */
  source: Source;
}

/** One thing to look at, with the evidence for it. Every string is already safe to print (secrets redacted, invisible characters escaped). */
export interface Finding {
  /** The rule id. */
  id: string;
  family: Family;
  priority: Priority;
  /** One line: what is wrong, naming the file or key. */
  title: string;
  /** Repo-relative path, with forward slashes. */
  file: string;
  /** 1-based line, when known. */
  line?: number;
  /** The config key or JSON path involved, e.g. `hooks.PreToolUse[0].hooks[0].command`. */
  key?: string;
  /** What we saw, with the values (redacted where secret). */
  observed: string;
  why: string;
  fix: string;
  source: Source;
  /** Flattened standard IDs, AST first: `AST02`, `ASI05`, `LLM03`, `MCP04`, `CWE-494`. */
  tags: string[];
  /** Stable across line moves: rule, file and the evidence. Used by baselines and SARIF. */
  fingerprint: string;
  /** Supporting lines, capped. */
  details?: string[];
}

/** What kind of agent surface something is. */
export type SurfaceKind =
  | 'settings'
  | 'hook'
  | 'helper'
  | 'env'
  | 'permissions'
  | 'mcp-server'
  | 'skill'
  | 'command'
  | 'agent'
  | 'plugin'
  | 'marketplace'
  | 'instructions'
  | 'rules'
  | 'prompt';

/** One item in the inventory: something an agent will load or run. */
export interface Surface {
  kind: SurfaceKind;
  /** Repo-relative path of the file that declares it (for a skill, its SKILL.md). */
  path: string;
  /** A short name: server name, skill name, hook event, setting key. */
  name: string;
  /** Which tools read it, e.g. `Claude Code`, `Cursor`. */
  tools: string[];
  /** True when it starts a process or runs a command. */
  runs: boolean;
  /** One line describing it (redacted, escaped). */
  summary: string;
}

/** Why a file was not read. */
export type UnreadReason = 'binary' | 'archive' | 'bytecode' | 'too-large' | 'symlink' | 'unreadable' | 'parse-error';

/** A file in an agent surface that this run could not check. It needs a human. */
export interface Unread {
  path: string;
  reason: UnreadReason;
  detail: string;
}

/** What this version can and cannot assess, per OWASP AST risk. */
export interface CoverageItem {
  id: string;
  title: string;
  status: 'partly-checked' | 'inventory-only' | 'not-assessed';
  /** How, or why not. */
  how: string;
}

/** The coverage section every report carries. */
export interface Coverage {
  ast: CoverageItem[];
  /** Things no rule here looks at. */
  notAssessed: string[];
  /** Files in agent surfaces that were not read. */
  unread: Unread[];
}

/** What `auditRepo` returns. There is deliberately no score and no "safe" verdict. */
export interface Report {
  tool: { name: string; version: string; url: string };
  /** The directory audited, as given. */
  root: string;
  startedAt: string;
  durationMs: number;
  /** The families this run covered. */
  families: Family[];
  /** Sorted by priority, then family, then file and line. */
  findings: Finding[];
  /** Findings hidden because the baseline already had them. */
  suppressed: number;
  /** Everything an agent will load or run. */
  inventory: Surface[];
  coverage: Coverage;
  stats: { filesSeen: number; filesRead: number; surfaces: number };
  notes: string[];
}

/** Options for {@link auditRepo}. Every one is optional. */
export interface AuditOptions {
  /** Only these families. Default: all. */
  only?: Family[];
  /** Repo-relative path prefixes to skip (in addition to `.git` and `node_modules`). */
  exclude?: string[];
  /**
   * Fingerprints to suppress, e.g. from an earlier JSON report. Suppressed
   * findings are counted in `report.suppressed`, not listed.
   */
  baseline?: Iterable<string>;
  /** Files larger than this are not read and are reported as needing review. Default `1_048_576` (1 MiB). */
  maxFileBytes?: number;
  /** Stop walking after this many files. Default `200_000`. */
  maxFiles?: number;
}
