/**
 * The parsed view of a repository's agent surfaces. `discover` builds it once;
 * the checks and the lockfile both read it, so they always agree on what exists.
 */
import type { Frontmatter } from './parse/frontmatter.js';
import type { Json, JsonDoc, JsonObject, JsonPath } from './parse/json.js';
import type { Unread } from './types.js';

/** What role a file plays. */
export type Role =
  | 'claude-settings'
  | 'mcp-config'
  | 'gemini-settings'
  | 'codex-config'
  | 'cursor-hooks'
  | 'plugin-hooks'
  | 'plugin-manifest'
  | 'marketplace'
  | 'skill'
  | 'skill-file'
  | 'plugin-file'
  | 'command'
  | 'agent'
  | 'instructions'
  | 'surface-file';

/** Instruction file flavors, for the context-hygiene rules. */
export type InstructionKind =
  | 'claude-md'
  | 'claude-local'
  | 'claude-rule'
  | 'agents-md'
  | 'gemini-md'
  | 'copilot'
  | 'copilot-path'
  | 'copilot-prompt'
  | 'cursor-rule'
  | 'cursor-rule-ignored'
  | 'windsurf-rule'
  | 'windsurf-legacy'
  | 'antigravity-rule';

export interface ScannedFile {
  path: string;
  role: Role;
  kind?: InstructionKind;
  /** Which tools read this file. */
  tools: string[];
  /** Decoded text, when the file was read. */
  text?: string;
  /** Why it was not read, when it was not. */
  unread?: Unread;
  /** For a symlink to another file in the repo: that file (which is scanned in its own right). */
  linkTarget?: string;
  /** SHA-256 of the raw bytes, when read (for the lockfile). */
  sha256?: string;
  bytes?: number;
}

export interface HookDef {
  file: string;
  tool: string;
  event: string;
  matcher?: string;
  type: string;
  command?: string;
  url?: string;
  line?: number;
  key: string;
  /** Where hooks of this kind live. */
  origin: 'settings' | 'plugin' | 'frontmatter' | 'cursor' | 'gemini';
}

export interface HelperDef {
  file: string;
  key: string;
  command: string;
  line?: number;
}

export interface McpServer {
  file: string;
  tool: string;
  name: string;
  transport: 'stdio' | 'http' | 'sse' | 'ws' | 'unknown';
  command?: string;
  args: string[];
  env: Record<string, string>;
  url?: string;
  headers: Record<string, string>;
  headersHelper?: string;
  trust?: boolean;
  /** Line of the server's key. */
  line?: number;
  /** Path of the server object, e.g. `["mcpServers","github"]`. */
  path: JsonPath;
  /** The raw config object, for line lookups of nested keys. */
  doc?: JsonDoc;
}

export interface SettingsFile {
  file: string;
  local: boolean;
  json: JsonObject;
  doc: JsonDoc;
}

export interface Skill {
  /** The skill directory, repo-relative. */
  dir: string;
  /** Path of SKILL.md. */
  file: string;
  tools: string[];
  fm: Frontmatter;
  /** Every file under the skill directory, repo-relative, sorted. */
  files: string[];
}

export interface JsonFile {
  file: string;
  json: Json;
  doc: JsonDoc;
}

export interface Model {
  root: string;
  /** Every surface file, read or not. */
  files: ScannedFile[];
  byPath: Map<string, ScannedFile>;
  /** Every path the walk saw (files and symlinks), for dead-reference checks. */
  paths: Set<string>;
  /** Every directory implied by `paths`. */
  dirs: Set<string>;
  settings: SettingsFile[];
  hooks: HookDef[];
  helpers: HelperDef[];
  servers: McpServer[];
  skills: Skill[];
  plugins: JsonFile[];
  marketplaces: JsonFile[];
  /** JSON documents by path (settings, MCP configs, hooks files, manifests) for duplicate and proto-key checks. */
  jsonDocs: Map<string, JsonDoc>;
  /** Frontmatter by path (skills, commands, agents, rules). */
  frontmatter: Map<string, Frontmatter>;
  walkTruncated: boolean;
  filesSeen: number;
}
