# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-10-23

### Added

- `agent-config-audit [dir]`: finds every agent surface in a repository (Claude Code settings, hooks, skills, commands, subagents, plugins and marketplaces; MCP configs for Claude Code, Cursor, VS Code, Gemini CLI and Codex; Cursor, Copilot, Devin Desktop/Windsurf and Antigravity rules; AGENTS.md, CLAUDE.md and GEMINI.md at every level) and prints findings grouped as Fix now / Should fix / Review, an inventory of what an agent will load or run, and a coverage section.
- 76 deterministic rules in nine families (execution surfaces, MCP servers, secrets, hidden content, dangerous instructions, external references, skill metadata, unscannable files, context hygiene), each tagged OWASP AST first, then ASI 2026, LLM 2025, MCP Top 10 and CWE, and each citing the vendor or standard page it follows (read on 2026-10-23).
- `lock` writes `agent-config.lock` (sorted, timestamp-free JSON with a hash and a readable descriptor per surface; secret values stored only as hashes); `diff` names each change in plain words and exits 1 when anything changed.
- Output as text, JSON, Markdown or SARIF 2.1.0 for GitHub code scanning; `--out`, `--fail-on fix-now|should-fix`, `--baseline` (a JSON report or SARIF log), `--only`, `--exclude`, `--max-file-bytes`, `--list-rules`.
- API: `auditRepo`, `createLock`, `diffLock`, `compareLocks`, `formatReport`, `formatDiff`, the rule list and the sources.
- Never executes, imports or fetches anything it finds; no network; no runtime dependencies. Secrets are redacted and invisible characters escaped in every output.

[Unreleased]: https://github.com/BYDTechSolutions/agent-config-audit/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/BYDTechSolutions/agent-config-audit/releases/tag/v0.1.0
