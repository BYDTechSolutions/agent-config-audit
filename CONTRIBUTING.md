# Contributing

Thanks for helping. Issues and pull requests are welcome at
[github.com/BYDTechSolutions/agent-config-audit](https://github.com/BYDTechSolutions/agent-config-audit).

## Setup

```sh
npm ci
npm run typecheck
npm test
npm run build
```

Node.js 20 or later.

## Rules

- **Never execute what is scanned.** No `child_process`, no `eval`, no dynamic
  `import()` or `require()` of repository files, no network. `src/` may import
  only `node:fs`, `node:path`, `node:crypto` and `node:util`;
  `test/noexec.test.ts` enforces it and proves that marker scripts in a fixture
  repository never run.
- **Every vendor fact needs its source.** A file path, config key or size budget
  a rule depends on must come from the vendor's own documentation, linked in
  `src/facts/sources.ts`, with `FACTS_VERIFIED_ON` updated when you re-read it.
  If it cannot be verified from a primary source, leave the rule out.
- **Tags come from each list's own publication**: OWASP AST (the `astNN.md`
  files), ASI 2026 (the December 2025 PDF), LLM 2025, the MCP Top 10, CWE. Keep
  the AST ID first.
- **Low noise.** A finding names the file, line and key, says what was seen,
  why it matters in one or two sentences, and gives a concrete fix. Shell use in
  a skill is not a finding by itself.
- **Never say "safe".** Clean output says "No findings for the rules in this
  version; this is not a malware check."
- **Output is always safe to print**: secrets redacted (`redact`), invisible
  characters escaped (`escapeHidden`). `makeFinding` applies both again.
- **Fixtures are data.** Fixture repositories live in `test/fixtures/repos.ts`
  and are written to a temp directory at test time, so no agent working on this
  package loads them. Dangerous-looking strings use reserved names
  (`example.invalid`, `example.net`), invisible characters are written as
  escapes, and fake credentials are assembled at run time.
- No runtime dependencies without a strong reason, stated in the README.
- Add a line to `CHANGELOG.md` under "Unreleased".
- American English in code, messages and docs.
