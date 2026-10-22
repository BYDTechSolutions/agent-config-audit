/**
 * Every vendor page and standard a rule relies on. Each URL was opened and read
 * on {@link FACTS_VERIFIED_ON}; a rule that could not be checked against its
 * vendor's own documentation was left out. When a vendor changes a file path or
 * a key, the fix starts here.
 */
import type { Source } from '../types.js';

/** The day every source below was last read. */
export const FACTS_VERIFIED_ON = '2026-10-23';

const CC = 'https://code.claude.com/docs/en';

export const SOURCES = {
  // Claude Code
  ccTrust: { title: 'Claude Code: What runs before you trust a folder', url: `${CC}/permissions#what-runs-before-you-trust-a-folder` },
  ccPermissionSyntax: { title: 'Claude Code: Permission rule syntax', url: `${CC}/permissions#permission-rule-syntax` },
  ccHooks: { title: 'Claude Code: Hooks reference', url: `${CC}/hooks` },
  ccHookHandlers: { title: 'Claude Code: Hook handler fields', url: `${CC}/hooks#hook-handler-fields` },
  ccSettings: { title: 'Claude Code: Settings files', url: `${CC}/settings` },
  ccApiKeyHelper: { title: 'Claude Code settings: apiKeyHelper', url: `${CC}/settings-reference#apikeyhelper` },
  ccStatusLine: { title: 'Claude Code settings: statusLine', url: `${CC}/settings-reference#statusline` },
  ccDefaultMode: { title: 'Claude Code settings: permissions.defaultMode', url: `${CC}/settings-reference#permissions-defaultmode` },
  ccEnableAllMcp: { title: 'Claude Code settings: enableAllProjectMcpServers', url: `${CC}/settings-reference#enableallprojectmcpservers` },
  ccDisableAllHooks: { title: 'Claude Code: turn hooks off for a run', url: `${CC}/permissions#what-runs-before-you-trust-a-folder` },
  ccEnv: { title: 'Claude Code settings: env', url: `${CC}/settings-reference#env` },
  ccEnvVars: { title: 'Claude Code: Environment variables', url: `${CC}/env-vars` },
  ccLlmGateway: { title: 'Claude Code: LLM gateway configuration', url: `${CC}/llm-gateway` },
  ccNetwork: { title: 'Claude Code: Enterprise network configuration', url: `${CC}/network-config` },
  ccBypass: { title: 'Claude Code: bypassPermissions mode', url: `${CC}/permission-modes#skip-all-checks-with-bypasspermissions-mode` },
  ccCli: { title: 'Claude Code: CLI reference', url: `${CC}/cli-reference` },
  ccMcp: { title: 'Claude Code: MCP project scope (.mcp.json)', url: `${CC}/mcp#project-scope` },
  ccMcpEnv: { title: 'Claude Code: Environment variable expansion in .mcp.json', url: `${CC}/mcp#environment-variable-expansion-in-mcpjson` },
  ccSkills: { title: 'Claude Code: Skills', url: `${CC}/skills` },
  ccSkillsFrontmatter: { title: 'Claude Code: Skill frontmatter reference', url: `${CC}/skills#frontmatter-reference` },
  ccSkillsInject: { title: 'Claude Code: Inject dynamic context', url: `${CC}/skills#inject-dynamic-context` },
  ccSubagents: { title: 'Claude Code: Subagents', url: `${CC}/sub-agents` },
  ccPluginManifest: { title: 'Claude Code: Plugin manifest reference', url: `${CC}/plugins/manifest-reference` },
  ccMarketplace: { title: 'Claude Code: Plugin marketplace reference', url: `${CC}/plugins/marketplace-reference` },
  ccMemory: { title: 'Claude Code: How Claude remembers your project', url: `${CC}/memory` },
  ccMemoryAgentsMd: { title: 'Claude Code: When Claude Code reads AGENTS.md', url: `${CC}/memory#agents-md` },

  // MCP in other clients
  cursorMcp: { title: 'Cursor: Model Context Protocol', url: 'https://cursor.com/docs/context/mcp' },
  cursorRules: { title: 'Cursor: Rules', url: 'https://cursor.com/docs/context/rules' },
  cursorHooks: { title: 'Cursor: Hooks', url: 'https://cursor.com/docs/agent/hooks' },
  vscodeMcp: { title: 'VS Code: MCP configuration reference', url: 'https://code.visualstudio.com/docs/copilot/reference/mcp-configuration' },
  vscodeMcpServers: { title: 'VS Code: Use MCP servers', url: 'https://code.visualstudio.com/docs/copilot/customization/mcp-servers' },
  vscodePrompts: { title: 'VS Code: Prompt files', url: 'https://code.visualstudio.com/docs/copilot/customization/prompt-files' },
  vscodeAgents: { title: 'VS Code: Custom agents', url: 'https://code.visualstudio.com/docs/copilot/customization/custom-agents' },
  geminiMcp: { title: 'Gemini CLI: MCP servers', url: 'https://geminicli.com/docs/tools/mcp-server/' },
  geminiHooks: { title: 'Gemini CLI: Hooks', url: 'https://geminicli.com/docs/hooks/' },
  geminiMd: { title: 'Gemini CLI: GEMINI.md context files', url: 'https://geminicli.com/docs/cli/gemini-md/' },
  geminiSkills: { title: 'Gemini CLI: Agent Skills', url: 'https://geminicli.com/docs/cli/skills/' },
  geminiCli: { title: 'Gemini CLI: CLI reference', url: 'https://geminicli.com/docs/cli/cli-reference/' },
  codexMcp: { title: 'Codex: Model Context Protocol', url: 'https://learn.chatgpt.com/docs/extend/mcp?surface=cli' },
  codexAgentsMd: { title: 'Codex: Custom instructions with AGENTS.md', url: 'https://learn.chatgpt.com/docs/agent-configuration/agents-md' },

  // Instruction files
  copilotInstructions: { title: 'GitHub Docs: Adding repository custom instructions for Copilot', url: 'https://docs.github.com/en/copilot/how-tos/configure-custom-instructions/add-repository-instructions' },
  copilotReviewSize: { title: 'GitHub Docs: Customizing Copilot code review', url: 'https://docs.github.com/en/copilot/tutorials/customize-code-review' },
  agentsMd: { title: 'AGENTS.md', url: 'https://agents.md' },
  devinRules: { title: 'Devin Desktop (formerly Windsurf): Memories & Rules', url: 'https://docs.devin.ai/desktop/cascade/memories' },
  antigravityRules: { title: 'Google Antigravity: Rules', url: 'https://antigravity.google/docs/rules' },
  antigravitySkills: { title: 'Google Antigravity: Skills', url: 'https://antigravity.google/docs/skills' },
  openclawSkills: { title: 'OpenClaw: Skills', url: 'https://docs.openclaw.ai/tools/skills' },
  agentsMdStudy: { title: 'Evaluating AGENTS.md: Are Repository-Level Context Files Helpful for Coding Agents? (arXiv 2602.11988)', url: 'https://arxiv.org/abs/2602.11988' },

  // Agent Skills spec
  skillsSpec: { title: 'Agent Skills specification', url: 'https://agentskills.io/specification' },

  // Standards
  ast01: { title: 'OWASP AST01: Malicious Skills', url: 'https://github.com/OWASP/www-project-agentic-skills-top-10/blob/main/ast01.md' },
  ast02: { title: 'OWASP AST02: Supply Chain Compromise', url: 'https://github.com/OWASP/www-project-agentic-skills-top-10/blob/main/ast02.md' },
  ast03: { title: 'OWASP AST03: Over-Privileged Skills', url: 'https://github.com/OWASP/www-project-agentic-skills-top-10/blob/main/ast03.md' },
  ast04: { title: 'OWASP AST04: Insecure Metadata', url: 'https://github.com/OWASP/www-project-agentic-skills-top-10/blob/main/ast04.md' },
  ast05: { title: 'OWASP AST05: Untrusted External Instructions', url: 'https://github.com/OWASP/www-project-agentic-skills-top-10/blob/main/ast05.md' },
  ast07: { title: 'OWASP AST07: Update Drift', url: 'https://github.com/OWASP/www-project-agentic-skills-top-10/blob/main/ast07.md' },
  ast08: { title: 'OWASP AST08: Poor Scanning', url: 'https://github.com/OWASP/www-project-agentic-skills-top-10/blob/main/ast08.md' },
  uts55: { title: 'Unicode Technical Standard #55: Unicode Source Code Handling', url: 'https://www.unicode.org/reports/tr55/' },
  unicodeTags: { title: 'Unicode Tags block (U+E0000–U+E007F)', url: 'https://www.unicode.org/Public/latest/charts/PDF/UE0000.pdf' },
  githubHiddenUnicode: { title: 'GitHub changelog: warning about hidden Unicode text', url: 'https://github.blog/changelog/2025-05-01-github-now-provides-a-warning-about-hidden-unicode-text' },

  // Runtimes and tools
  npx: { title: 'npm Docs: npx', url: 'https://docs.npmjs.com/cli/v11/commands/npx' },
  uvTools: { title: 'uv: Using tools (uvx)', url: 'https://docs.astral.sh/uv/guides/tools/' },
  dockerRun: { title: 'Docker Docs: docker container run', url: 'https://docs.docker.com/reference/cli/docker/container/run/' },
  dockerPullDigest: { title: 'Docker Docs: Pull an image by digest', url: 'https://docs.docker.com/reference/cli/docker/image/pull/#pull-an-image-by-digest-immutable-identifier' },
  nodeOptions: { title: 'Node.js: NODE_OPTIONS', url: 'https://nodejs.org/api/cli.html#node_optionsoptions' },
  nodeExtraCa: { title: 'Node.js: NODE_EXTRA_CA_CERTS', url: 'https://nodejs.org/api/cli.html#node_extra_ca_certsfile' },
  ldso: { title: 'ld.so(8): LD_PRELOAD', url: 'https://man7.org/linux/man-pages/man8/ld.so.8.html' },
  cwe798: { title: 'CWE-798: Use of Hard-coded Credentials', url: 'https://cwe.mitre.org/data/definitions/798.html' },
} satisfies Record<string, Source>;

export type SourceKey = keyof typeof SOURCES;
