/**
 * The standard IDs findings are tagged with, and their names, as read from each
 * list's own publication on 2026-10-23. Each list is cited independently: the
 * AST files' own crosswalk to LLM IDs uses pre-2025 numbering, so it is not
 * inherited here.
 */

/** The taxonomy version the AST tags follow. */
export const AST_VERSION = 'OWASP Agentic Skills Top 10, v1 (2026 edition, incubator)';

/** OWASP Agentic Skills Top 10 — github.com/OWASP/www-project-agentic-skills-top-10, ast01.md … ast10.md. */
export const AST: Record<string, { title: string; severity: string }> = {
  AST01: { title: 'Malicious Skills', severity: 'Critical' },
  AST02: { title: 'Supply Chain Compromise', severity: 'Critical' },
  AST03: { title: 'Over-Privileged Skills', severity: 'High' },
  AST04: { title: 'Insecure Metadata', severity: 'High' },
  AST05: { title: 'Untrusted External Instructions', severity: 'High' },
  AST06: { title: 'Weak Isolation', severity: 'High' },
  AST07: { title: 'Update Drift', severity: 'Medium' },
  AST08: { title: 'Poor Scanning', severity: 'Medium' },
  AST09: { title: 'No Governance', severity: 'Medium' },
  AST10: { title: 'Cross-Platform Reuse', severity: 'Medium' },
};

/** OWASP Top 10 for Agentic Applications 2026 (December 2025 PDF from genai.owasp.org). */
export const ASI: Record<string, string> = {
  ASI01: 'Agent Goal Hijack',
  ASI02: 'Tool Misuse and Exploitation',
  ASI03: 'Identity and Privilege Abuse',
  ASI04: 'Agentic Supply Chain Vulnerabilities',
  ASI05: 'Unexpected Code Execution (RCE)',
  ASI06: 'Memory & Context Poisoning',
  ASI07: 'Insecure Inter-Agent Communication',
  ASI08: 'Cascading Failures',
  ASI09: 'Human-Agent Trust Exploitation',
  ASI10: 'Rogue Agents',
};

/** OWASP Top 10 for LLM Applications 2025 (genai.owasp.org/llm-top-10). */
export const LLM: Record<string, string> = {
  LLM01: 'Prompt Injection',
  LLM02: 'Sensitive Information Disclosure',
  LLM03: 'Supply Chain',
  LLM04: 'Data and Model Poisoning',
  LLM05: 'Improper Output Handling',
  LLM06: 'Excessive Agency',
  LLM07: 'System Prompt Leakage',
  LLM08: 'Vector and Embedding Weaknesses',
  LLM09: 'Misinformation',
  LLM10: 'Unbounded Consumption',
};

/** OWASP MCP Top 10 (2025, beta) — owasp.org/www-project-mcp-top-10. */
export const MCP: Record<string, string> = {
  MCP01: 'Token Mismanagement & Secret Exposure',
  MCP02: 'Privilege Escalation via Scope Creep',
  MCP03: 'Tool Poisoning',
  MCP04: 'Software Supply Chain Attacks & Dependency Tampering',
  MCP05: 'Command Injection & Execution',
  MCP06: 'Prompt Injection via Contextual Payloads',
  MCP07: 'Insufficient Authentication & Authorization',
  MCP08: 'Lack of Audit and Telemetry',
  MCP09: 'Shadow MCP Servers',
  MCP10: 'Context Injection & Over-Sharing',
};

/** CWE titles (cwe.mitre.org, CWE 4.20) for every CWE a rule uses. */
export const CWE: Record<number, string> = {
  15: 'External Control of System or Configuration Setting',
  78: "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
  250: 'Execution with Unnecessary Privileges',
  295: 'Improper Certificate Validation',
  319: 'Cleartext Transmission of Sensitive Information',
  451: 'User Interface (UI) Misrepresentation of Critical Information',
  494: 'Download of Code Without Integrity Check',
  502: 'Deserialization of Untrusted Data',
  506: 'Embedded Malicious Code',
  798: 'Use of Hard-coded Credentials',
  829: 'Inclusion of Functionality from Untrusted Control Sphere',
  912: 'Hidden Functionality',
  1321: "Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')",
  1357: 'Reliance on Insufficiently Trustworthy Component',
};
