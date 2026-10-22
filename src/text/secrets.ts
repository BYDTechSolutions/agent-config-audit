/**
 * Credential detection and redaction. Patterns are deliberately narrow (known
 * token prefixes, private-key headers, secret-named keys with literal values) so
 * a finding is worth acting on. Output never carries a full secret.
 */

/** Token formats with a recognizable prefix. */
export const TOKEN_PATTERNS: { name: string; re: RegExp }[] = [
  { name: 'Anthropic API key', re: /\bsk-ant-[A-Za-z0-9_-]{20,}/g },
  { name: 'OpenAI API key', re: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}/g },
  { name: 'GitHub token', re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}/g },
  { name: 'GitHub fine-grained token', re: /\bgithub_pat_[A-Za-z0-9_]{22,}/g },
  { name: 'GitLab token', re: /\bglpat-[A-Za-z0-9_-]{20,}/g },
  { name: 'Slack token', re: /\bxox[abprs]-[A-Za-z0-9-]{10,}/g },
  { name: 'AWS access key ID', re: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g },
  { name: 'Google API key', re: /\bAIza[0-9A-Za-z_-]{35}/g },
  { name: 'npm token', re: /\bnpm_[A-Za-z0-9]{36}\b/g },
  { name: 'Stripe live key', re: /\b(?:sk|rk)_live_[A-Za-z0-9]{20,}/g },
  { name: 'Hugging Face token', re: /\bhf_[A-Za-z0-9]{30,}/g },
  { name: 'private key', re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/g },
];

/** A key name that says its value is a secret. */
export const SECRET_KEY = /(?:^|[_-])(?:TOKEN|SECRET|PASSWORD|PASSWD|PASS|API[_-]?KEY|APIKEY|ACCESS[_-]?KEY|PRIVATE[_-]?KEY|AUTH|AUTHORIZATION|CREDENTIALS?|BEARER)(?:$|[_-])|^authorization$|^x-api-key$/i;

/** `${VAR}`, `${VAR:-x}`, `${env:VAR}`, `${input:id}`, `$VAR`, `%VAR%`: a reference, not a value. */
const REFERENCE = /\$\{[^}]+\}|\$[A-Z_][A-Z0-9_]*|%[A-Z_][A-Z0-9_]*%/gi;
const HAS_REFERENCE = /\$\{[^}]+\}|\$[A-Z_][A-Z0-9_]*|%[A-Z_][A-Z0-9_]*%/i;

/** Obvious placeholders people leave in examples. */
const PLACEHOLDER = /^(?:<[^>]*>|\[[^\]]*\]|your[_-].*|.*(?:example|placeholder|changeme|replace[_-]?me|dummy|redacted|xxxx|\*\*\*|\.\.\.).*|todo|none|null|true|false|test|secret|password|token)$/i;

/** True when the value is only references to environment variables or inputs (after `Bearer `). */
export function isReferenceOnly(value: string): boolean {
  const stripped = value.replace(/^\s*(?:Bearer|Basic|Token)\s+/i, '').replace(REFERENCE, '').trim();
  return stripped.length === 0;
}

/**
 * True when a value of a secret-named key looks like a real literal credential:
 * not a reference, not a placeholder, at least 8 characters, no spaces.
 */
export function looksLikeLiteralSecret(value: string): boolean {
  const v = value.replace(/^\s*(?:Bearer|Basic|Token)\s+/i, '').trim();
  if (v.length < 8 || /\s/.test(v)) return false;
  if (HAS_REFERENCE.test(v)) return false;
  if (PLACEHOLDER.test(v)) return false;
  if (/^(.)\1+$/.test(v)) return false;
  return true;
}

/** `sk-a…Q2 (51 chars)`: first four and last two characters only. Short values show no characters at all. */
export function redact(value: string): string {
  if (value.length < 12) return `**** (${value.length} chars)`;
  return `${value.slice(0, 4)}…${value.slice(-2)} (${value.length} chars)`;
}

/** One credential found in text. */
export interface SecretMatch {
  name: string;
  index: number;
  value: string;
}

/** Finds known token formats in text. Skips AWS's published example key. */
export function findTokens(text: string): SecretMatch[] {
  const out: SecretMatch[] = [];
  for (const { name, re } of TOKEN_PATTERNS) {
    re.lastIndex = 0;
    for (const m of text.matchAll(re)) {
      if (/EXAMPLE/.test(m[0])) continue;
      if (out.some((o) => o.index <= (m.index ?? 0) && (m.index ?? 0) < o.index + o.value.length)) continue;
      out.push({ name, index: m.index ?? 0, value: m[0] });
    }
  }
  return out.sort((a, b) => a.index - b.index);
}

/** Replaces every known token in a string with its redacted form. Applied to all output. */
export function scrubSecrets(text: string): string {
  let out = text;
  for (const { re } of TOKEN_PATTERNS) {
    re.lastIndex = 0;
    out = out.replace(re, (m) => (m.startsWith('-----BEGIN') ? m : redact(m)));
  }
  // Inline credentials in URLs (user:password@host) and Authorization values.
  out = out.replace(/(\b[a-z][a-z0-9+.-]*:\/\/[^\s:/@]+:)([^\s@/]{4,})(@)/gi, (_m, a: string, p: string, b: string) => `${a}${redact(p)}${b}`);
  out = out.replace(/(\bBearer\s+)([A-Za-z0-9._~+/=-]{12,})/g, (_m, a: string, t: string) => (isReferenceOnly(t) ? `${a}${t}` : `${a}${redact(t)}`));
  return out;
}
