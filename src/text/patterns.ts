/**
 * Patterns for commands and prose: download-and-run, persistence, secret files,
 * concealment, permission bypass, and URL classes that can change after review.
 * Every pattern is line-based and specific; plain shell use is not a finding.
 */

/** One pattern match in a text. */
export interface PatternHit {
  rule: string;
  /** UTF-16 index of the start of the match in the text. */
  index: number;
  /** The matched excerpt (raw; callers pass it through `safe`). */
  text: string;
  /** Extra words for the finding, e.g. which secret file. */
  detail?: string;
}

const SHELLS = String.raw`(?:sudo\s+(?:-\S+\s+)*)?(?:env\s+(?:\S+=\S*\s+)*)?(?:/(?:usr/)?(?:local/)?bin/)?(?:ba|z|da|k|fi|tc|c)?sh\b`;
const INTERPRETERS = String.raw`(?:python[0-9.]*|node|perl|ruby|php|pwsh|powershell|iex|Invoke-Expression)\b`;
const FETCHERS = String.raw`(?:curl|wget|fetch|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)`;

const DOWNLOAD_EXEC: RegExp[] = [
  new RegExp(String.raw`\b${FETCHERS}\b[^\n|]*(?:\|[^\n|]*)*?\|\s*(?:${SHELLS}|${INTERPRETERS})`, 'i'),
  new RegExp(String.raw`\b(?:ba|z|da|k)?sh\b[^\n]{0,40}(?:\$\(|<\()\s*(?:curl|wget)\b`, 'i'),
  /(?:^|[\s;&|])(?:source|\.)\s+<\(\s*(?:curl|wget)\b/i,
  new RegExp(String.raw`\bbase64\s+(?:-d|--decode|-D)\b[^\n]*\|\s*(?:${SHELLS}|${INTERPRETERS})`, 'i'),
  /\beval\s+["']?\$\(\s*(?:curl|wget|echo\s[^)]*\|\s*base64)/i,
  /\b(?:iex|Invoke-Expression)\s*\(?\s*(?:\(\s*)?(?:New-Object\s+(?:System\.)?Net\.WebClient|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b/i,
];

const DOWNLOAD_TO_FILE = /\b(?:curl|wget)\b[^\n]*(?:\s-o\s?\S|\s-O\b|\s--output[\s=]|\s>\s*\S|\s-o$)/i;
const MAKE_RUNNABLE = /\bchmod\s+(?:[ugoa]*\+x|[0-7]?[0-7][0-7][1357])\b|\bxattr\s+(?:-r\s+)?-d\s+com\.apple\.quarantine\b|\bxattr\s+-c\b/i;

const HOME = String.raw`(?:~|\$HOME|\$\{HOME\})`;
const WRITE = String.raw`(?:>>?|\btee\s+(?:-a\s+)?)\s*["']?`;
const PERSISTENCE: { re: RegExp; detail: string }[] = [
  { re: new RegExp(String.raw`${WRITE}${HOME}/\.(?:bashrc|bash_profile|bash_login|zshrc|zprofile|zshenv|zlogin|profile|config/fish/config\.fish)\b`), detail: 'a shell profile' },
  { re: new RegExp(String.raw`(?:${WRITE}|\b(?:cp|mv|install|ln\s+-s\w*)\s+\S+\s+["']?)${HOME}/\.ssh/`), detail: 'the SSH directory' },
  { re: /\|\s*crontab\b|\bcrontab\s+(?:-r\b|-e\b|-(?:\s|$)|[^\s-]\S*)/, detail: 'crontab' },
  { re: /\bgit\s+config\s+(?:[^\n]*\s)?--(?:global|system)\b(?![^\n]*--(?:get|list|unset)\b)(?=\s+\S+\s+\S)/, detail: 'global git config' },
  { re: new RegExp(String.raw`${HOME}/Library/LaunchAgents/|\blaunchctl\s+(?:load|bootstrap)\b|\bsystemctl\s+--user\s+enable\b`), detail: 'a login item or user service' },
  { re: new RegExp(String.raw`${WRITE}\S*\b(?:SOUL|MEMORY|IDENTITY|CLAUDE|AGENTS|GEMINI)\.md\b`), detail: 'an agent memory or instruction file' },
  { re: new RegExp(String.raw`${WRITE}${HOME}/\.(?:claude|cursor|gemini|codex|codeium)/`), detail: "another agent's config directory" },
];

const USER_DIR = String.raw`(?:~|\$HOME|\$\{HOME\}|/home/[^/\s]+|/Users/[^/\s]+|%USERPROFILE%)`;
const SECRET_FILES = new RegExp(
  String.raw`${USER_DIR}[/\\]\.(?:ssh[/\\](?:id_[a-z0-9_]+|identity)\b|aws[/\\]credentials\b|config[/\\]gcloud[/\\](?:credentials\.db|application_default_credentials\.json|access_tokens\.db)|netrc\b|docker[/\\]config\.json|kube[/\\]config\b|npmrc\b|pypirc\b|git-credentials\b|claude\.json\b)|\bsecurity\s+find-(?:generic|internet)-password\b|/etc/shadow\b`,
  'i',
);
const NETWORK = /\b(?:curl|wget|nc|ncat|netcat|scp|rsync|ftp|sftp|Invoke-WebRequest|iwr|irm)\b|https?:\/\//i;
const NEGATED = /\b(?:never|don['’]t|do not|must not|should not|avoid|deny|denied|block|blocked|forbid|forbidden|refuse|disallow)\b/i;

const CONCEAL: RegExp[] = [
  /\b(?:do not|don['’]t|never|must not)\s+(?:tell|mention|inform|reveal|show|disclose|report|alert|notify)\b[^.\n]{0,40}\b(?:the\s+)?user\b/i,
  /\bwithout\s+(?:telling|informing|notifying|alerting|asking)\s+(?:the\s+)?user\b/i,
  /\b(?:hide|conceal|keep)\b[^.\n]{0,30}\bfrom\s+(?:the\s+)?user\b/i,
];
const OVERRIDE = /\b(?:ignore|disregard|forget)\s+(?:all\s+|any\s+)?(?:(?:the|your)\s+)?(?:previous|prior|above|earlier|other|system)\s+(?:instructions|rules|guidelines|prompts?|directions)\b/i;
const DISABLE_SAFETY = /--dangerously-skip-permissions\b|--permission-mode[ =]["']?bypassPermissions\b|--approval-mode[ =]["']?yolo\b|(?:^|\s)--yolo\b/;
const FETCH_INSTRUCTIONS = /\b(?:follow|obey|execute|apply|load|fetch|adopt)\b[^.\n]{0,60}\b(?:instructions?|rules|guidelines|directives|system prompt|prompt)\b[^\n]{0,80}https?:\/\/|\b(?:instructions?|rules|guidelines|directives)\b[^.\n]{0,30}\b(?:at|from)\s+<?https?:\/\/[^\n]{0,40}\b(?:and|then)\s+(?:follow|obey|apply)/i;

function lines(text: string): { line: string; index: number }[] {
  const out: { line: string; index: number }[] = [];
  let index = 0;
  for (const line of text.split('\n')) {
    out.push({ line, index });
    index += line.length + 1;
  }
  return out;
}

/**
 * Patterns that matter wherever an agent may act on the text: commands in
 * hooks and MCP launch specs, scripts, and prose in skills and rules files.
 */
export function scanCommands(text: string): PatternHit[] {
  const hits: PatternHit[] = [];
  const ls = lines(text);
  for (let i = 0; i < ls.length; i++) {
    const { line, index } = ls[i] as { line: string; index: number };
    if (!line.trim()) continue;
    const de = DOWNLOAD_EXEC.map((re) => re.exec(line)).find(Boolean);
    if (de) hits.push({ rule: 'prose/download-exec', index: index + de.index, text: de[0] });
    if (!de && MAKE_RUNNABLE.test(line)) {
      const window = ls.slice(Math.max(0, i - 6), i + 1);
      const dl = window.find((w) => DOWNLOAD_TO_FILE.test(w.line));
      if (dl) hits.push({ rule: 'prose/download-then-run', index: dl.index, text: `${dl.line.trim()} … ${line.trim()}` });
    }
    const negated = NEGATED.test(line);
    for (const p of PERSISTENCE) {
      const m = p.re.exec(line);
      if (m && !negated) {
        hits.push({ rule: 'prose/persistence-write', index: index + m.index, text: m[0], detail: p.detail });
        break;
      }
    }
    const sf = SECRET_FILES.exec(line);
    if (sf && !negated) {
      const exfil = NETWORK.test(line);
      hits.push({ rule: exfil ? 'prose/secret-exfil' : 'prose/secret-file-read', index: index + sf.index, text: exfil ? line.trim() : sf[0], detail: sf[0] });
    }
    const ds = DISABLE_SAFETY.exec(line);
    if (ds && !negated) hits.push({ rule: 'prose/disable-safety', index: index + ds.index, text: ds[0].trim() });
  }
  return hits;
}

/** Patterns that only make sense in instructions written for a model. */
export function scanProse(text: string): PatternHit[] {
  const hits: PatternHit[] = [];
  for (const { line, index } of lines(text)) {
    const c = CONCEAL.map((re) => re.exec(line)).find(Boolean);
    if (c) hits.push({ rule: 'prose/conceal', index: index + c.index, text: c[0] });
    const o = OVERRIDE.exec(line);
    if (o) hits.push({ rule: 'prose/override-instructions', index: index + o.index, text: o[0] });
    const f = FETCH_INSTRUCTIONS.exec(line);
    if (f) {
      const url = extractUrls(line)[0];
      if (url && !isExampleHost(url.url)) hits.push({ rule: 'refs/fetch-instructions', index: index + f.index, text: line.trim(), detail: url.url });
    }
  }
  return hits;
}

/** Every http(s) URL in a text, with trailing punctuation trimmed. */
export function extractUrls(text: string): { url: string; index: number }[] {
  const out: { url: string; index: number }[] = [];
  for (const m of text.matchAll(/\bhttps?:\/\/[^\s<>"'`)\]}|\\]+/gi)) {
    const url = m[0].replace(/[.,;:!?*_~]+$/, '');
    out.push({ url, index: m.index ?? 0 });
  }
  return out;
}

const EXAMPLE_HOST = /(?:^|\.)(?:example\.(?:com|net|org)|example|invalid|test|localhost)$/i;

/** Reserved names (RFC 2606/6761): example.com, *.invalid, *.test, localhost. */
export function isExampleHost(url: string): boolean {
  try {
    return EXAMPLE_HOST.test(new URL(url).hostname);
  } catch {
    return true;
  }
}

/** True for loopback and private addresses, and `localhost`. */
export function isLocalHost(hostname: string): boolean {
  const h = hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (h === 'localhost' || h.endsWith('.localhost') || h === '::1' || h === '0.0.0.0') return true;
  const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(h);
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  return a === 127 || a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254);
}

const SHORTENERS = new Set(['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'ow.ly', 'cutt.ly', 'rb.gy', 'shorturl.at', 'buff.ly', 'tiny.cc', 'rebrand.ly', 't.ly', 's.id', 'v.gd', 'bl.ink', 'lnkd.in']);
const PASTE = new Set(['pastebin.com', 'paste.ee', 'hastebin.com', 'ghostbin.com', 'ghostbin.co', 'rentry.co', 'rentry.org', 'dpaste.org', 'dpaste.com', 'termbin.com', 'transfer.sh', 'controlc.com', 'justpaste.it', 'paste.rs', '0x0.st', 'privatebin.net', 'pastes.dev', 'paste.mozilla.org', 'pastie.org']);
const SHA = /^[0-9a-f]{40}$/i;
const VERSION_TAG = /^v?\d+(?:\.\d+)+(?:[-+][\w.]+)?$/;

/** Why a URL can serve different content after review, or `null`. */
export function classifyUrl(raw: string): { rule: string; detail: string } | null {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    return null;
  }
  const host = u.hostname.toLowerCase().replace(/^www\./, '');
  if (EXAMPLE_HOST.test(host)) return null;
  const segs = u.pathname.split('/').filter(Boolean);
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host) || host.startsWith('[')) {
    if (!isLocalHost(host)) return { rule: 'refs/ip-literal', detail: `host ${host}` };
    return null;
  }
  if (SHORTENERS.has(host)) return { rule: 'refs/shortener', detail: host };
  if (PASTE.has(host)) return { rule: 'refs/paste-site', detail: host };
  if (host === 'gist.githubusercontent.com') {
    // /<user>/<id>/raw/<revision>/<file> is pinned; /<user>/<id>/raw/<file> follows the latest revision.
    const rev = segs[3];
    if (!(segs[2] === 'raw' && rev && SHA.test(rev))) return { rule: 'refs/paste-site', detail: 'gist without a pinned revision' };
    return null;
  }
  if (host === 'gist.github.com') {
    if (!(segs[2] && SHA.test(segs[2]))) return { rule: 'refs/paste-site', detail: 'gist without a pinned revision' };
    return null;
  }
  if (/\/releases\/latest(?:\/|$)/.test(u.pathname)) return { rule: 'refs/releases-latest', detail: 'releases/latest' };
  let ref: string | undefined;
  if (host === 'raw.githubusercontent.com') ref = segs[2] === 'refs' ? `${segs[3]}/${segs[4]}` : segs[2];
  else if (host === 'github.com' && segs[2] === 'raw') ref = segs[3];
  if (ref !== undefined) {
    if (SHA.test(ref) || VERSION_TAG.test(ref)) return null;
    return { rule: 'refs/mutable-raw', detail: `ref \`${ref}\`` };
  }
  return null;
}
