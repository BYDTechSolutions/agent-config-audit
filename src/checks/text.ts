/**
 * Checks that read text: hidden characters, padding and blobs; dangerous
 * commands and instructions; external references; credentials. They run on
 * every agent file that could be read, and on the command strings of hooks,
 * helpers and MCP servers.
 */
import type { Model, ScannedFile } from '../model.js';
import { formatPath } from '../parse/json.js';
import { classifyUrl, extractUrls, scanCommands, scanProse, type PatternHit } from '../text/patterns.js';
import { code, lineIndex, safe } from '../text/safe.js';
import { findTokens, redact } from '../text/secrets.js';
import { decodeTags, describeRun, findHidden } from '../text/unicode.js';
import type { Emit } from './emit.js';

const isMarkdown = (f: ScannedFile) => /\.(?:md|mdc|markdown|txt)$/i.test(f.path) || f.path.endsWith('.windsurfrules');
const PROSE_ROLES = new Set(['skill', 'skill-file', 'command', 'agent', 'instructions', 'plugin-file', 'surface-file']);

const PATTERN_TITLES: Record<string, (h: PatternHit) => string> = {
  'prose/download-exec': () => 'Downloads a script and pipes it to a shell',
  'prose/download-then-run': () => 'Downloads a file and makes it executable',
  'prose/persistence-write': (h) => `Writes to ${h.detail ?? 'a persistent location'}`,
  'prose/secret-file-read': (h) => `Reads ${h.detail ? code(h.detail, 40) : 'a secret file'}`,
  'prose/secret-exfil': (h) => `Sends ${h.detail ? code(h.detail, 40) : 'a secret file'} over the network`,
  'prose/disable-safety': (h) => `Runs an agent with ${code(h.text, 40)}`,
  'prose/conceal': () => 'Tells the agent to hide something from the user',
  'prose/override-instructions': () => 'Tells the agent to ignore its other instructions',
  'refs/fetch-instructions': () => 'Tells the agent to follow instructions from a URL',
};

function emitHits(emit: Emit, file: string, hits: PatternHit[], at: (i: number) => number, context?: { line?: number; key?: string; what: string }) {
  for (const h of hits) {
    emit(h.rule, {
      file,
      line: context?.line ?? at(h.index),
      ...(context?.key ? { key: context.key } : {}),
      title: `${(PATTERN_TITLES[h.rule] ?? (() => ''))(h) || h.rule}${context ? ` (${context.what})` : ''}`,
      observed: code(h.text, 160),
      evidence: `${context?.key ?? ''}:${h.text}`,
      ...(h.rule === 'refs/fetch-instructions' && h.detail ? { details: [`URL: ${h.detail}`] } : {}),
    });
  }
}

function urlFindings(emit: Emit, file: string, text: string, at: (i: number) => number, context?: { line?: number; key?: string; what: string }) {
  const seen = new Set<string>();
  for (const { url, index } of extractUrls(text)) {
    const c = classifyUrl(url);
    if (!c || seen.has(`${c.rule}:${url}`)) continue;
    seen.add(`${c.rule}:${url}`);
    emit(c.rule, { file, line: context?.line ?? at(index), ...(context?.key ? { key: context.key } : {}), title: `${titleFor(c.rule)}: ${code(url, 70)}${context ? ` (${context.what})` : ''}`, observed: `${code(url, 160)} (${c.detail})`, evidence: url });
  }
}

function titleFor(rule: string): string {
  return { 'refs/mutable-raw': 'Raw file on a branch', 'refs/releases-latest': 'Download from releases/latest', 'refs/paste-site': 'Paste site or unpinned gist', 'refs/shortener': 'Shortened link', 'refs/ip-literal': 'Bare IP address' }[rule] ?? rule;
}

export function textChecks(model: Model, emit: Emit): void {
  for (const f of model.files) {
    if (f.text === undefined) continue;
    const text = f.text;
    const at = lineIndex(text);

    // Hidden characters, grouped per kind.
    const runs = findHidden(text);
    for (const kind of ['bidi', 'tag', 'invisible'] as const) {
      const rs = runs.filter((r) => r.kind === kind);
      if (!rs.length) continue;
      const rule = kind === 'bidi' ? 'hidden/bidi-control' : kind === 'tag' ? 'hidden/tag-characters' : 'hidden/invisible-char';
      const count = rs.reduce((n, r) => n + r.codePoints.length, 0);
      const details = rs.slice(0, 10).map((r) => {
        const line = at(r.index);
        const lineText = text.split('\n')[line - 1] ?? '';
        const decoded = kind === 'tag' ? decodeTags(r.codePoints) : '';
        return `line ${line}: ${describeRun(r)}${decoded ? ` — spells "${safe(decoded, 100)}"` : ''} in ${code(lineText, 100)}`;
      });
      if (rs.length > 10) details.push(`… and ${rs.length - 10} more`);
      emit(rule, { file: f.path, line: at((rs[0] as { index: number }).index), title: `${count} ${kind === 'bidi' ? 'bidirectional control' : kind === 'tag' ? 'invisible tag' : 'invisible'} character${count === 1 ? '' : 's'} in ${f.path}`, observed: `${describeRun(rs[0] as (typeof rs)[number])} first at line ${at((rs[0] as { index: number }).index)}`, evidence: kind, details });
    }

    // Padding: long runs of blank lines, or a huge run of spaces on one line.
    const blank = /(?:^[ \t]*\r?\n){100,}/gm;
    for (const m of text.matchAll(blank)) {
      const n = (m[0].match(/\n/g) ?? []).length;
      emit('hidden/padding', { file: f.path, line: at(m.index ?? 0), title: `${n} blank lines in a row in ${f.path}`, observed: `${n} consecutive blank lines starting at line ${at(m.index ?? 0)}; content continues at line ${at((m.index ?? 0) + m[0].length)}`, evidence: `blank@${at(m.index ?? 0)}` });
      break;
    }
    const wide = /[ \t]{400,}/.exec(text);
    if (wide) emit('hidden/padding', { file: f.path, line: at(wide.index), title: `${wide[0].length} spaces in a row in ${f.path}`, observed: `${wide[0].length} consecutive spaces or tabs on line ${at(wide.index)}, then ${code(text.slice(wide.index + wide[0].length, wide.index + wide[0].length + 60), 60)}`, evidence: `wide@${at(wide.index)}` });

    // Base64 blobs (data URIs for images and fonts are left alone).
    if (!/\.svg$/i.test(f.path)) {
      const blobs = [...text.matchAll(/(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/]{200,}={0,2}(?![A-Za-z0-9+/=_-])/g)].filter((m) => !/data:(?:image|font)\/[\w.+-]+;base64,$/.test(text.slice(Math.max(0, (m.index ?? 0) - 60), m.index)));
      if (blobs.length) {
        const first = blobs[0] as RegExpMatchArray;
        let decoded = '';
        try {
          const d = Buffer.from(first[0], 'base64').toString('latin1');
          const printable = d.replace(/[^\x20-\x7e\n\t]/g, '').length / Math.max(1, d.length);
          if (printable > 0.9) decoded = ` — decodes to text starting ${code(d.slice(0, 80), 90)}`;
        } catch {
          decoded = '';
        }
        emit('hidden/base64-blob', { file: f.path, line: at(first.index ?? 0), title: `${blobs.length > 1 ? `${blobs.length} base64 blobs` : 'Base64 blob'} in ${f.path}`, observed: `${first[0].length}-character base64 string ${code(first[0].slice(0, 24), 30)}… at line ${at(first.index ?? 0)}${decoded}`, evidence: first[0].slice(0, 64) });
      }
    }

    // Long HTML comments in Markdown read by agents.
    if (isMarkdown(f) && PROSE_ROLES.has(f.role)) {
      for (const m of text.matchAll(/<!--([\s\S]*?)-->/g)) {
        const inner = (m[1] as string).trim();
        if (inner.replace(/\s+/g, '').length < 120) continue;
        emit('hidden/html-comment', { file: f.path, line: at(m.index ?? 0), observed: `HTML comment of ${inner.length} characters: ${code(inner, 120)}`, evidence: inner.slice(0, 80) });
      }
    }

    // Commands, instructions and URLs in files agents act on.
    if (PROSE_ROLES.has(f.role)) {
      emitHits(emit, f.path, scanCommands(text), at);
      if (isMarkdown(f)) emitHits(emit, f.path, scanProse(text), at);
      urlFindings(emit, f.path, text, at);
    }

    // Credentials in any agent file.
    for (const t of findTokens(text)) {
      emit('secrets/hardcoded', { file: f.path, line: at(t.index), title: `${t.name} in ${f.path}`, observed: t.name === 'private key' ? `a ${t.value} block` : `${t.name}: ${redact(t.value)}`, evidence: t.value.slice(0, 12) + t.value.length });
    }
  }

  // JSON structure: duplicate keys and prototype keys.
  for (const [path, doc] of model.jsonDocs) {
    for (const d of doc.duplicates) emit('hidden/duplicate-key', { file: path, line: d.line, key: formatPath(d.path), title: `Duplicate key ${code(formatPath(d.path), 60)} in ${path}`, observed: `${code(String(d.path[d.path.length - 1]), 40)} appears more than once in the same object; the last value wins`, evidence: formatPath(d.path) });
    for (const p of doc.protoKeys) emit('hidden/proto-key', { file: path, line: p.line, key: formatPath(p.path), title: `Key ${code(String(p.path[p.path.length - 1]), 20)} in ${path}`, observed: `key ${code(formatPath(p.path), 60)}`, evidence: formatPath(p.path) });
  }
  for (const [path, fm] of model.frontmatter) {
    for (const p of fm.protoKeys) emit('hidden/proto-key', { file: path, line: p.line, key: p.key, title: `Key ${code(p.key, 20)} in frontmatter of ${path}`, observed: `frontmatter key ${code(p.key, 20)}`, evidence: `fm:${p.key}` });
  }

  // Command strings in configs: hooks, helpers, MCP launches.
  const none = () => 1;
  for (const h of model.hooks) {
    if (!h.command && !h.url) continue;
    const ctx = { line: h.line, key: h.key, what: `${h.tool} hook ${h.event}` };
    if (h.command) emitHits(emit, h.file, scanCommands(h.command), none, ctx);
    urlFindings(emit, h.file, `${h.command ?? ''} ${h.url ?? ''}`, none, ctx);
  }
  for (const h of model.helpers) {
    const ctx = { line: h.line, key: h.key, what: h.key };
    emitHits(emit, h.file, scanCommands(h.command), none, ctx);
    urlFindings(emit, h.file, h.command, none, ctx);
  }
  for (const s of model.servers) {
    const launch = [s.command ?? '', ...s.args].join(' ');
    const ctx = { line: s.line, key: formatPath(s.path), what: `MCP server ${s.name}` };
    emitHits(emit, s.file, scanCommands(launch), none, ctx);
    urlFindings(emit, s.file, `${launch} ${s.url ?? ''}`, none, ctx);
  }
}
