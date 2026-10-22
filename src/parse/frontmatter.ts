/**
 * Reads YAML frontmatter the way skill, rule and agent files use it: top-level
 * scalars, lists, block scalars and one level of nested maps. It is a reader,
 * not a YAML engine: type tags (`!!python/object`) are reported, never
 * interpreted, and anything deeper is kept as raw text for the rules to search.
 */

export type FmValue = string | number | boolean | null | FmValue[] | { [key: string]: FmValue };

export interface Frontmatter {
  /** True when the file starts with a `---` block. */
  present: boolean;
  /** Parsed top-level keys (null-prototype object). */
  data: Record<string, FmValue>;
  /** Line of each top-level key, 1-based in the file. */
  keyLines: Record<string, number>;
  /** The frontmatter text between the fences. */
  raw: string;
  /** 1-based line where the body starts. */
  bodyLine: number;
  /** The text after the closing fence. */
  body: string;
  /** Type tags such as `!!python/object/apply:os.system`, with their line. */
  tags: { line: number; text: string }[];
  /** Keys named `__proto__`, `constructor` or `prototype`, at any level. */
  protoKeys: { line: number; key: string }[];
  /** Problems reading it (unclosed block, duplicate keys…). */
  errors: string[];
}

function scalar(raw: string): FmValue {
  let s = raw.trim();
  if (s.startsWith('"')) {
    const end = s.lastIndexOf('"');
    try {
      return JSON.parse(s.slice(0, end > 0 ? end + 1 : undefined)) as string;
    } catch {
      return s.slice(1, end > 0 ? end : undefined);
    }
  }
  if (s.startsWith("'")) {
    const end = s.lastIndexOf("'");
    return s.slice(1, end > 0 ? end : undefined).replace(/''/g, "'");
  }
  s = s.replace(/\s+#.*$/, '');
  if (s === '' || s === '~' || s === 'null') return null;
  if (s === 'true' || s === 'True') return true;
  if (s === 'false' || s === 'False') return false;
  if (/^-?\d+(?:\.\d+)?$/.test(s)) return Number(s);
  if (s.startsWith('[') && s.endsWith(']')) {
    const inner = s.slice(1, -1).trim();
    return inner ? inner.split(',').map((x) => scalar(x)) : [];
  }
  return s;
}

const TAG = /(?:^|[\s:[{,-])(!!?[A-Za-z][\w./:-]*|!<[^>]*>)/;
const PROTO = new Set(['__proto__', 'constructor', 'prototype']);

/** Splits off and reads the frontmatter. Files without one return `present: false` and the whole text as body. */
export function parseFrontmatter(text: string): Frontmatter {
  const src = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
  const empty: Frontmatter = { present: false, data: Object.create(null), keyLines: Object.create(null), raw: '', bodyLine: 1, body: src, tags: [], protoKeys: [], errors: [] };
  const lines = src.split('\n');
  if (!/^---\s*$/.test(lines[0] ?? '')) return empty;
  let end = -1;
  for (let i = 1; i < lines.length; i++) {
    if (/^(?:---|\.\.\.)\s*$/.test(lines[i] as string)) {
      end = i;
      break;
    }
  }
  if (end < 0) return { ...empty, present: true, errors: ['The frontmatter block starts with `---` but is never closed.'] };

  const fm: Frontmatter = {
    ...empty,
    present: true,
    raw: lines.slice(1, end).join('\n'),
    bodyLine: end + 2,
    body: lines.slice(end + 1).join('\n'),
  };
  const block = lines.slice(1, end);
  for (let i = 0; i < block.length; i++) {
    const l = block[i] as string;
    if (/^\s*#/.test(l)) continue;
    const t = TAG.exec(l.replace(/(["']).*?\1/g, ''));
    if (t) fm.tags.push({ line: i + 2, text: (t[1] as string).trim() });
    const k = /^\s*["']?([^\s"':]+)["']?\s*:/.exec(l);
    if (k && PROTO.has(k[1] as string)) fm.protoKeys.push({ line: i + 2, key: k[1] as string });
  }

  let i = 0;
  while (i < block.length) {
    const l = block[i] as string;
    if (!l.trim() || /^\s*#/.test(l)) {
      i++;
      continue;
    }
    const m = /^([^\s#:][^:]*?)\s*:(?:\s+(.*)|\s*)$/.exec(l);
    if (!m || /^\s/.test(l)) {
      fm.errors.push(`Line ${i + 2} is not a \`key: value\` line.`);
      i++;
      continue;
    }
    const key = (m[1] as string).replace(/^["']|["']$/g, '');
    const rest = (m[2] ?? '').trim();
    if (key in fm.keyLines) fm.errors.push(`Key \`${key}\` appears twice (line ${i + 2}).`);
    fm.keyLines[key] = i + 2;
    i++;
    // Collect the indented continuation.
    const cont: string[] = [];
    while (i < block.length && (/^\s+\S/.test(block[i] as string) || /^-\s/.test(block[i] as string) || !(block[i] as string).trim())) {
      cont.push(block[i] as string);
      i++;
    }
    while (cont.length && !(cont[cont.length - 1] as string).trim()) cont.pop();
    if (/^[|>][+-]?\d*$/.test(rest)) {
      const indent = Math.min(...cont.filter((c) => c.trim()).map((c) => (/^\s*/.exec(c) as RegExpExecArray)[0].length));
      const body = cont.map((c) => c.slice(Number.isFinite(indent) ? indent : 0));
      fm.data[key] = rest.startsWith('|') ? body.join('\n') : body.join(' ').replace(/\s+/g, ' ').trim();
    } else if (rest) {
      fm.data[key] = cont.length ? scalar([rest, ...cont.map((c) => c.trim())].join(' ')) : scalar(rest);
    } else if (cont.length && cont.every((c) => !c.trim() || /^\s*-(?:\s|$)/.test(c) || /^\s{2,}/.test(c)) && /^\s*-(?:\s|$)/.test(cont.find((c) => c.trim()) ?? '')) {
      const items: FmValue[] = [];
      let raw: string[] = [];
      const flush = () => {
        if (!raw.length) return;
        const first = (raw[0] as string).replace(/^\s*-\s?/, '');
        items.push(raw.length === 1 && !/^[\w-]+\s*:\s/.test(first) ? scalar(first) : [first, ...raw.slice(1).map((r) => r.trim())].join('\n'));
        raw = [];
      };
      for (const c of cont) {
        if (/^\s*-(?:\s|$)/.test(c) && (/^\s*/.exec(c) as RegExpExecArray)[0].length <= ((/^\s*/.exec(cont[0] as string) as RegExpExecArray)[0].length)) {
          flush();
          raw.push(c);
        } else if (c.trim()) raw.push(c);
      }
      flush();
      fm.data[key] = items;
    } else if (cont.length) {
      const nested = Object.create(null) as Record<string, FmValue>;
      const base = (/^\s*/.exec(cont[0] as string) as RegExpExecArray)[0].length;
      let ok = true;
      let lastKey: string | null = null;
      for (const c of cont) {
        if (!c.trim()) continue;
        const ind = (/^\s*/.exec(c) as RegExpExecArray)[0].length;
        const nm = /^\s*([^\s#:][^:]*?)\s*:(?:\s+(.*)|\s*)$/.exec(c);
        if (ind === base && nm) {
          lastKey = (nm[1] as string).replace(/^["']|["']$/g, '');
          nested[lastKey] = nm[2] !== undefined ? scalar(nm[2]) : null;
        } else if (ind > base && lastKey) {
          const prev = nested[lastKey];
          nested[lastKey] = `${typeof prev === 'string' ? `${prev}\n` : ''}${c.trim()}`;
          ok = false;
        } else ok = false;
      }
      fm.data[key] = ok ? nested : cont.join('\n');
      if (!ok && Object.keys(nested).length) fm.data[key] = nested;
    } else {
      fm.data[key] = null;
    }
  }
  return fm;
}
