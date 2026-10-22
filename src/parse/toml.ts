/**
 * Enough TOML to read Codex's `[mcp_servers.<name>]` tables: tables and dotted
 * table names, `key = value` with strings, numbers, booleans, arrays (also over
 * several lines) and inline tables. Unknown syntax is an error, which the audit
 * reports as "could not be parsed: needs human review".
 */

export type TomlValue = string | number | boolean | TomlValue[] | { [key: string]: TomlValue };
export type TomlTable = { [key: string]: TomlValue };

export class TomlSyntaxError extends Error {
  constructor(
    message: string,
    readonly line: number,
  ) {
    super(`${message} (line ${line})`);
  }
}

export interface TomlDoc {
  value: TomlTable;
  /** Line of each table header or key, by dotted path. */
  lines: Map<string, number>;
}

function splitKey(s: string, line: number): string[] {
  const parts: string[] = [];
  let i = 0;
  const src = s.trim();
  while (i < src.length) {
    while (src[i] === ' ' || src[i] === '\t') i++;
    if (src[i] === '"' || src[i] === "'") {
      const q = src[i] as string;
      const end = src.indexOf(q, i + 1);
      if (end < 0) throw new TomlSyntaxError('Unterminated quoted key', line);
      parts.push(src.slice(i + 1, end));
      i = end + 1;
    } else {
      const m = /^[A-Za-z0-9_-]+/.exec(src.slice(i));
      if (!m) throw new TomlSyntaxError(`Bad key ${JSON.stringify(src)}`, line);
      parts.push(m[0]);
      i += m[0].length;
    }
    while (src[i] === ' ' || src[i] === '\t') i++;
    if (i < src.length) {
      if (src[i] !== '.') throw new TomlSyntaxError(`Bad key ${JSON.stringify(src)}`, line);
      i++;
    }
  }
  return parts;
}

function parseValue(src: string, line: number): [TomlValue, number] {
  let i = 0;
  const ws = () => {
    while (i < src.length && /[\s]/.test(src[i] as string)) i++;
    if (src[i] === '#') {
      while (i < src.length && src[i] !== '\n') i++;
      ws();
    }
  };
  const val = (): TomlValue => {
    ws();
    const c = src[i];
    if (c === '"') {
      if (src.startsWith('"""', i)) {
        const end = src.indexOf('"""', i + 3);
        if (end < 0) throw new TomlSyntaxError('Unterminated string', line);
        const s = src.slice(i + 3, end).replace(/^\n/, '');
        i = end + 3;
        return s;
      }
      let out = '';
      i++;
      while (i < src.length && src[i] !== '"') {
        if (src[i] === '\\') {
          const e = src[i + 1] as string;
          const map: Record<string, string> = { n: '\n', t: '\t', r: '\r', '"': '"', '\\': '\\', b: '\b', f: '\f' };
          if (e === 'u' || e === 'U') {
            const len = e === 'u' ? 4 : 8;
            out += String.fromCodePoint(parseInt(src.slice(i + 2, i + 2 + len), 16));
            i += 2 + len;
            continue;
          }
          out += map[e] ?? e;
          i += 2;
          continue;
        }
        if (src[i] === '\n') throw new TomlSyntaxError('Newline in string', line);
        out += src[i];
        i++;
      }
      if (src[i] !== '"') throw new TomlSyntaxError('Unterminated string', line);
      i++;
      return out;
    }
    if (c === "'") {
      const triple = src.startsWith("'''", i);
      const q = triple ? "'''" : "'";
      const end = src.indexOf(q, i + q.length);
      if (end < 0) throw new TomlSyntaxError('Unterminated string', line);
      const s = src.slice(i + q.length, end);
      i = end + q.length;
      return triple ? s.replace(/^\n/, '') : s;
    }
    if (c === '[') {
      i++;
      const arr: TomlValue[] = [];
      for (;;) {
        ws();
        if (src[i] === ']') {
          i++;
          return arr;
        }
        arr.push(val());
        ws();
        if (src[i] === ',') {
          i++;
          continue;
        }
        if (src[i] === ']') {
          i++;
          return arr;
        }
        throw new TomlSyntaxError('Expected "," or "]" in array', line);
      }
    }
    if (c === '{') {
      i++;
      const obj = Object.create(null) as TomlTable;
      for (;;) {
        ws();
        if (src[i] === '}') {
          i++;
          return obj;
        }
        const eq = src.indexOf('=', i);
        if (eq < 0) throw new TomlSyntaxError('Expected "=" in inline table', line);
        const keys = splitKey(src.slice(i, eq), line);
        i = eq + 1;
        let target = obj;
        for (const k of keys.slice(0, -1)) target = (target[k] ??= Object.create(null) as TomlTable) as TomlTable;
        target[keys[keys.length - 1] as string] = val();
        ws();
        if (src[i] === ',') {
          i++;
          continue;
        }
        if (src[i] === '}') {
          i++;
          return obj;
        }
        throw new TomlSyntaxError('Expected "," or "}" in inline table', line);
      }
    }
    const m = /^(?:true|false|[+-]?(?:\d[\d_]*)(?:\.\d+)?(?:[eE][+-]?\d+)?|\d{4}-\d{2}-\d{2}[T ]?[\d:.Z+-]*)/.exec(src.slice(i));
    if (!m) throw new TomlSyntaxError(`Unexpected value ${JSON.stringify(src.slice(i, i + 20))}`, line);
    i += m[0].length;
    if (m[0] === 'true') return true;
    if (m[0] === 'false') return false;
    if (/^\d{4}-/.test(m[0])) return m[0];
    return Number(m[0].replace(/_/g, ''));
  };
  const v = val();
  return [v, i];
}

function balanced(s: string): boolean {
  let depth = 0;
  let q: string | null = null;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (q) {
      if (c === '\\' && q === '"') i++;
      else if (c === q) q = null;
    } else if (c === '"' || c === "'") q = c;
    else if (c === '#') {
      while (i < s.length && s[i] !== '\n') i++;
    } else if (c === '[' || c === '{') depth++;
    else if (c === ']' || c === '}') depth--;
  }
  return depth <= 0 && !q;
}

/** Parses the subset described above. */
export function parseToml(text: string): TomlDoc {
  const root = Object.create(null) as TomlTable;
  const lines = new Map<string, number>();
  let current = root;
  let prefix: string[] = [];
  const src = text.split('\n');
  for (let n = 0; n < src.length; n++) {
    const raw = src[n] as string;
    const t = raw.trim();
    if (!t || t.startsWith('#')) continue;
    const header = /^\[\[?\s*(.+?)\s*\]\]?\s*(?:#.*)?$/.exec(t);
    if (header && !t.includes('=')) {
      const arrayTable = t.startsWith('[[');
      prefix = splitKey(header[1] as string, n + 1);
      let target = root;
      for (const [idx, k] of prefix.entries()) {
        const last = idx === prefix.length - 1;
        if (last && arrayTable) {
          const arr = (target[k] ??= []) as TomlValue[];
          const t2 = Object.create(null) as TomlTable;
          arr.push(t2);
          target = t2;
        } else {
          const next = target[k];
          if (Array.isArray(next)) target = next[next.length - 1] as TomlTable;
          else target = (target[k] ??= Object.create(null) as TomlTable) as TomlTable;
        }
      }
      current = target;
      lines.set(prefix.join('.'), n + 1);
      continue;
    }
    const eq = raw.indexOf('=');
    if (eq < 0) throw new TomlSyntaxError(`Expected "key = value"`, n + 1);
    const keys = splitKey(raw.slice(0, eq), n + 1);
    let rest = raw.slice(eq + 1);
    const startLine = n + 1;
    while (!balanced(rest) && n + 1 < src.length) {
      n++;
      rest += `\n${src[n]}`;
    }
    if (/^\s*("""|''')/.test(rest)) {
      const q = (/("""|''')/.exec(rest) as RegExpExecArray)[1] as string;
      while (rest.indexOf(q, rest.indexOf(q) + 3) < 0 && n + 1 < src.length) {
        n++;
        rest += `\n${src[n]}`;
      }
    }
    const [value, used] = parseValue(rest, startLine);
    const tail = rest.slice(used).trim();
    if (tail && !tail.startsWith('#')) throw new TomlSyntaxError(`Unexpected ${JSON.stringify(tail.slice(0, 20))} after value`, n + 1);
    let target = current;
    for (const k of keys.slice(0, -1)) target = (target[k] ??= Object.create(null) as TomlTable) as TomlTable;
    target[keys[keys.length - 1] as string] = value;
    lines.set([...prefix, ...keys].join('.'), startLine);
  }
  return { value: root, lines };
}
