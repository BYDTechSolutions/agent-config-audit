/**
 * A small JSON parser that also accepts comments and trailing commas (VS Code's
 * JSONC), records the line of every key, and reports duplicate keys and
 * prototype-polluting keys. Objects are built without a prototype, so a
 * `__proto__` key in a scanned file is just data.
 */

export type Json = null | boolean | number | string | Json[] | JsonObject;
export interface JsonObject {
  [key: string]: Json;
}

export type JsonPath = (string | number)[];

/** A parsed document. */
export interface JsonDoc {
  value: Json;
  /** Line (1-based) where the key or array element at `path` starts. */
  lineOf(path: JsonPath): number | undefined;
  duplicates: { path: JsonPath; line: number }[];
  protoKeys: { path: JsonPath; line: number }[];
}

/** A syntax error, with where it happened. */
export class JsonSyntaxError extends Error {
  constructor(
    message: string,
    readonly line: number,
  ) {
    super(`${message} (line ${line})`);
  }
}

const PROTO_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

/** Parses JSON. With `jsonc`, `//` and block comments and trailing commas are allowed. */
export function parseJson(text: string, options: { jsonc?: boolean } = {}): JsonDoc {
  const src = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
  let pos = 0;
  let line = 1;
  const lines = new Map<string, number>();
  const duplicates: { path: JsonPath; line: number }[] = [];
  const protoKeys: { path: JsonPath; line: number }[] = [];
  const jsonc = options.jsonc ?? false;

  const fail = (msg: string): never => {
    throw new JsonSyntaxError(msg, line);
  };
  const skip = () => {
    for (;;) {
      const c = src[pos];
      if (c === '\n') {
        line++;
        pos++;
      } else if (c === ' ' || c === '\t' || c === '\r') pos++;
      else if (c === '/' && src[pos + 1] === '/' && jsonc) {
        while (pos < src.length && src[pos] !== '\n') pos++;
      } else if (c === '/' && src[pos + 1] === '*' && jsonc) {
        const end = src.indexOf('*/', pos + 2);
        if (end < 0) fail('Unterminated comment');
        for (let i = pos; i < end; i++) if (src[i] === '\n') line++;
        pos = end + 2;
      } else break;
    }
  };
  const str = (): string => {
    pos++; // opening quote
    let out = '';
    for (;;) {
      if (pos >= src.length) fail('Unterminated string');
      const c = src[pos] as string;
      if (c === '"') {
        pos++;
        return out;
      }
      if (c === '\n') fail('Newline in string');
      if (c === '\\') {
        const e = src[pos + 1];
        pos += 2;
        if (e === 'u') {
          const hex = src.slice(pos, pos + 4);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) fail('Bad \\u escape');
          out += String.fromCharCode(parseInt(hex, 16));
          pos += 4;
        } else {
          const map: Record<string, string> = { '"': '"', '\\': '\\', '/': '/', b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' };
          const v = e === undefined ? undefined : map[e];
          if (v === undefined) fail(`Bad escape \\${e ?? ''}`);
          out += v;
        }
        continue;
      }
      out += c;
      pos++;
    }
  };
  const value = (path: JsonPath, depth: number): Json => {
    if (depth > 200) fail('Nested too deeply');
    skip();
    const c = src[pos];
    if (c === '{') {
      pos++;
      const obj = Object.create(null) as JsonObject;
      const seen = new Set<string>();
      skip();
      if (src[pos] === '}') {
        pos++;
        return obj;
      }
      for (;;) {
        skip();
        if (jsonc && src[pos] === '}') {
          pos++;
          return obj;
        }
        if (src[pos] !== '"') fail('Expected a property name');
        const keyLine = line;
        const key = str();
        const childPath = [...path, key];
        if (seen.has(key)) duplicates.push({ path: childPath, line: keyLine });
        seen.add(key);
        if (PROTO_KEYS.has(key)) protoKeys.push({ path: childPath, line: keyLine });
        lines.set(JSON.stringify(childPath), keyLine);
        skip();
        if (src[pos] !== ':') fail('Expected ":"');
        pos++;
        obj[key] = value(childPath, depth + 1);
        skip();
        if (src[pos] === ',') {
          pos++;
          continue;
        }
        if (src[pos] === '}') {
          pos++;
          return obj;
        }
        fail('Expected "," or "}"');
      }
    }
    if (c === '[') {
      pos++;
      const arr: Json[] = [];
      skip();
      if (src[pos] === ']') {
        pos++;
        return arr;
      }
      for (;;) {
        skip();
        if (jsonc && src[pos] === ']') {
          pos++;
          return arr;
        }
        const childPath = [...path, arr.length];
        lines.set(JSON.stringify(childPath), line);
        arr.push(value(childPath, depth + 1));
        skip();
        if (src[pos] === ',') {
          pos++;
          continue;
        }
        if (src[pos] === ']') {
          pos++;
          return arr;
        }
        fail('Expected "," or "]"');
      }
    }
    if (c === '"') return str();
    const lit = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(src.slice(pos, pos + 64));
    if (!lit) fail(pos >= src.length ? 'Unexpected end of file' : `Unexpected character ${JSON.stringify(c)}`);
    const tok = (lit as RegExpExecArray)[0];
    pos += tok.length;
    return tok === 'true' ? true : tok === 'false' ? false : tok === 'null' ? null : Number(tok);
  };

  const root = value([], 0);
  skip();
  if (pos < src.length) fail('Unexpected content after the document');
  return {
    value: root,
    lineOf: (path) => lines.get(JSON.stringify(path)),
    duplicates,
    protoKeys,
  };
}

/** `hooks.PreToolUse[0].command`, or `env["my-key"]` for keys that are not identifiers. */
export function formatPath(path: JsonPath): string {
  let out = '';
  for (const p of path) {
    if (typeof p === 'number') out += `[${p}]`;
    else if (/^[A-Za-z_$][\w$-]*$/.test(p)) out += out ? `.${p}` : p;
    else out += `[${JSON.stringify(p)}]`;
  }
  return out;
}

/** Narrowing helpers. */
export const isObject = (v: Json | undefined): v is JsonObject => typeof v === 'object' && v !== null && !Array.isArray(v);
export const isString = (v: Json | undefined): v is string => typeof v === 'string';
export const stringArray = (v: Json | undefined): string[] => (Array.isArray(v) ? v.filter(isString) : []);
