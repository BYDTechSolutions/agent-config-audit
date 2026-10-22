import { scrubSecrets } from './secrets.js';
import { escapeHidden } from './unicode.js';

/**
 * Makes any string from a scanned file safe to print: secrets redacted,
 * invisible characters escaped as `<U+XXXX>`, one line, and capped in length.
 */
export function safe(text: string, max = 160): string {
  const clean = escapeHidden(scrubSecrets(text)).replace(/\s+/g, ' ').trim();
  return clean.length > max ? `${clean.slice(0, max - 1)}…` : clean;
}

/** `` `text` `` with {@link safe} applied, using a fence that the text cannot break. */
export function code(text: string, max = 160): string {
  const s = safe(text, max);
  return s.includes('`') ? `"${s}"` : `\`${s}\``;
}

/** 1-based line number of a UTF-16 index. */
export function lineAt(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) if (text.charCodeAt(i) === 10) line++;
  return line;
}

/** Precomputed line starts, for many lookups in one file. */
export function lineIndex(text: string): (index: number) => number {
  const starts = [0];
  for (let i = 0; i < text.length; i++) if (text.charCodeAt(i) === 10) starts.push(i + 1);
  return (index: number) => {
    let lo = 0;
    let hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if ((starts[mid] as number) <= index) lo = mid;
      else hi = mid - 1;
    }
    return lo + 1;
  };
}
