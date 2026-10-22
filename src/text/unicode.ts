/**
 * Invisible and direction-changing characters: finding them, decoding tag
 * characters, and escaping them so output never contains them raw.
 */

/** Bidi embeddings, overrides, isolates and marks (UAX #9). */
const BIDI = new Set([0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069, 0x200e, 0x200f, 0x061c]);

const ZWJ = 0x200d;
const ZWNJ = 0x200c;
const BOM = 0xfeff;
const BLACK_FLAG = 0x1f3f4;

/** What kind of hidden character a code point is, or `null` when it is visible text. */
export type HiddenKind = 'bidi' | 'tag' | 'invisible';

const isTag = (cp: number) => cp >= 0xe0000 && cp <= 0xe007f;
const FORMAT = /^\p{Cf}$/u;
const PICTO = /^\p{Extended_Pictographic}$/u;
const EMOJI_PART = /^[\p{Extended_Pictographic}\p{Emoji_Modifier}\u{FE0F}\u{20E3}]$/u;
const LETTER_NON_ASCII = /^[^\x00-\x7f]$/u;
const LETTER = /^\p{L}$/u;
/** Fast pre-check: does the text contain anything `classify` could flag? */
const ANY_HIDDEN = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\p{Cf}\u{E0000}-\u{E007F}]/u;

function classify(cp: number): HiddenKind | null {
  if (BIDI.has(cp)) return 'bidi';
  if (isTag(cp)) return 'tag';
  if (cp === 0x09 || cp === 0x0a || cp === 0x0d) return null;
  if (cp < 0x20 || cp === 0x7f || (cp >= 0x80 && cp <= 0x9f)) return 'invisible';
  if (FORMAT.test(String.fromCodePoint(cp))) return 'invisible';
  return null;
}

/** One run of hidden characters of the same kind. */
export interface HiddenRun {
  kind: HiddenKind;
  /** Index in the string (UTF-16) of the first character. */
  index: number;
  /** The code points, in order. */
  codePoints: number[];
}

/**
 * Finds hidden characters, grouped into runs. Leaves out the uses that are
 * normal text: a byte-order mark at the very start, a zero-width joiner inside
 * an emoji sequence, a zero-width non-joiner between letters of a non-Latin
 * script, and tag characters that end a subdivision flag emoji.
 */
export function findHidden(text: string): HiddenRun[] {
  if (!ANY_HIDDEN.test(text)) return [];
  const chars = Array.from(text);
  const runs: HiddenRun[] = [];
  let index = 0;
  let current: HiddenRun | null = null;
  let inFlag = false;
  let prevEnd = -1;
  for (let i = 0; i < chars.length; i++) {
    const ch = chars[i] as string;
    const cp = ch.codePointAt(0) as number;
    let kind = classify(cp);
    if (kind === 'invisible' && cp === BOM && index === 0) kind = null;
    if (kind === 'invisible' && cp === ZWJ) {
      const prev = chars[i - 1] ?? '';
      const next = chars[i + 1] ?? '';
      if (EMOJI_PART.test(prev) && PICTO.test(next)) kind = null;
    }
    if (kind === 'invisible' && cp === ZWNJ) {
      const prev = chars[i - 1] ?? '';
      const next = chars[i + 1] ?? '';
      if (LETTER.test(prev) && LETTER.test(next) && LETTER_NON_ASCII.test(prev) && LETTER_NON_ASCII.test(next)) kind = null;
    }
    if (cp === BLACK_FLAG) inFlag = true;
    else if (kind === 'tag' && inFlag) {
      if (cp === 0xe007f) inFlag = false;
      kind = null;
    } else inFlag = false;

    if (kind) {
      if (current && current.kind === kind && prevEnd === index) {
        current.codePoints.push(cp);
      } else {
        current = { kind, index, codePoints: [cp] };
        runs.push(current);
      }
      prevEnd = index + ch.length;
    }
    index += ch.length;
  }
  return runs;
}

/** `U+202E` for one code point. */
export function codePointLabel(cp: number): string {
  return `U+${cp.toString(16).toUpperCase().padStart(4, '0')}`;
}

/** The ASCII text a run of tag characters spells (U+E0020–U+E007E map to ASCII 0x20–0x7E). */
export function decodeTags(codePoints: number[]): string {
  return codePoints
    .filter((cp) => cp >= 0xe0020 && cp <= 0xe007e)
    .map((cp) => String.fromCharCode(cp - 0xe0000))
    .join('');
}

/** Summarizes a run, e.g. `U+202E ×3` or `U+200B, U+200C`. */
export function describeRun(run: HiddenRun): string {
  const counts = new Map<number, number>();
  for (const cp of run.codePoints) counts.set(cp, (counts.get(cp) ?? 0) + 1);
  const parts = [...counts].slice(0, 6).map(([cp, n]) => (n > 1 ? `${codePointLabel(cp)} ×${n}` : codePointLabel(cp)));
  if (counts.size > 6) parts.push('…');
  return parts.join(', ');
}

/**
 * Replaces every hidden character with a visible `<U+XXXX>` marker, so output
 * never carries them raw. Tabs stay; newlines become `⏎` only when `oneLine`.
 */
export function escapeHidden(text: string, oneLine = true): string {
  let out = '';
  for (const ch of text) {
    const cp = ch.codePointAt(0) as number;
    if (cp === 0x0a || cp === 0x0d) {
      out += oneLine ? (cp === 0x0a ? '⏎' : '') : ch;
      continue;
    }
    if (cp === 0x09) {
      out += oneLine ? ' ' : ch;
      continue;
    }
    out += classify(cp) ? `<${codePointLabel(cp)}>` : ch;
  }
  return out;
}
