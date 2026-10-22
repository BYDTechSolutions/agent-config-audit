/**
 * Decides whether a file's bytes can be checked as text, and why not when they
 * cannot (binary, archive, bytecode).
 */
import type { UnreadReason } from '../types.js';

const ARCHIVE_EXT = /\.(?:zip|tar|tgz|gz|bz2|xz|zst|7z|rar|jar|war|whl|egg|docx|xlsx|pptx|odt|ods|odp|epub|apk|dmg|iso|pkg|deb|rpm|crx|vsix|nupkg)$/i;
const BYTECODE_EXT = /\.(?:pyc|pyo|class|wasm|beam|luac|elc)$/i;

/** The verdict on a file's bytes. */
export type Content = { kind: 'text'; text: string } | { kind: 'unread'; reason: UnreadReason; detail: string };

function startsWith(buf: Buffer, bytes: number[], offset = 0): boolean {
  return bytes.every((b, i) => buf[offset + i] === b);
}

/** Classifies bytes by extension and magic number, then decodes UTF-8 text. */
export function inspect(path: string, buf: Buffer): Content {
  if (BYTECODE_EXT.test(path) || startsWith(buf, [0x00, 0x61, 0x73, 0x6d]) || startsWith(buf, [0xca, 0xfe, 0xba, 0xbe])) {
    return { kind: 'unread', reason: 'bytecode', detail: 'compiled bytecode' };
  }
  const zip = startsWith(buf, [0x50, 0x4b, 0x03, 0x04]) || startsWith(buf, [0x50, 0x4b, 0x05, 0x06]);
  const gz = startsWith(buf, [0x1f, 0x8b]);
  const rar = startsWith(buf, [0x52, 0x61, 0x72, 0x21]);
  const sevenZ = startsWith(buf, [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]);
  const tar = buf.length > 262 && buf.toString('latin1', 257, 262) === 'ustar';
  if (ARCHIVE_EXT.test(path) || zip || gz || rar || sevenZ || tar) {
    return { kind: 'unread', reason: 'archive', detail: zip ? 'zip container' : gz ? 'gzip data' : rar ? 'RAR archive' : sevenZ ? '7-Zip archive' : tar ? 'tar archive' : 'archive' };
  }
  const head = buf.subarray(0, Math.min(buf.length, 8192));
  if (head.includes(0)) {
    // UTF-16 text has NULs too; decode it if it starts with a BOM.
    if (startsWith(buf, [0xff, 0xfe]) || startsWith(buf, [0xfe, 0xff])) {
      return { kind: 'text', text: new TextDecoder(buf[0] === 0xff ? 'utf-16le' : 'utf-16be').decode(buf) };
    }
    return { kind: 'unread', reason: 'binary', detail: 'binary data' };
  }
  const text = new TextDecoder('utf-8', { fatal: false }).decode(buf);
  const bad = (text.match(/�/g) ?? []).length;
  if (bad > 8 && bad / Math.max(1, text.length) > 0.01) return { kind: 'unread', reason: 'binary', detail: 'not valid UTF-8 text' };
  return { kind: 'text', text };
}
