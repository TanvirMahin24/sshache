// Byte helpers. Named sodium.ts for historical reasons; the crypto now runs on @noble
// (audited, ESM-native, pure JS — works identically in Node, the browser, and the Tauri
// webview with no WASM init). base64 uses global btoa/atob (present in Node 20+ + browsers).
import { randomBytes as nobleRandom } from '@noble/hashes/utils';

export const randomBytes = (n: number): Uint8Array => nobleRandom(n);

export function b64(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(s);
}
export function unb64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);
export const fromUtf8 = (b: Uint8Array): string => new TextDecoder().decode(b);

export function u32be(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n >>> 0, false);
  return b;
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  const len = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(len);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

// Best-effort zeroization of sensitive buffers (03 §14: zero(dek), MK, TK).
export function zero(...bufs: (Uint8Array | undefined | null)[]): void {
  for (const b of bufs) if (b) b.fill(0);
}

// No async init needed with @noble; kept as a resolved no-op for API stability.
export async function ready(): Promise<void> {}
