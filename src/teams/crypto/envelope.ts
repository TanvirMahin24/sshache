import { concat } from './sodium.js';

// Self-describing AEAD envelope (03 §8.1):
//   envelope = header || nonce || ct_and_tag
//   header   = magic(4) || version(1) || algId(1) || flags(1) || reserved(1)
// A blob written by one platform is always readable by the other (alg is tagged).

export const MAGIC = new Uint8Array([0x53, 0x41, 0x63, 0x31]); // "SAc1"
export const ENV_VERSION = 0x01;
export const HEADER_LEN = 8;

export const ALG = {
  XCHACHA20POLY1305: 0x01, // canonical symmetric AEAD (24-byte nonce)
  AES256GCM: 0x03, // WebCrypto-native symmetric AEAD fallback (12-byte nonce)
  SEALEDBOX: 0x11, // X25519 + HKDF-SHA256 + XChaCha20-Poly1305 sealed box (§6.4-style)
} as const;
export type AlgId = (typeof ALG)[keyof typeof ALG];

// Nonce length by algId (bytes) for the generic AEAD envelope. The sealed box (0x11)
// has its own layout (eph pub || nonce || ct) and is parsed in aead.ts, not here.
export function nonceLen(alg: number): number {
  if (alg === ALG.XCHACHA20POLY1305) return 24;
  if (alg === ALG.AES256GCM) return 12;
  return 0;
}

export function packEnvelope(alg: number, nonce: Uint8Array, body: Uint8Array): Uint8Array {
  const header = new Uint8Array([...MAGIC, ENV_VERSION, alg, 0x00, 0x00]);
  return concat(header, nonce, body);
}

export interface ParsedEnvelope {
  alg: number;
  nonce: Uint8Array;
  body: Uint8Array;
}

export function parseEnvelope(env: Uint8Array): ParsedEnvelope {
  if (env.length < HEADER_LEN) throw new Error('crypto: envelope too short');
  for (let i = 0; i < MAGIC.length; i++) {
    if (env[i] !== MAGIC[i]) throw new Error('crypto: bad envelope magic');
  }
  if (env[4] !== ENV_VERSION) throw new Error(`crypto: unsupported envelope version ${env[4]}`);
  const alg = env[5]!;
  const nl = nonceLen(alg);
  const nonce = env.subarray(HEADER_LEN, HEADER_LEN + nl);
  const body = env.subarray(HEADER_LEN + nl);
  return { alg, nonce, body };
}
