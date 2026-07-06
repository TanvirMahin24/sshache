import { xchacha20poly1305 } from '@noble/ciphers/chacha';
import { x25519 } from '@noble/curves/ed25519';
import { hkdf } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';
import { randomBytes, utf8, concat, zero } from './sodium.js';
import { ALG, type AlgId, MAGIC, ENV_VERSION, packEnvelope, parseEnvelope } from './envelope.js';

// Symmetric AEAD behind one interface (03 §8): XChaCha20-Poly1305 (canonical, 0x01,
// @noble) and AES-256-GCM (WebCrypto fallback, 0x03, desktop parity). Every seal binds
// associated data `domain|ids|version` so blobs can't be swapped across contexts (§8.3).

export type SymAlg = typeof ALG.XCHACHA20POLY1305 | typeof ALG.AES256GCM;

export function ad(context: string): Uint8Array {
  return utf8(context);
}

// TS 5.7 typed-array generics reject Uint8Array<ArrayBufferLike> for BufferSource params;
// our buffers are always ArrayBuffer-backed, so narrow here.
const bs = (u: Uint8Array): BufferSource => u as unknown as BufferSource;

export async function aeadSeal(
  alg: SymAlg,
  key: Uint8Array,
  associated: Uint8Array,
  msg: Uint8Array,
): Promise<Uint8Array> {
  if (alg === ALG.XCHACHA20POLY1305) {
    const nonce = randomBytes(24);
    const ct = xchacha20poly1305(key, nonce, associated).encrypt(msg);
    return packEnvelope(alg, nonce, ct);
  }
  const nonce = randomBytes(12);
  const ck = await crypto.subtle.importKey('raw', bs(key), 'AES-GCM', false, ['encrypt']);
  const ctBuf = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: bs(nonce), additionalData: bs(associated) },
    ck,
    bs(msg),
  );
  return packEnvelope(alg, nonce, new Uint8Array(ctBuf));
}

export async function aeadOpen(
  key: Uint8Array,
  envelope: Uint8Array,
  associated: Uint8Array,
): Promise<Uint8Array> {
  const { alg, nonce, body } = parseEnvelope(envelope);
  if (alg === ALG.XCHACHA20POLY1305) {
    return xchacha20poly1305(key, nonce, associated).decrypt(body);
  }
  if (alg === ALG.AES256GCM) {
    const ck = await crypto.subtle.importKey('raw', bs(key), 'AES-GCM', false, ['decrypt']);
    const msg = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: bs(nonce), additionalData: bs(associated) },
      ck,
      bs(body),
    );
    return new Uint8Array(msg);
  }
  throw new Error(`crypto: cannot AEAD-open algId 0x${alg.toString(16)}`);
}

// ── Sealed box (0x11): X25519 ECDH → HKDF-SHA256 → XChaCha20-Poly1305 (03 §6.4). ──
// Anonymous-sender public-key wrap of the Team Key to a member's X25519 public key.
// Layout: header(8) || ephemeralPub(32) || nonce(24) || ct+tag.
const SEAL_INFO = utf8('sshache/teamkey-seal/v1');
const SEAL_HEADER = new Uint8Array([...MAGIC, ENV_VERSION, ALG.SEALEDBOX, 0x00, 0x00]);

export async function sealBox(recipientX25519Pub: Uint8Array, msg: Uint8Array): Promise<Uint8Array> {
  const ephPriv = x25519.utils.randomPrivateKey();
  const ephPub = x25519.getPublicKey(ephPriv);
  const shared = x25519.getSharedSecret(ephPriv, recipientX25519Pub);
  const wrapKey = hkdf(sha256, shared, new Uint8Array(0), SEAL_INFO, 32);
  const nonce = randomBytes(24);
  const ct = xchacha20poly1305(wrapKey, nonce, SEAL_INFO).encrypt(msg);
  zero(ephPriv, shared, wrapKey);
  return concat(SEAL_HEADER, ephPub, nonce, ct);
}

export async function openBox(
  envelope: Uint8Array,
  recipientX25519Priv: Uint8Array,
): Promise<Uint8Array> {
  for (let i = 0; i < MAGIC.length; i++) {
    if (envelope[i] !== MAGIC[i]) throw new Error('crypto: bad sealed-box magic');
  }
  if (envelope[5] !== ALG.SEALEDBOX) throw new Error('crypto: not a sealed box');
  const ephPub = envelope.subarray(8, 40);
  const nonce = envelope.subarray(40, 64);
  const ct = envelope.subarray(64);
  const shared = x25519.getSharedSecret(recipientX25519Priv, ephPub);
  const wrapKey = hkdf(sha256, shared, new Uint8Array(0), SEAL_INFO, 32);
  const msg = xchacha20poly1305(wrapKey, nonce, SEAL_INFO).decrypt(ct);
  zero(shared, wrapKey);
  return msg;
}

export type { AlgId };
