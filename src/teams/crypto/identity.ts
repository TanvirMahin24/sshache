import { ed25519, x25519 } from '@noble/curves/ed25519';
import { b64, unb64, utf8, concat, zero, randomBytes } from './sodium.js';
import { ALG } from './envelope.js';
import { aeadSeal, aeadOpen, ad } from './aead.js';
import { deriveMasterKey, deriveRecoveryKey, type KdfParams } from './kdf.js';

export interface KeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}
export interface Identity {
  x25519: KeyPair; // wrapping (receives sealed Team Keys)
  ed25519: KeyPair; // signing (proves wrap/rotation provenance); secretKey = 32-byte seed
}

// Server-visible, self-signed public identity bundle (03 §4.1). Clients pin it (TOFU)
// and verify the Ed25519 self-signature to block server key-substitution.
export interface PublicBundle {
  userId: string;
  x25519Pub: string;
  ed25519Pub: string;
  createdAt: string;
  sig: string;
}

// What the server stores for a vault (User.encPrivKeys / User.recoveryWrap JSON, 05).
export interface EncPrivKeys {
  v: 1;
  ad: string; // AAD domain prefix
  wrap: string; // base64 AEAD envelope of concat(x25519Priv[32] || ed25519Seed[32])
  kdf: KdfParams;
}

export async function generateIdentity(): Promise<Identity> {
  const xPriv = x25519.utils.randomPrivateKey();
  const ePriv = ed25519.utils.randomPrivateKey();
  return {
    x25519: { publicKey: x25519.getPublicKey(xPriv), secretKey: xPriv },
    ed25519: { publicKey: ed25519.getPublicKey(ePriv), secretKey: ePriv },
  };
}

function canonicalBundle(b: Omit<PublicBundle, 'sig'>): Uint8Array {
  return utf8(
    JSON.stringify({
      userId: b.userId,
      x25519Pub: b.x25519Pub,
      ed25519Pub: b.ed25519Pub,
      createdAt: b.createdAt,
    }),
  );
}

export async function publicBundle(
  id: Identity,
  userId: string,
  createdAt: string,
): Promise<PublicBundle> {
  const unsigned = {
    userId,
    x25519Pub: b64(id.x25519.publicKey),
    ed25519Pub: b64(id.ed25519.publicKey),
    createdAt,
  };
  const sig = ed25519.sign(canonicalBundle(unsigned), id.ed25519.secretKey);
  return { ...unsigned, sig: b64(sig) };
}

export async function verifyBundle(b: PublicBundle): Promise<boolean> {
  try {
    return ed25519.verify(unb64(b.sig), canonicalBundle(b), unb64(b.ed25519Pub));
  } catch {
    return false;
  }
}

const IDENTITY_AD = 'sshache/identity/v1';
const IDENTITY_RECOVERY_AD = 'sshache/identity-recovery/v1';

async function sealUnder(
  id: Identity,
  key: Uint8Array,
  kdf: KdfParams,
  adDomain: string,
  userId: string,
): Promise<EncPrivKeys> {
  const plaintext = concat(id.x25519.secretKey, id.ed25519.secretKey); // 32 + 32 = 64 bytes
  const env = await aeadSeal(ALG.XCHACHA20POLY1305, key, ad(`${adDomain}|${userId}`), plaintext);
  zero(plaintext);
  return { v: 1, ad: adDomain, wrap: b64(env), kdf };
}

async function openUnder(enc: EncPrivKeys, key: Uint8Array, userId: string): Promise<Identity> {
  const plaintext = await aeadOpen(key, unb64(enc.wrap), ad(`${enc.ad}|${userId}`));
  const xPriv = plaintext.subarray(0, 32);
  const ePriv = plaintext.subarray(32, 64);
  return {
    x25519: { publicKey: x25519.getPublicKey(xPriv), secretKey: xPriv },
    ed25519: { publicKey: ed25519.getPublicKey(ePriv), secretKey: ePriv },
  };
}

export async function sealIdentity(
  id: Identity,
  mk: { key: Uint8Array; params: KdfParams },
  userId: string,
): Promise<EncPrivKeys> {
  return sealUnder(id, mk.key, mk.params, IDENTITY_AD, userId);
}

export async function openIdentity(
  enc: EncPrivKeys,
  masterKey: Uint8Array,
  userId: string,
): Promise<Identity> {
  return openUnder(enc, masterKey, userId);
}

// ── Recovery code (03 §5): 256-bit, Crockford base32, shown once, never stored. ──
const B32 = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
export async function generateRecoveryCode(): Promise<string> {
  const raw = randomBytes(32);
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of raw) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return (out.match(/.{1,4}/g) ?? [out]).join('-');
}

export async function makeRecoveryWrap(
  id: Identity,
  userId: string,
  recoveryKey: { key: Uint8Array; params: KdfParams },
): Promise<EncPrivKeys> {
  return sealUnder(id, recoveryKey.key, recoveryKey.params, IDENTITY_RECOVERY_AD, userId);
}

export async function openIdentityWithRecovery(
  enc: EncPrivKeys,
  code: string,
  userId: string,
): Promise<Identity> {
  const rk = await deriveRecoveryKey(code, enc.kdf);
  return openUnder(enc, rk.key, userId);
}

// One-call account bootstrap: identity + signed bundle + password wrap + recovery wrap.
export async function bootstrapAccount(
  password: string,
  userId: string,
  createdAt: string,
  kdfParams?: Partial<KdfParams>,
): Promise<{
  identity: Identity;
  bundle: PublicBundle;
  encPrivKeys: EncPrivKeys;
  recoveryCode: string;
  recoveryWrap: EncPrivKeys;
}> {
  const identity = await generateIdentity();
  const bundle = await publicBundle(identity, userId, createdAt);
  const mk = await deriveMasterKey(password, kdfParams);
  const encPrivKeys = await sealIdentity(identity, mk, userId);
  const recoveryCode = await generateRecoveryCode();
  const rk = await deriveRecoveryKey(recoveryCode, kdfParams);
  const recoveryWrap = await makeRecoveryWrap(identity, userId, rk);
  zero(mk.key, rk.key);
  return { identity, bundle, encPrivKeys, recoveryCode, recoveryWrap };
}

export function pubKeysB64(id: Identity): { x25519Pub: string; ed25519Pub: string } {
  return { x25519Pub: b64(id.x25519.publicKey), ed25519Pub: b64(id.ed25519.publicKey) };
}

// X25519 keypair for Enterprise admin key escrow (03 §10). The Team Key is sealed to the
// public half; the private half is Shamir-split among custodians (never sent to the server).
export function generateEscrowKeypair(): KeyPair {
  const priv = x25519.utils.randomPrivateKey();
  return { publicKey: x25519.getPublicKey(priv), secretKey: priv };
}
