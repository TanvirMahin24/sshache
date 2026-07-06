import { argon2id } from '@noble/hashes/argon2';
import { b64, unb64, utf8, concat, randomBytes } from './sodium.js';

// Argon2id key derivation with mandatory domain separation (03 §4.2, §5, §12).
// The SAME password can derive the Master Key, a Recovery Key, and a login verifier —
// each with a DISJOINT salt AND a disjoint domain string, so none derives another. The
// domain is prefixed into the password input (Argon2 has no context param).

export interface KdfParams {
  kdf: 'argon2id';
  v: 1;
  mem: number; // memory in bytes (03 §4.2 floor: 256 MiB)
  ops: number; // iterations (t)
  p: 1;
  salt: string; // base64, 16 bytes
}

export const DOMAIN = {
  MASTERKEY: 'sshache/masterkey/v1',
  RECOVERY: 'sshache/identity-recovery/v1',
  LOGIN: 'sshache/login/v1',
} as const;

// Production floor (03 §4.2). Tests override with lighter params (versioned in header).
export const DEFAULT_KDF = { mem: 268435456, ops: 3 } as const;

export async function deriveKey(
  secret: string,
  domain: string,
  params?: Partial<KdfParams>,
): Promise<{ key: Uint8Array; params: KdfParams }> {
  const mem = params?.mem ?? DEFAULT_KDF.mem;
  const ops = params?.ops ?? DEFAULT_KDF.ops;
  const salt = params?.salt ? unb64(params.salt) : randomBytes(16);
  const pwInput = concat(utf8(domain + '|'), utf8(secret));
  // @noble argon2id: m is in KiB, t = iterations, p = parallelism, version 0x13 default.
  const key = argon2id(pwInput, salt, { t: ops, m: Math.floor(mem / 1024), p: 1, dkLen: 32 });
  return { key, params: { kdf: 'argon2id', v: 1, mem, ops, p: 1, salt: b64(salt) } };
}

export const deriveMasterKey = (password: string, params?: Partial<KdfParams>) =>
  deriveKey(password, DOMAIN.MASTERKEY, params);

export const deriveRecoveryKey = (code: string, params?: Partial<KdfParams>) =>
  deriveKey(normalizeRecoveryCode(code), DOMAIN.RECOVERY, params);

// Client-side login verifier (03 §12): derived with the LOGIN domain + its own salt,
// sent to the server which stores an Argon2id hash of it — so a leaked server login hash
// gives no advantage against the Master Key.
export async function loginVerifier(
  password: string,
  loginSalt: string,
  params?: Partial<KdfParams>,
): Promise<string> {
  const { key } = await deriveKey(password, DOMAIN.LOGIN, { ...params, salt: loginSalt });
  return b64(key);
}

export function normalizeRecoveryCode(code: string): string {
  return code.toUpperCase().replace(/[^A-Z0-9]/g, '');
}
