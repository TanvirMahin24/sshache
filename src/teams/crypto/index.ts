// @sshache/crypto — the E2EE spine shared by apps/web and the desktop Teams module.
// Single implementation, no per-platform crypto (03-SECURITY-ARCHITECTURE.md §14).
//
// Key hierarchy (03 §3): password --Argon2id--> Master Key --unwraps--> identity keys
// --sealed box--> Team Key --wraps--> per-connection DEK --AEAD--> connection secret.
// Wire format is self-describing (envelope header, §8.1) and FROZEN as of v0.1.0.

export { ready, b64, unb64, zero } from './sodium.js';
export { ALG, MAGIC, ENV_VERSION, parseEnvelope, packEnvelope, type AlgId } from './envelope.js';
export { aeadSeal, aeadOpen, ad, sealBox, openBox, type SymAlg } from './aead.js';
export {
  deriveKey,
  deriveMasterKey,
  deriveRecoveryKey,
  loginVerifier,
  normalizeRecoveryCode,
  DOMAIN,
  DEFAULT_KDF,
  type KdfParams,
} from './kdf.js';
export {
  generateIdentity,
  publicBundle,
  verifyBundle,
  sealIdentity,
  openIdentity,
  generateRecoveryCode,
  makeRecoveryWrap,
  openIdentityWithRecovery,
  bootstrapAccount,
  pubKeysB64,
  generateEscrowKeypair,
  type Identity,
  type KeyPair,
  type PublicBundle,
  type EncPrivKeys,
} from './identity.js';
export { splitSecret, combineShares } from './shamir.js';
export {
  newTeamKey,
  wrapTeamKeyToMember,
  verifyAndOpenTeamKeyWrap,
  type SignedWrap,
} from './teamkey.js';
export {
  sealConnection,
  openConnection,
  sealMeta,
  openMeta,
  rewrapDek,
  type SealedConnection,
} from './connection.js';
