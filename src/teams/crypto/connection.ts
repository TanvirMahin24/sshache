import { utf8, fromUtf8, zero, randomBytes } from './sodium.js';
import { ALG } from './envelope.js';
import { aeadSeal, aeadOpen, ad, type SymAlg } from './aead.js';

// Connection secrets (03 §7). Each connection gets its own DEK; the DEK is wrapped by the
// Team Key. The whole connection blob (SSH secret + sensitive metadata: host, user, port,
// name, folder, tags, jump, forwards) is encrypted — only ids/version/timestamps stay
// cleartext (05 §5). AAD binds connId (and keyGeneration on the DEK wrap).

export interface SealedConnection {
  ciphertext: Uint8Array; // AEAD envelope of the connection blob (under the DEK)
  wrappedDek: Uint8Array; // AEAD envelope of the DEK (under the Team Key)
  alg: SymAlg;
  keyGeneration: number;
}

export async function sealConnection(
  blob: unknown,
  teamKey: Uint8Array,
  connId: string,
  keyGeneration: number,
  alg: SymAlg = ALG.XCHACHA20POLY1305,
): Promise<SealedConnection> {
  const dek = randomBytes(32);
  const ciphertext = await aeadSeal(alg, dek, ad(`sshache/conn/v1|${connId}`), utf8(JSON.stringify(blob)));
  const wrappedDek = await aeadSeal(
    alg,
    teamKey,
    ad(`sshache/dek-wrap/v1|${connId}|${keyGeneration}`),
    dek,
  );
  zero(dek);
  return { ciphertext, wrappedDek, alg, keyGeneration };
}

// Connection METADATA blob (name/host/port/user/folder/tags/jump/forwards) is sealed
// directly under the Team Key (09 §4: Connection.encBlob), NOT under a per-connection
// DEK — only the SSH secret gets a DEK. AAD binds the connId.
export async function sealMeta(
  meta: unknown,
  teamKey: Uint8Array,
  connId: string,
  alg: SymAlg = ALG.XCHACHA20POLY1305,
): Promise<Uint8Array> {
  return aeadSeal(alg, teamKey, ad(`sshache/conn-meta/v1|${connId}`), utf8(JSON.stringify(meta)));
}

export async function openMeta<T = unknown>(
  encBlob: Uint8Array,
  teamKey: Uint8Array,
  connId: string,
): Promise<T> {
  const pt = await aeadOpen(teamKey, encBlob, ad(`sshache/conn-meta/v1|${connId}`));
  return JSON.parse(fromUtf8(pt)) as T;
}

export async function openConnection<T = unknown>(
  rec: Pick<SealedConnection, 'ciphertext' | 'wrappedDek' | 'keyGeneration'>,
  teamKey: Uint8Array,
  connId: string,
): Promise<T> {
  const dek = await aeadOpen(
    teamKey,
    rec.wrappedDek,
    ad(`sshache/dek-wrap/v1|${connId}|${rec.keyGeneration}`),
  );
  const plaintext = await aeadOpen(dek, rec.ciphertext, ad(`sshache/conn/v1|${connId}`));
  zero(dek);
  return JSON.parse(fromUtf8(plaintext)) as T;
}

// Re-wrap a connection's DEK from an old Team Key to a new one (Team Key rotation, §9.4).
// The connection ciphertext does NOT change — only the DEK wrap — so rotation is cheap.
export async function rewrapDek(
  rec: Pick<SealedConnection, 'wrappedDek'>,
  oldTeamKey: Uint8Array,
  newTeamKey: Uint8Array,
  connId: string,
  oldKeyGeneration: number,
  newKeyGeneration: number,
  alg: SymAlg = ALG.XCHACHA20POLY1305,
): Promise<Uint8Array> {
  const dek = await aeadOpen(
    oldTeamKey,
    rec.wrappedDek,
    ad(`sshache/dek-wrap/v1|${connId}|${oldKeyGeneration}`),
  );
  const wrappedDek = await aeadSeal(
    alg,
    newTeamKey,
    ad(`sshache/dek-wrap/v1|${connId}|${newKeyGeneration}`),
    dek,
  );
  zero(dek);
  return wrappedDek;
}
