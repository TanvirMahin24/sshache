import { ed25519 } from '@noble/curves/ed25519';
import { utf8, u32be, concat, randomBytes } from './sodium.js';
import { sealBox, openBox } from './aead.js';
import type { Identity } from './identity.js';

// Team Key distribution via signed sealed box (03 §6). The 256-bit Team Key is sealed to
// each member's X25519 public key; the wrap is Ed25519-signed by the producing Admin/Owner
// so the recipient can verify provenance (anti server key-substitution). `keyGeneration`
// matches Team.keyGeneration (05, decision D6) and increments on every rotation.

export async function newTeamKey(): Promise<Uint8Array> {
  return randomBytes(32);
}

export interface SignedWrap {
  wrap: Uint8Array; // sealed-box envelope (algId 0x11)
  sig: Uint8Array; // Ed25519 over teamId | memberId | keyGeneration | wrap
}

function wrapSigMsg(
  teamId: string,
  memberId: string,
  keyGeneration: number,
  wrap: Uint8Array,
): Uint8Array {
  return concat(utf8(teamId), utf8(memberId), u32be(keyGeneration), wrap);
}

export async function wrapTeamKeyToMember(
  teamKey: Uint8Array,
  memberX25519Pub: Uint8Array,
  adminEd25519Priv: Uint8Array,
  teamId: string,
  memberId: string,
  keyGeneration: number,
): Promise<SignedWrap> {
  const wrap = await sealBox(memberX25519Pub, teamKey);
  const sig = ed25519.sign(wrapSigMsg(teamId, memberId, keyGeneration, wrap), adminEd25519Priv);
  return { wrap, sig };
}

export async function verifyAndOpenTeamKeyWrap(
  wrap: Uint8Array,
  sig: Uint8Array,
  recipient: Identity,
  wrappedByEd25519Pub: Uint8Array,
  teamId: string,
  memberId: string,
  keyGeneration: number,
): Promise<Uint8Array> {
  const ok = ed25519.verify(
    sig,
    wrapSigMsg(teamId, memberId, keyGeneration, wrap),
    wrappedByEd25519Pub,
  );
  if (!ok) throw new Error('crypto: Team Key wrap signature invalid (possible key substitution)');
  return openBox(wrap, recipient.x25519.secretKey);
}
