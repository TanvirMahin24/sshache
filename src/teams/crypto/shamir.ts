import { randomBytes } from './sodium.js';

// Shamir Secret Sharing over GF(256) (03 §10). Splits a byte string (e.g. an escrow X25519
// private key) into N shares, any M of which reconstruct it — the M-of-N break-glass basis
// for Enterprise admin key escrow. Byte-wise, AES field (poly 0x11b).

function gfMul(a: number, b: number): number {
  let p = 0;
  for (let i = 0; i < 8; i++) {
    if (b & 1) p ^= a;
    const hi = a & 0x80;
    a = (a << 1) & 0xff;
    if (hi) a ^= 0x1b;
    b >>= 1;
  }
  return p & 0xff;
}
function gfPow(a: number, e: number): number {
  let r = 1;
  while (e > 0) {
    if (e & 1) r = gfMul(r, a);
    a = gfMul(a, a);
    e >>= 1;
  }
  return r;
}
const gfInv = (a: number): number => gfPow(a, 254); // a^(255-1) since a^255 = 1

// Each share is [x, ...y] where x ∈ 1..255 is the evaluation point and y are the secret bytes.
export function splitSecret(secret: Uint8Array, threshold: number, shares: number): Uint8Array[] {
  if (threshold < 2 || shares < threshold || shares > 255) {
    throw new Error('shamir: need 2 <= threshold <= shares <= 255');
  }
  const out: Uint8Array[] = [];
  for (let x = 1; x <= shares; x++) {
    const s = new Uint8Array(1 + secret.length);
    s[0] = x;
    out.push(s);
  }
  for (let b = 0; b < secret.length; b++) {
    const coeffs = new Uint8Array(threshold);
    coeffs[0] = secret[b]!;
    const rnd = randomBytes(threshold - 1);
    for (let i = 1; i < threshold; i++) coeffs[i] = rnd[i - 1]!;
    for (let x = 1; x <= shares; x++) {
      let y = 0;
      let xp = 1;
      for (let i = 0; i < threshold; i++) {
        y ^= gfMul(coeffs[i]!, xp);
        xp = gfMul(xp, x);
      }
      out[x - 1]![1 + b] = y;
    }
  }
  return out;
}

// Reconstruct the secret from >= threshold shares (Lagrange interpolation at x=0).
export function combineShares(shares: Uint8Array[]): Uint8Array {
  if (shares.length < 2) throw new Error('shamir: need at least 2 shares');
  const xs = shares.map((s) => s[0]!);
  // Reject invalid inputs loudly instead of silently returning garbage: x must be nonzero
  // and distinct (a duplicate/zero x collapses a Lagrange basis term via gfInv(0)=0), and
  // all shares must be the same length.
  if (xs.some((x) => x === 0) || new Set(xs).size !== xs.length) {
    throw new Error('shamir: shares must have distinct, nonzero x-coordinates');
  }
  if (shares.some((s) => s.length !== shares[0]!.length)) {
    throw new Error('shamir: share length mismatch');
  }
  const len = shares[0]!.length - 1;
  const out = new Uint8Array(len);
  for (let b = 0; b < len; b++) {
    let secret = 0;
    for (let j = 0; j < shares.length; j++) {
      let basis = 1;
      for (let k = 0; k < shares.length; k++) {
        if (k === j) continue;
        basis = gfMul(basis, gfMul(xs[k]!, gfInv(xs[j]! ^ xs[k]!)));
      }
      secret ^= gfMul(shares[j]![1 + b]!, basis);
    }
    out[b] = secret;
  }
  return out;
}
