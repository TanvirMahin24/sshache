// SSH Ache Teams — desktop client for the sshache-sass zero-knowledge SaaS.
//
// Signs into the SaaS, unlocks the E2EE identity IN MEMORY (never persisted — the vault
// needs the password each launch, same as the web app on reload), then decrypts a team's
// shared SSH connections locally. The server only ever sees ciphertext + wrapped keys.
//
// Transport: plain fetch() from the Tauri webview (CORS-free) with a Bearer access token
// the server returns in the login body for `platform:'desktop'`. Refresh-on-401 keeps the
// ~15-minute access token fresh via the rotating refresh token (also body-delivered).

import * as C from './crypto/index.js';

export interface Membership {
  teamId: string;
  teamName: string;
  role: string;
  planTier: string;
}
export interface TeamConnMeta {
  schema: 1;
  name: string;
  host: string;
  port: number;
  user: string;
  auth: string;
}
export interface TeamConnSecret {
  schema?: 1;
  password?: string | null;
  passphrase?: string | null;
  keyText?: string | null;
}
export interface TeamConn {
  id: string;
  version: number;
  meta: TeamConnMeta;
}

export class TeamsError extends Error {
  status: number;
  code?: string;
  constructor(status: number, message: string, code?: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

interface Vault {
  userId: string;
  email: string;
  identity: C.Identity;
}

let base = '';
let accessToken = '';
let refreshToken = '';
let vault: Vault | null = null;
// Cached across TeamsPanel unmount/remount (view switches): the vault lives in this module, so
// the UI must restore its memberships from here rather than re-init to [] and render blank.
let cachedMemberships: Membership[] = [];
const teamKeys = new Map<string, { tk: Uint8Array; keyGeneration: number }>();

export const isSignedIn = (): boolean => vault !== null;
export const getBase = (): string => base;
export const currentMemberships = (): Membership[] => cachedMemberships;

// Re-fetch memberships for an already-unlocked session (used to repopulate the UI on remount).
export async function loadMemberships(): Promise<Membership[]> {
  const me = await req('GET', '/v1/auth/me');
  cachedMemberships = me.memberships ?? [];
  return cachedMemberships;
}

export function signOut(): void {
  vault = null;
  cachedMemberships = [];
  accessToken = '';
  refreshToken = '';
  teamKeys.clear();
}

// ---- HTTP ----------------------------------------------------------------

interface Raw {
  status: number;
  ok: boolean;
  data: any;
}

async function raw(method: string, path: string, body?: unknown, auth = true): Promise<Raw> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers['content-type'] = 'application/json';
  if (auth && accessToken) headers['authorization'] = 'Bearer ' + accessToken;
  const res = await fetch(base + path, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  let data: any = null;
  try {
    data = await res.json();
  } catch {
    /* empty / non-JSON body */
  }
  return { status: res.status, ok: res.ok, data };
}

async function refresh(): Promise<void> {
  if (!refreshToken) throw new TeamsError(401, 'Session expired', 'no_refresh');
  const r = await raw('POST', '/v1/auth/refresh', { refreshToken }, false);
  if (!r.ok || !r.data?.accessToken) {
    signOut();
    throw new TeamsError(r.status, 'Session expired — sign in again', 'refresh_failed');
  }
  accessToken = r.data.accessToken;
  refreshToken = r.data.refreshToken;
}

// Authenticated request with one transparent refresh-and-retry on 401.
async function req(method: string, path: string, body?: unknown): Promise<any> {
  let r = await raw(method, path, body);
  if (r.status === 401 && refreshToken) {
    await refresh();
    r = await raw(method, path, body);
  }
  if (!r.ok) {
    throw new TeamsError(r.status, r.data?.error?.message ?? `HTTP ${r.status}`, r.data?.error?.code);
  }
  return r.data;
}

// ---- Sign in + unlock ----------------------------------------------------

export async function signIn(
  apiUrl: string,
  email: string,
  password: string,
): Promise<{ user: { id: string; email: string; displayName: string }; memberships: Membership[] }> {
  base = apiUrl.replace(/\/+$/, '');
  const login = await raw(
    'POST',
    '/v1/auth/login',
    { email, password, deviceName: 'SSH Ache Desktop', platform: 'desktop' },
    false,
  );
  if (!login.ok) {
    throw new TeamsError(login.status, login.data?.error?.message ?? 'Sign-in failed', login.data?.error?.code);
  }
  if (!login.data?.accessToken || !login.data?.refreshToken) {
    throw new TeamsError(500, 'Server did not return desktop tokens — update the server', 'no_token');
  }
  accessToken = login.data.accessToken;
  refreshToken = login.data.refreshToken;

  // Unlock the vault: password -> Master Key (Argon2id, params from the sealed vault) -> identity.
  const keys = await req('GET', '/v1/auth/keys');
  const mk = await C.deriveMasterKey(password, keys.encPrivKeys.kdf);
  const identity = await C.openIdentity(keys.encPrivKeys, mk.key, email);
  C.zero(mk.key);
  vault = { userId: login.data.user.id, email, identity };

  const me = await req('GET', '/v1/auth/me');
  cachedMemberships = me.memberships ?? [];
  return { user: me.user, memberships: cachedMemberships };
}

// ---- Team key + connections ---------------------------------------------

async function ensureTeamKey(teamId: string): Promise<{ tk: Uint8Array; keyGeneration: number }> {
  if (!vault) throw new TeamsError(401, 'Not signed in', 'locked');
  const cached = teamKeys.get(teamId);
  if (cached) return cached;

  let w: any;
  try {
    w = await req('GET', `/v1/teams/${teamId}/keys/wrap`);
  } catch (err) {
    if (err instanceof TeamsError && err.status === 404) {
      throw new TeamsError(404, 'No Team Key shared with you yet — ask an admin to share it from the web app', 'no_wrap');
    }
    throw err;
  }
  // Ed25519-verify the wrap signature (anti server-key-substitution) then sealed-box open.
  const tk = await C.verifyAndOpenTeamKeyWrap(
    C.unb64(w.wrappedTeamKey),
    C.unb64(w.sig),
    vault.identity,
    C.unb64(w.wrappedByEd25519Pub),
    teamId,
    vault.userId,
    w.keyGeneration,
  );
  const entry = { tk, keyGeneration: w.keyGeneration };
  teamKeys.set(teamId, entry);
  return entry;
}

export async function listConnections(teamId: string): Promise<TeamConn[]> {
  const { tk } = await ensureTeamKey(teamId);
  const { connections } = await req('GET', `/v1/teams/${teamId}/connections`);
  return Promise.all(
    (connections as { id: string; version: number; encBlob: string }[]).map(async (c) => ({
      id: c.id,
      version: c.version,
      meta: await C.openMeta<TeamConnMeta>(C.unb64(c.encBlob), tk, c.id),
    })),
  );
}

// Returns the decrypted secret, or null if none is stored / the caller lacks a live grant.
export async function revealSecret(teamId: string, connId: string): Promise<TeamConnSecret | null> {
  const { tk } = await ensureTeamKey(teamId);
  const c = await req('GET', `/v1/teams/${teamId}/connections/${connId}`);
  if (!c.secret) return null;
  return C.openConnection<TeamConnSecret>(
    {
      ciphertext: C.unb64(c.secret.ciphertext),
      wrappedDek: C.unb64(c.secret.wrappedDek),
      keyGeneration: c.secret.keyGeneration,
    },
    tk,
    connId,
  );
}
