import React, { useEffect, useRef, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import * as teams from './client.js';

// The "Teams" view: sign into SSH Ache Teams (the sshache-sass SaaS), browse a team's shared
// SSH connections (decrypted locally), and import them into the local host list. All crypto is
// client-side; the panel talks to teams/client.ts which holds the unlocked vault in memory.

export interface ImportArgs {
  meta: teams.TeamConnMeta;
  secret: teams.TeamConnSecret | null;
  teamName: string;
}

interface Props {
  isTauri: boolean;
  defaults: { apiUrl: string; email: string };
  onImport: (args: ImportArgs) => void;
  onRemember: (apiUrl: string, email: string) => void;
  onSync: (force?: boolean) => Promise<number | undefined>;
  onGoDashboard: () => void;
}

const box: React.CSSProperties = {
  background: 'var(--surface)',
  border: '1px solid var(--border)',
  borderRadius: 8,
  padding: 16,
};
const input: React.CSSProperties = {
  width: '100%',
  boxSizing: 'border-box',
  background: 'var(--bg)',
  border: '1px solid var(--border)',
  borderRadius: 6,
  color: 'var(--text)',
  padding: '8px 10px',
  font: 'inherit',
  marginTop: 4,
};
const btn = (primary?: boolean): React.CSSProperties => ({
  background: primary ? 'var(--accent)' : 'transparent',
  color: primary ? 'var(--accent-ink, #fff)' : 'var(--text)',
  border: '1px solid var(--border)',
  borderRadius: 6,
  padding: '7px 14px',
  font: 'inherit',
  cursor: 'pointer',
});
const label: React.CSSProperties = { display: 'block', marginTop: 12, color: 'var(--muted)', fontSize: 13 };

function timeAgo(iso: string): string {
  const ms = Date.now() - new Date(iso).getTime();
  const m = Math.floor(ms / 60000);
  if (m < 1) return 'just now';
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

export default function TeamsPanel({ isTauri, defaults, onRemember, onSync, onGoDashboard }: Props): React.ReactElement {
  const [apiUrl, setApiUrl] = useState(defaults.apiUrl || 'https://platform.sshache.com');
  const [email, setEmail] = useState(defaults.email || '');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');

  const [signedIn, setSignedIn] = useState(teams.isSignedIn());
  const [memberships, setMemberships] = useState<teams.Membership[]>(teams.currentMemberships());
  const [teamId, setTeamId] = useState('');
  const [conns, setConns] = useState<teams.TeamConn[]>([]);
  const [connErr, setConnErr] = useState('');
  const [activity, setActivity] = useState<Record<string, { lastUsedAt: string; actorName: string }>>({});
  const [linking, setLinking] = useState<{ code: string; linkId: string } | null>(null);
  const [linkErr, setLinkErr] = useState('');
  const [syncing, setSyncing] = useState(false);
  const [syncMsg, setSyncMsg] = useState('');
  // Team management (all in the app now).
  const [members, setMembers] = useState<teams.TeamMember[]>([]);
  const [teamInvites, setTeamInvites] = useState<teams.TeamInvite[]>([]);
  const [myInvites, setMyInvites] = useState<teams.MyInvite[]>([]);
  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteRole, setInviteRole] = useState('MEMBER');
  const [newTeamName, setNewTeamName] = useState('');
  const [showCreate, setShowCreate] = useState(false);
  const [mgmtBusy, setMgmtBusy] = useState(false);
  const [mgmtMsg, setMgmtMsg] = useState('');
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  useEffect(() => () => { if (pollRef.current) clearInterval(pollRef.current); }, []);

  const role = memberships.find((m) => m.teamId === teamId)?.role ?? '';
  const canManage = role === 'OWNER' || role === 'ADMIN';

  // Auto-sync team connections into the local vault (no manual import). Runs after sign-in/link.
  async function runSync(force?: boolean): Promise<void> {
    setSyncing(true);
    setSyncMsg('');
    try {
      const n = await onSync(force);
      setSyncMsg(n ? `Synced ${n} connection${n === 1 ? '' : 's'} — they're in your Connections list.` : 'Connections are up to date.');
    } catch {
      setSyncMsg('Sync failed — try again.');
    } finally {
      setSyncing(false);
    }
  }


  // On (re)mount while already signed in — e.g. returning to Teams after importing a connection
  // and visiting the Dashboard — the vault persists in the client module but this component's
  // team/connection state was reset, which rendered a blank Teams view. Restore + reload here.
  useEffect(() => {
    if (!signedIn || teamId) return;
    void (async () => {
      let ms = teams.currentMemberships();
      if (!ms.length) {
        try {
          ms = await teams.loadMemberships();
        } catch {
          return;
        }
      }
      setMemberships(ms);
      if (ms.length) void loadTeam(ms[0].teamId);
      void runSync(); void loadMyInvites();
    })();
  }, []);

  // Device linking: open the web app in the browser, sign in / approve there, then unseal the
  // identity locally — no email/password is ever typed in the app.
  async function startLinkFlow(): Promise<void> {
    setLinkErr('');
    if (pollRef.current) clearInterval(pollRef.current);
    try {
      const { linkId, code, approveUrl } = await teams.startLink(apiUrl.trim());
      onRemember(apiUrl.trim(), email.trim());
      setLinking({ code, linkId });
      if (isTauri) void invoke('open_url', { url: approveUrl }).catch(() => {});
      else window.open(approveUrl, '_blank', 'noopener');
      let tries = 0;
      pollRef.current = setInterval(() => {
        tries += 1;
        void (async () => {
          try {
            const r = await teams.claimLink(linkId);
            if (r.status === 'linked') {
              if (pollRef.current) clearInterval(pollRef.current);
              setLinking(null);
              setSignedIn(true);
              setMemberships(r.memberships ?? []);
              if (r.memberships?.length) void loadTeam(r.memberships[0].teamId);
              void runSync(); void loadMyInvites();
            } else if (r.status === 'expired' || r.status === 'claimed') {
              if (pollRef.current) clearInterval(pollRef.current);
              setLinking(null);
              setLinkErr('The link expired before it was approved. Try again.');
            }
          } catch {
            /* transient — keep polling */
          }
        })();
        if (tries > 150) {
          if (pollRef.current) clearInterval(pollRef.current);
          setLinking(null);
          setLinkErr('Timed out waiting for approval. Try again.');
        }
      }, 2000);
    } catch (e: any) {
      setLinkErr(e?.message ?? String(e));
    }
  }
  function cancelLink(): void {
    if (pollRef.current) clearInterval(pollRef.current);
    setLinking(null);
  }

  async function doSignIn(e: React.FormEvent): Promise<void> {
    e.preventDefault();
    setErr('');
    setBusy(true);
    try {
      const { memberships: ms } = await teams.signIn(apiUrl.trim(), email.trim(), password);
      onRemember(apiUrl.trim(), email.trim());
      setPassword('');
      setSignedIn(true);
      setMemberships(ms);
      if (ms.length) void loadTeam(ms[0].teamId);
      void runSync(); void loadMyInvites();
    } catch (e2: any) {
      setErr(e2?.message ?? String(e2));
    } finally {
      setBusy(false);
    }
  }

  async function loadTeam(id: string): Promise<void> {
    setTeamId(id);
    setConnErr('');
    setConns([]);
    setActivity({});
    setMembers([]);
    setTeamInvites([]);
    setMgmtMsg('');
    try {
      setConns(await teams.listConnections(id));
    } catch (e: any) {
      setConnErr(e?.message ?? String(e));
    }
    const r = teams.currentMemberships().find((m) => m.teamId === id)?.role ?? '';
    // Members (any member); activity + pending invites (admin/auditor).
    try {
      setMembers(await teams.listMembers(id));
    } catch {
      /* ignore */
    }
    if (['OWNER', 'ADMIN', 'AUDITOR'].includes(r)) {
      try {
        setActivity(await teams.listActivity(id));
      } catch {
        /* best-effort */
      }
    }
    if (r === 'OWNER' || r === 'ADMIN') {
      try {
        setTeamInvites(await teams.getTeamInvites(id));
      } catch {
        /* best-effort */
      }
    }
  }

  async function loadMyInvites(): Promise<void> {
    try {
      setMyInvites(await teams.listMyInvites());
    } catch {
      setMyInvites([]);
    }
  }

  // ---- management actions ----
  async function createTeamNow(e: React.FormEvent): Promise<void> {
    e.preventDefault();
    const name = newTeamName.trim();
    if (!name) return;
    setMgmtBusy(true);
    setMgmtMsg('');
    try {
      const ms = await teams.createTeam(name);
      setMemberships(ms);
      setNewTeamName('');
      setShowCreate(false);
      const created = ms.find((m) => m.teamName === name);
      if (created) await loadTeam(created.teamId);
      setMgmtMsg(`Created "${name}".`);
    } catch (e2: any) {
      setMgmtMsg(e2?.message ?? String(e2));
    } finally {
      setMgmtBusy(false);
    }
  }
  async function doInvite(e: React.FormEvent): Promise<void> {
    e.preventDefault();
    if (!inviteEmail.trim()) return;
    setMgmtBusy(true);
    setMgmtMsg('');
    try {
      const code = await teams.inviteMember(teamId, inviteEmail.trim(), inviteRole);
      setInviteEmail('');
      setMgmtMsg(`Invited. Share this code so they can join: ${code}`);
      setTeamInvites(await teams.getTeamInvites(teamId));
    } catch (e2: any) {
      setMgmtMsg(e2?.message ?? String(e2));
    } finally {
      setMgmtBusy(false);
    }
  }
  async function doShareKeys(): Promise<void> {
    setMgmtBusy(true);
    setMgmtMsg('');
    try {
      const n = await teams.shareTeamKey(teamId);
      setMgmtMsg(`Team key shared with ${n} member${n === 1 ? '' : 's'} — they can now decrypt.`);
    } catch (e2: any) {
      setMgmtMsg(e2?.message ?? String(e2));
    } finally {
      setMgmtBusy(false);
    }
  }
  async function doRemove(memberId: string): Promise<void> {
    setMgmtBusy(true);
    try {
      await teams.removeMember(teamId, memberId);
      setMembers(await teams.listMembers(teamId));
    } catch (e2: any) {
      setMgmtMsg(e2?.message ?? String(e2));
    } finally {
      setMgmtBusy(false);
    }
  }
  async function actInvite(id: string, kind: 'accept' | 'reject'): Promise<void> {
    setMgmtBusy(true);
    try {
      if (kind === 'accept') {
        const ms = await teams.acceptInvite(id);
        setMemberships(ms);
        void runSync(true);
      } else {
        await teams.rejectInvite(id);
      }
      await loadMyInvites();
    } catch (e2: any) {
      setMgmtMsg(e2?.message ?? String(e2));
    } finally {
      setMgmtBusy(false);
    }
  }

  function signOut(): void {
    teams.signOut();
    setSignedIn(false);
    setMemberships([]);
    setConns([]);
    setTeamId('');
  }

  if (!signedIn) {
    return (
      <div style={{ maxWidth: 420, margin: '40px auto' }}>
        <h2 style={{ marginBottom: 4 }}>Teams</h2>
        <p style={{ color: 'var(--muted)', marginTop: 0, marginBottom: 16, fontSize: 14 }}>
          Sign in to SSH Ache Teams to load connections your team has shared with you. They are
          decrypted on this device — the server never sees your secrets.
        </p>
        <ul style={{ listStyle: 'none', padding: 0, margin: '0 0 18px', display: 'grid', gap: 9 }}>
          {[
            ['🔐', 'Share SSH connections end-to-end encrypted — the server only stores ciphertext.'],
            ['🟢', "See who's online and watch a teammate's live session, Figma-style."],
            ['🎫', 'Grant per-connection access and revoke anyone in one click.'],
          ].map(([ic, t]) => (
            <li key={t} style={{ display: 'flex', gap: 10, alignItems: 'flex-start', fontSize: 13, color: 'var(--muted)' }}>
              <span style={{ flex: 'none' }}>{ic}</span>
              <span>{t}</span>
            </li>
          ))}
        </ul>
        {!isTauri && (
          <p style={{ color: 'var(--muted)', fontSize: 13 }}>
            Note: imported credentials are stored in your OS keychain, which is only available in
            the desktop app.
          </p>
        )}
        {linking ? (
          <div style={{ ...box, textAlign: 'center' }}>
            <div style={{ fontSize: 13, color: 'var(--muted)', marginBottom: 12 }}>
              Approve in your browser to finish. Confirm this code matches the one shown there:
            </div>
            <div style={{ fontSize: 26, fontWeight: 700, letterSpacing: '0.14em', color: 'var(--text, #ededf0)', margin: '4px 0 14px' }}>{linking.code}</div>
            <div style={{ fontSize: 12.5, color: 'var(--muted)' }}>Waiting for approval…</div>
            <div style={{ marginTop: 14 }}>
              <button style={btn()} onClick={cancelLink}>Cancel</button>
            </div>
          </div>
        ) : (
          <div style={box}>
            <label style={{ ...label, marginTop: 0 }}>
              Server URL
              <input style={input} value={apiUrl} onChange={(e) => setApiUrl(e.target.value)} placeholder="https://platform.sshache.com" />
            </label>
            <p style={{ fontSize: 12.5, color: 'var(--muted)', margin: '10px 0 0' }}>
              We'll open the web app in your browser to sign in or create an account — no password typed here.
            </p>
            {linkErr && <p style={{ color: 'var(--danger, #ff6b6b)', fontSize: 13, marginBottom: 0 }}>{linkErr}</p>}
            <div style={{ marginTop: 16 }}>
              <button style={btn(true)} onClick={() => void startLinkFlow()} disabled={!apiUrl.trim()}>
                Connect via browser
              </button>
            </div>
            <details style={{ marginTop: 18 }}>
              <summary style={{ cursor: 'pointer', fontSize: 12.5, color: 'var(--muted)' }}>Sign in with email instead</summary>
              <form onSubmit={doSignIn} style={{ ...box, marginTop: 12 }}>
                <label style={{ ...label, marginTop: 0 }}>
                  Email
                  <input style={input} type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="username" />
                </label>
                <label style={label}>
                  Password
                  <input style={input} type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />
                </label>
                {err && <p style={{ color: 'var(--danger, #ff6b6b)', fontSize: 13, marginBottom: 0 }}>{err}</p>}
                <div style={{ marginTop: 16 }}>
                  <button type="submit" style={btn(true)} disabled={busy || !email || !password}>
                    {busy ? 'Signing in…' : 'Sign in & unlock'}
                  </button>
                </div>
              </form>
            </details>
          </div>
        )}
      </div>
    );
  }

  return (
    <div style={{ maxWidth: 760, margin: '24px auto' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <h2 style={{ margin: 0 }}>Teams</h2>
        <div style={{ display: 'flex', gap: 8 }}>
          <button style={btn(true)} disabled={syncing} onClick={() => void runSync(true)}>{syncing ? 'Syncing…' : '↻ Sync now'}</button>
          <button style={btn()} onClick={() => setShowCreate((v) => !v)}>+ New team</button>
          <button style={btn()} onClick={signOut}>Sign out</button>
        </div>
      </div>

      {showCreate && (
        <form onSubmit={createTeamNow} style={{ ...box, margin: '14px 0', display: 'flex', gap: 8, alignItems: 'center' }}>
          <input style={{ ...input, marginTop: 0, flex: 1 }} value={newTeamName} onChange={(e) => setNewTeamName(e.target.value)} placeholder="Team name" />
          <button style={btn(true)} type="submit" disabled={mgmtBusy || !newTeamName.trim()}>Create</button>
        </form>
      )}

      {myInvites.length > 0 && (
        <div style={{ ...box, margin: '16px 0', borderColor: 'var(--accent, #46d9a0)' }}>
          <div style={{ fontWeight: 600, marginBottom: 8 }}>You've been invited</div>
          {myInvites.map((iv) => (
            <div key={iv.id} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, padding: '6px 0' }}>
              <span>{iv.teamName} <span style={{ color: 'var(--muted)', fontSize: 13 }}>· join as {iv.role.toLowerCase()}</span></span>
              <span style={{ display: 'flex', gap: 6 }}>
                <button style={btn(true)} disabled={mgmtBusy} onClick={() => void actInvite(iv.id, 'accept')}>Join</button>
                <button style={btn()} disabled={mgmtBusy} onClick={() => void actInvite(iv.id, 'reject')}>Reject</button>
              </span>
            </div>
          ))}
        </div>
      )}

      {memberships.length === 0 ? (
        <p style={{ color: 'var(--muted)' }}>No teams yet. Create one above, or accept an invitation.</p>
      ) : (
        <>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', margin: '16px 0' }}>
            {memberships.map((m) => (
              <button
                key={m.teamId}
                style={{ ...btn(m.teamId === teamId), fontSize: 13 }}
                onClick={() => void loadTeam(m.teamId)}
              >
                {m.teamName} <span style={{ color: 'var(--muted)' }}>· {m.role.toLowerCase()}</span>
              </button>
            ))}
          </div>

          {connErr && <p style={{ color: 'var(--danger, #ff6b6b)', fontSize: 13 }}>{connErr}</p>}
          {syncMsg && <p style={{ color: 'var(--accent, #46d9a0)', fontSize: 13, margin: '0 0 4px' }}>{syncMsg}</p>}

          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, margin: '4px 0 12px', flexWrap: 'wrap' }}>
            <span style={{ color: 'var(--muted)', fontSize: 13 }}>Shared connections sync into your Connections list automatically — no import needed.</span>
            <button style={btn()} onClick={onGoDashboard}>Open Connections →</button>
          </div>

          {teamId && !connErr && conns.length === 0 && (
            <p style={{ color: 'var(--muted)' }}>No shared connections in this team.</p>
          )}

          <div style={{ display: 'grid', gap: 8 }}>
            {conns.map((c) => (
              <div key={c.id} style={{ ...box, display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 14px' }}>
                <div>
                  <div style={{ fontWeight: 600 }}>{c.meta.name}</div>
                  <div style={{ color: 'var(--muted)', fontSize: 13 }}>
                    {c.meta.user}@{c.meta.host}:{c.meta.port} · {c.meta.auth}
                  </div>
                  {activity[c.id] && (
                    <div style={{ color: 'var(--accent, #46d9a0)', fontSize: 12, marginTop: 3 }}>
                      Last used {timeAgo(activity[c.id]!.lastUsedAt)} · {activity[c.id]!.actorName}
                    </div>
                  )}
                </div>
                <span style={{ color: 'var(--accent, #46d9a0)', fontSize: 12.5, fontWeight: 600, flex: 'none' }}>✓ Synced</span>
              </div>
            ))}
          </div>

          {teamId && (
            <>
              <div style={{ ...box, marginTop: 16 }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
                  <div style={{ fontWeight: 600 }}>Members ({members.length})</div>
                  {canManage && <button style={btn()} disabled={mgmtBusy} onClick={() => void doShareKeys()} title="Wrap the team key to every member so they can decrypt">🔑 Share keys</button>}
                </div>
                {members.map((m) => (
                  <div key={m.id} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, padding: '6px 0' }}>
                    <span>{m.displayName} <span style={{ color: 'var(--muted)', fontSize: 13 }}>· {m.email}</span></span>
                    <span style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                      <span style={{ color: 'var(--muted)', fontSize: 12 }}>{m.role.toLowerCase()}</span>
                      {canManage && m.role !== 'OWNER' && m.userId !== teams.currentUserId() && (
                        <button style={{ ...btn(), color: 'var(--danger, #ff6b6b)', fontSize: 12 }} disabled={mgmtBusy} onClick={() => void doRemove(m.id)}>Remove</button>
                      )}
                    </span>
                  </div>
                ))}
              </div>

              {canManage && (
                <div style={{ ...box, marginTop: 12 }}>
                  <div style={{ fontWeight: 600, marginBottom: 10 }}>Invite a member</div>
                  <form onSubmit={doInvite} style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                    <input style={{ ...input, marginTop: 0, flex: 1, minWidth: 180 }} type="email" value={inviteEmail} onChange={(e) => setInviteEmail(e.target.value)} placeholder="teammate@company.dev" />
                    <select style={{ ...input, marginTop: 0, width: 'auto' }} value={inviteRole} onChange={(e) => setInviteRole(e.target.value)}>
                      <option value="MEMBER">Member</option>
                      <option value="ADMIN">Admin</option>
                    </select>
                    <button style={btn(true)} type="submit" disabled={mgmtBusy || !inviteEmail.trim()}>Invite</button>
                  </form>
                  {teamInvites.length > 0 && (
                    <div style={{ marginTop: 12 }}>
                      <div style={{ color: 'var(--muted)', fontSize: 12, marginBottom: 6 }}>Pending invitations</div>
                      {teamInvites.map((iv) => (
                        <div key={iv.id} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, padding: '4px 0', fontSize: 13 }}>
                          <span>{iv.email} <span style={{ color: 'var(--muted)' }}>· {iv.role.toLowerCase()}</span></span>
                          {iv.code && <code style={{ color: 'var(--accent, #46d9a0)', fontSize: 12 }}>{iv.code}</code>}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {mgmtMsg && <p style={{ color: 'var(--accent, #46d9a0)', fontSize: 13, wordBreak: 'break-all', marginTop: 10 }}>{mgmtMsg}</p>}
            </>
          )}
        </>
      )}
    </div>
  );
}
