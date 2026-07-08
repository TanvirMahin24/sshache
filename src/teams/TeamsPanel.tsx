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
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  useEffect(() => () => { if (pollRef.current) clearInterval(pollRef.current); }, []);

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
      void runSync();
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
              void runSync();
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
      void runSync();
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
    try {
      setConns(await teams.listConnections(id));
    } catch (e: any) {
      setConnErr(e?.message ?? String(e));
    }
    // Admins/Auditors see per-connection last-activity (best-effort; 403 for others).
    const role = teams.currentMemberships().find((m) => m.teamId === id)?.role ?? '';
    if (['OWNER', 'ADMIN', 'AUDITOR'].includes(role)) {
      try {
        setActivity(await teams.listActivity(id));
      } catch {
        /* ignore — activity is best-effort */
      }
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
          <button style={btn()} onClick={signOut}>Sign out</button>
        </div>
      </div>

      {memberships.length === 0 ? (
        <p style={{ color: 'var(--muted)' }}>You are not a member of any team yet.</p>
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
        </>
      )}
    </div>
  );
}
