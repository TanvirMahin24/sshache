import React, { useState } from 'react';
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

export default function TeamsPanel({ isTauri, defaults, onImport, onRemember }: Props): React.ReactElement {
  const [apiUrl, setApiUrl] = useState(defaults.apiUrl || 'https://api.sshache.com');
  const [email, setEmail] = useState(defaults.email || '');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');

  const [signedIn, setSignedIn] = useState(teams.isSignedIn());
  const [memberships, setMemberships] = useState<teams.Membership[]>([]);
  const [teamId, setTeamId] = useState('');
  const [conns, setConns] = useState<teams.TeamConn[]>([]);
  const [connErr, setConnErr] = useState('');
  const [imported, setImported] = useState<Record<string, boolean>>({});
  const [importing, setImporting] = useState<Record<string, boolean>>({});

  const teamName = memberships.find((m) => m.teamId === teamId)?.teamName ?? '';

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
    try {
      setConns(await teams.listConnections(id));
    } catch (e: any) {
      setConnErr(e?.message ?? String(e));
    }
  }

  async function importOne(c: teams.TeamConn): Promise<void> {
    setImporting((s) => ({ ...s, [c.id]: true }));
    try {
      const secret = await teams.revealSecret(teamId, c.id);
      onImport({ meta: c.meta, secret, teamName });
      setImported((s) => ({ ...s, [c.id]: true }));
    } catch (e: any) {
      setConnErr(e?.message ?? String(e));
    } finally {
      setImporting((s) => ({ ...s, [c.id]: false }));
    }
  }

  function signOut(): void {
    teams.signOut();
    setSignedIn(false);
    setMemberships([]);
    setConns([]);
    setTeamId('');
    setImported({});
  }

  if (!signedIn) {
    return (
      <div style={{ maxWidth: 420, margin: '40px auto' }}>
        <h2 style={{ marginBottom: 4 }}>Teams</h2>
        <p style={{ color: 'var(--muted)', marginTop: 0, marginBottom: 16, fontSize: 14 }}>
          Sign in to SSH Ache Teams to load connections your team has shared with you. They are
          decrypted on this device — the server never sees your secrets.
        </p>
        {!isTauri && (
          <p style={{ color: 'var(--muted)', fontSize: 13 }}>
            Note: imported credentials are stored in your OS keychain, which is only available in
            the desktop app.
          </p>
        )}
        <form onSubmit={doSignIn} style={box}>
          <label style={{ ...label, marginTop: 0 }}>
            Server URL
            <input style={input} value={apiUrl} onChange={(e) => setApiUrl(e.target.value)} placeholder="https://api.sshache.com" />
          </label>
          <label style={label}>
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
      </div>
    );
  }

  return (
    <div style={{ maxWidth: 760, margin: '24px auto' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <h2 style={{ margin: 0 }}>Teams</h2>
        <button style={btn()} onClick={signOut}>Sign out</button>
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
                </div>
                <button
                  style={btn(!imported[c.id])}
                  disabled={!!importing[c.id] || !!imported[c.id]}
                  onClick={() => void importOne(c)}
                >
                  {imported[c.id] ? 'Imported ✓' : importing[c.id] ? 'Importing…' : 'Import'}
                </button>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
