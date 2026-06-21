# sshache

A local-only SSH client with a clean UI. No accounts, no cloud, no telemetry —
your connection data never leaves the machine. Open source.

Built with [Tauri](https://tauri.app) (Rust) + [xterm.js](https://xtermjs.org).

## Status

Early MVP. Works: save hosts, connect with password, interactive PTY shell,
resize, multiple sequential sessions.

## Stack

- **Shell**: Tauri 2 (Rust backend, web frontend, ~10 MB binary)
- **Terminal**: xterm.js + fit/web-links addons
- **SSH**: [`russh`](https://crates.io/crates/russh) (pure-Rust SSH)
- **Storage**: host profiles in `localStorage` (host/port/user only). Passwords
  are typed per connection and never written to disk.

## Develop

Requires Node 18+ and Rust (stable).

```bash
npm install
npm run tauri dev      # hot-reload dev build
npm run tauri build    # production bundle
```

## Security

Host keys are verified against `~/.ssh/known_hosts` using trust-on-first-use
(same policy as OpenSSH `StrictHostKeyChecking=accept-new`):

- **Unknown host** → key is recorded, connection proceeds.
- **Known host, key matches** → connection proceeds.
- **Known host, key changed** → connection is **refused** (possible MITM); the
  terminal shows a warning. Remove the stale `known_hosts` line if the change is
  legitimate.

Not yet done: interactive confirm-on-first-use prompt (currently auto-accepts
new keys). Passwords/passphrases are never written to disk.

## Roadmap

- [x] Public-key auth (`~/.ssh` keys, encrypted or not)
- [x] SSH-agent auth (`SSH_AUTH_SOCK`)
- [x] Host-key verification (`known_hosts`, TOFU / accept-new)
- [ ] Interactive confirm on first-seen host key
- [ ] OS keychain for saved secrets
- [ ] Multiple tabs / split panes
- [ ] SFTP file browser
- [ ] Themes, settings, port forwarding

## License

MIT
