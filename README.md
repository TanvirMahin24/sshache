# sshache

A local-only SSH client with a clean UI. No accounts, no cloud, no telemetry —
your connection data never leaves the machine. Open source.

Built with [Tauri](https://tauri.app) (Rust) + [xterm.js](https://xtermjs.org).

## Status

UI rebuilt to the **SSH Ache** design (Claude Design handoff) as a React app —
dashboard, command palette, themes, multi-tab / split terminal, SFTP panel,
settings. **Connecting opens a real SSH shell** (password / key / agent auth,
PTY, first-seen `known_hosts` confirmation) in a live xterm.js pane. SFTP
(list + drag-transfer), theme→terminal colours, live terminal settings,
OS-keychain secrets, and a frameless window with working titlebar controls are
all wired. "New tab" opens a real local shell (PTY); SFTP browses directories;
pasted private keys connect; config exports as a password-encrypted file — run
it with `npm run tauri dev`. Remaining: per-theme ANSI palettes and port
forwarding — see [docs/TASKS.md](docs/TASKS.md).

## Stack

- **Shell**: Tauri 2 (Rust backend, web frontend, ~10 MB binary)
- **Terminal**: xterm.js + fit/web-links addons
- **SSH**: [`russh`](https://crates.io/crates/russh) (pure-Rust SSH)
- **Storage**: host profiles in `~/.ssh-ache/state.json` (non-secret fields
  only; `localStorage` in the browser preview). Passwords / passphrases are
  saved in the OS keychain via [`keyring`](https://crates.io/crates/keyring), or
  typed per connection — never written to the config file.

## Develop

Requires Node 18+ and Rust (stable).

```bash
npm install
npm run tauri dev      # hot-reload dev build
npm run tauri build    # production bundle
```

## Security

Host keys are verified against `~/.ssh/known_hosts`:

- **Unknown host** → you're shown the key's SHA256 fingerprint and must confirm
  before it is trusted (written to `known_hosts`) and the connection proceeds.
- **Known host, key matches** → connection proceeds.
- **Known host, key changed** → connection is **refused** (possible MITM); the
  terminal shows a warning. Remove the stale `known_hosts` line if the change is
  legitimate.

Saved passwords / passphrases live in the OS keychain (via `keyring`), never in
the plaintext config file — or type them per connection.

## Roadmap

- [x] Public-key auth (`~/.ssh` keys, encrypted or not)
- [x] SSH-agent auth (`SSH_AUTH_SOCK`)
- [x] Host-key verification (`known_hosts`, TOFU / accept-new)
- [x] Interactive confirm on first-seen host key
- [x] OS keychain for saved secrets
- [x] Multiple tabs / split panes
- [x] SFTP file browser (list + drag-to-transfer; navigation pending)
- [x] Themes (terminal colours) & settings (font, cursor, scrollback)
- [x] Encrypted config backup (password-based import / export)
- [x] Local port forwarding (-L)

## License

MIT
