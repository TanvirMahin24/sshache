#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use russh::client;
use russh::client::{AuthResult, KeyboardInteractiveAuthResponse};
use russh::keys::ssh_key::PublicKey;
use russh::keys::agent::client::AgentClient;
use russh::keys::agent::AgentIdentity;
use russh::keys::known_hosts::{check_known_hosts, learn_known_hosts};
use russh::keys::{decode_secret_key, load_secret_key, PrivateKeyWithHashAlg};
use russh::ChannelMsg;
use russh_sftp::client::SftpSession;
use portable_pty::{native_pty_system, CommandBuilder, MasterPty, PtySize};
use std::io::{Read, Write};
use tauri::ipc::Channel;
use tauri::State;
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};

enum KeyIssue {
    Unknown(String, String), // (fingerprint, openssh public key)
    Changed,
}

struct Handler {
    host: String,
    port: u16,
    // Set by check_server_key when the presented key is unknown or changed, so
    // ssh_connect can surface it to the UI instead of silently trusting it.
    issue: Arc<Mutex<Option<KeyIssue>>>,
}

impl client::Handler for Handler {
    type Error = russh::Error;

    // Trust-on-first-use with an interactive confirm (Phase 3):
    //   known host, key matches -> Ok(true)
    //   unknown host            -> record fingerprint + reject; the UI confirms,
    //                              then `trust_host` learns it and we reconnect
    //   known host, key CHANGED -> record + abort (possible MITM)
    // The mismatch MUST stay a rejection — that is the entire MITM protection.
    async fn check_server_key(&mut self, key: &PublicKey) -> Result<bool, Self::Error> {
        match check_known_hosts(&self.host, self.port, key) {
            Ok(true) => Ok(true),
            Ok(false) => {
                let fp = key.fingerprint(russh::keys::ssh_key::HashAlg::Sha256).to_string();
                let openssh = key.to_openssh().unwrap_or_default();
                *self.issue.lock().unwrap() = Some(KeyIssue::Unknown(fp, openssh));
                Ok(false)
            }
            Err(e) => {
                *self.issue.lock().unwrap() = Some(KeyIssue::Changed);
                Err(e.into())
            }
        }
    }
}

enum SshCmd {
    Data(Vec<u8>),
    Resize(u32, u32),
    Close,
}

// One live PTY session per id (= a UI pane). ponytail: a dead session's Sender
// lingers in the map until ssh_disconnect / a reconnect with the same id — the
// IO task can't reach the state to evict itself; harmless, the frontend cleans
// up on pane unmount.
#[derive(Default)]
struct SshState(Mutex<HashMap<String, UnboundedSender<SshCmd>>>);

#[derive(serde::Serialize)]
struct FileEntry {
    name: String,
    kind: String, // "dir" | "file"
    size: String,
}

// One dedicated SFTP connection per UI panel, keyed by id (= tab id + ":sftp").
// ponytail: opens its own SSH connection instead of sharing the terminal's
// russh Handle across the IO task — simpler; reuse the session later if the
// extra connection ever matters.
#[derive(Default)]
struct SftpState(Mutex<HashMap<String, (Arc<SftpSession>, client::Handle<Handler>)>>);

// Local shell (Phase: "New tab") — a real PTY per local tab.
struct PtySlot {
    master: Box<dyn MasterPty + Send>,
    writer: Box<dyn Write + Send>,
    child: Box<dyn portable_pty::Child + Send + Sync>,
}
#[derive(Default)]
struct PtyState(Mutex<HashMap<String, PtySlot>>);

// Local port forwards (id -> the listener task). Aborting the task drops the
// dedicated SSH connection and closes the local listener.
#[derive(Default)]
struct ForwardState(Mutex<HashMap<String, tauri::async_runtime::JoinHandle<()>>>);

fn sftp_of(state: &SftpState, id: &str) -> Result<Arc<SftpSession>, String> {
    state
        .0
        .lock()
        .unwrap()
        .get(id)
        .map(|(s, _)| s.clone())
        .ok_or_else(|| "SFTP not connected".to_string())
}

fn human_size(n: u64) -> String {
    const U: [&str; 5] = ["B", "K", "M", "G", "T"];
    let mut f = n as f64;
    let mut i = 0;
    while f >= 1024.0 && i < U.len() - 1 {
        f /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n}B")
    } else {
        format!("{f:.1}{}", U[i])
    }
}

fn sort_entries(v: &mut [FileEntry]) {
    v.sort_by(|a, b| {
        (b.kind == "dir")
            .cmp(&(a.kind == "dir"))
            .then(a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
}

// Shared SSH authentication, used by both the terminal and SFTP connections.
async fn do_auth(
    session: &mut client::Handle<Handler>,
    user: &str,
    auth: &str,
    secret: &str,
    key_path: &str,
    key_text: &str,
) -> Result<(), String> {
    let res = match auth {
        "key" => {
            let pass = if secret.is_empty() { None } else { Some(secret) };
            let key = if !key_text.is_empty() {
                // Pasted key text — decode from memory (never written to disk).
                decode_secret_key(key_text, pass).map_err(|e| format!("decode key: {e}"))?
            } else {
                // Expand a leading ~/ since load_secret_key won't.
                let path = key_path
                    .strip_prefix("~/")
                    .map(|rest| format!("{}/{}", std::env::var("HOME").unwrap_or_default(), rest))
                    .unwrap_or_else(|| key_path.to_string());
                load_secret_key(path, pass).map_err(|e| format!("load key: {e}"))?
            };
            let hash = session
                .best_supported_rsa_hash()
                .await
                .map_err(|e| format!("auth: {e}"))?
                .flatten();
            session
                .authenticate_publickey(user, PrivateKeyWithHashAlg::new(Arc::new(key), hash))
                .await
                .map_err(|e| format!("auth: {e}"))?
        }
        "agent" => {
            let mut agent = AgentClient::connect_env()
                .await
                .map_err(|e| format!("ssh-agent connect (is SSH_AUTH_SOCK set?): {e}"))?;
            let ids = agent
                .request_identities()
                .await
                .map_err(|e| format!("ssh-agent identities: {e}"))?;
            if ids.is_empty() {
                return Err("ssh-agent has no keys loaded (try `ssh-add`)".into());
            }
            let hash = session
                .best_supported_rsa_hash()
                .await
                .map_err(|e| format!("auth: {e}"))?
                .flatten();
            let mut last = None;
            for id in ids {
                let res = match id {
                    AgentIdentity::PublicKey { key, .. } => {
                        session
                            .authenticate_publickey_with(user, key, hash, &mut agent)
                            .await
                    }
                    AgentIdentity::Certificate { certificate, .. } => {
                        session
                            .authenticate_certificate_with(user, certificate, hash, &mut agent)
                            .await
                    }
                }
                .map_err(|e| format!("ssh-agent auth: {e}"))?;
                let ok = res.success();
                last = Some(res);
                if ok {
                    break;
                }
            }
            last.ok_or_else(|| "ssh-agent: no identity accepted".to_string())?
        }
        _ => {
            let mut res = session
                .authenticate_password(user, secret)
                .await
                .map_err(|e| format!("auth: {e}"))?;
            // Fallback: many servers (PAM) accept passwords only via
            // keyboard-interactive — `ssh` tries this too.
            if !res.success() {
                let mut step = session
                    .authenticate_keyboard_interactive_start(user, None::<String>)
                    .await
                    .map_err(|e| format!("auth: {e}"))?;
                // Cap rounds so a server looping InfoRequests can't hang us.
                for _ in 0..10 {
                    match step {
                        KeyboardInteractiveAuthResponse::Success => {
                            res = AuthResult::Success;
                            break;
                        }
                        KeyboardInteractiveAuthResponse::Failure { .. } => break,
                        KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                            let answers = vec![secret.to_string(); prompts.len()];
                            step = session
                                .authenticate_keyboard_interactive_respond(answers)
                                .await
                                .map_err(|e| format!("auth: {e}"))?;
                        }
                    }
                }
            }
            res
        }
    };
    if !res.success() {
        return Err(format!("authentication failed — server reports {res:?}"));
    }
    Ok(())
}

#[tauri::command]
async fn ssh_connect(
    state: State<'_, SshState>,
    session_id: String,
    host: String,
    port: u16,
    user: String,
    auth: String,
    secret: String,
    key_path: String,
    key_text: String,
    cols: u16,
    rows: u16,
    on_data: Channel<Vec<u8>>,
    on_close: Channel<String>,
) -> Result<(), String> {
    // Drop any existing session reusing this id before starting a new one.
    if let Some(tx) = state.0.lock().unwrap().remove(&session_id) {
        let _ = tx.send(SshCmd::Close);
    }

    let config = Arc::new(client::Config::default());
    let issue = Arc::new(Mutex::new(None));
    let handler = Handler {
        host: host.clone(),
        port,
        issue: issue.clone(),
    };
    let connect_res = client::connect(config, (host, port), handler).await;
    // An aborted handshake from an unknown / changed host key becomes a
    // structured error the UI parses (\u{1} = field separator).
    match issue.lock().unwrap().take() {
        Some(KeyIssue::Unknown(fp, key)) => return Err(format!("UNKNOWN_HOST\u{1}{fp}\u{1}{key}")),
        Some(KeyIssue::Changed) => return Err("KEY_CHANGED".to_string()),
        None => {}
    }
    let mut session = connect_res.map_err(|e| format!("connect: {e}"))?;

    do_auth(&mut session, &user, &auth, &secret, &key_path, &key_text).await?;

    let mut channel = session
        .channel_open_session()
        .await
        .map_err(|e| format!("channel: {e}"))?;
    channel
        .request_pty(false, "xterm-256color", cols as u32, rows as u32, 0, 0, &[])
        .await
        .map_err(|e| format!("pty: {e}"))?;
    channel
        .request_shell(true)
        .await
        .map_err(|e| format!("shell: {e}"))?;

    let (tx, mut rx) = unbounded_channel::<SshCmd>();
    state.0.lock().unwrap().insert(session_id, tx);

    tauri::async_runtime::spawn(async move {
        let _session = session; // keep the connection alive for the task's lifetime
        loop {
            tokio::select! {
                msg = channel.wait() => {
                    match msg {
                        Some(ChannelMsg::Data { ref data }) => {
                            let _ = on_data.send(data.to_vec());
                        }
                        Some(ChannelMsg::ExtendedData { ref data, .. }) => {
                            let _ = on_data.send(data.to_vec());
                        }
                        Some(ChannelMsg::ExitStatus { .. }) | None => {
                            let _ = on_close.send("closed".into());
                            break;
                        }
                        _ => {}
                    }
                }
                cmd = rx.recv() => {
                    match cmd {
                        Some(SshCmd::Data(d)) => { let _ = channel.data(&d[..]).await; }
                        Some(SshCmd::Resize(c, r)) => { let _ = channel.window_change(c, r, 0, 0).await; }
                        Some(SshCmd::Close) | None => {
                            let _ = channel.eof().await;
                            break;
                        }
                    }
                }
            }
        }
    });

    Ok(())
}

#[tauri::command]
fn ssh_write(state: State<'_, SshState>, session_id: String, data: String) -> Result<(), String> {
    if let Some(tx) = state.0.lock().unwrap().get(&session_id) {
        tx.send(SshCmd::Data(data.into_bytes()))
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
fn ssh_resize(state: State<'_, SshState>, session_id: String, cols: u16, rows: u16) {
    if let Some(tx) = state.0.lock().unwrap().get(&session_id) {
        let _ = tx.send(SshCmd::Resize(cols as u32, rows as u32));
    }
}

#[tauri::command]
fn ssh_disconnect(state: State<'_, SshState>, session_id: String) {
    if let Some(tx) = state.0.lock().unwrap().remove(&session_id) {
        let _ = tx.send(SshCmd::Close);
    }
}

// ---- local config store: ~/.ssh-ache/<name>.json (non-secret data only) ----

fn config_dir() -> Result<std::path::PathBuf, String> {
    let home = std::env::var("HOME").map_err(|_| "HOME not set".to_string())?;
    let dir = std::path::Path::new(&home).join(".ssh-ache");
    std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }
    Ok(dir)
}

fn config_path(name: &str) -> Result<std::path::PathBuf, String> {
    // Only a simple file stem — no path traversal from the UI.
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
        return Err("bad config name".into());
    }
    Ok(config_dir()?.join(format!("{name}.json")))
}

#[tauri::command]
fn read_config(name: String) -> Result<String, String> {
    let path = config_path(&name)?;
    match std::fs::read_to_string(&path) {
        Ok(s) => Ok(s),
        Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(format!("read: {e}")),
    }
}

#[tauri::command]
fn write_config(name: String, data: String) -> Result<(), String> {
    let path = config_path(&name)?;
    std::fs::write(&path, data).map_err(|e| format!("write: {e}"))
}

// ---- secrets: OS keychain via the `keyring` crate (service = "sshache") ----
// ponytail: macOS only for now (apple-native feature). Add the windows-native /
// sync-secret-service features in Cargo.toml to cover those platforms.

fn secret_entry(id: &str) -> Result<keyring::Entry, String> {
    keyring::Entry::new("sshache", id).map_err(|e| e.to_string())
}

#[tauri::command]
fn secret_get(id: String) -> Result<String, String> {
    match secret_entry(&id)?.get_password() {
        Ok(p) => Ok(p),
        Err(keyring::Error::NoEntry) => Ok(String::new()),
        Err(e) => Err(e.to_string()),
    }
}

#[tauri::command]
fn secret_set(id: String, value: String) -> Result<(), String> {
    secret_entry(&id)?.set_password(&value).map_err(|e| e.to_string())
}

#[tauri::command]
fn secret_delete(id: String) -> Result<(), String> {
    match secret_entry(&id)?.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

// Persist a server key to ~/.ssh/known_hosts after the user confirms it (Phase 3).
#[tauri::command]
fn trust_host(host: String, port: u16, key: String) -> Result<(), String> {
    let pk = PublicKey::from_openssh(&key).map_err(|e| format!("parse key: {e}"))?;
    learn_known_hosts(&host, port, &pk).map_err(|e| format!("learn: {e}"))?;
    Ok(())
}

// ---- SFTP commands (Phase 4) ----

#[tauri::command]
async fn sftp_connect(
    state: State<'_, SftpState>,
    id: String,
    host: String,
    port: u16,
    user: String,
    auth: String,
    secret: String,
    key_path: String,
) -> Result<String, String> {
    // Drop any previous SFTP session reusing this id.
    let prev = state.0.lock().unwrap().remove(&id);
    drop(prev);

    let config = Arc::new(client::Config::default());
    let handler = Handler {
        host: host.clone(),
        port,
        issue: Arc::new(Mutex::new(None)),
    };
    let mut session = client::connect(config, (host, port), handler)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    do_auth(&mut session, &user, &auth, &secret, &key_path, "").await?;

    let channel = session
        .channel_open_session()
        .await
        .map_err(|e| format!("channel: {e}"))?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(|e| format!("sftp subsystem: {e}"))?;
    let sftp = SftpSession::new(channel.into_stream())
        .await
        .map_err(|e| format!("sftp init: {e}"))?;
    let home = sftp
        .canonicalize(".")
        .await
        .unwrap_or_else(|_| "/".to_string());
    state.0.lock().unwrap().insert(id, (Arc::new(sftp), session));
    Ok(home)
}

#[tauri::command]
async fn sftp_list(
    state: State<'_, SftpState>,
    id: String,
    path: String,
) -> Result<Vec<FileEntry>, String> {
    let sftp = sftp_of(&state, &id)?;
    let entries = sftp.read_dir(&path).await.map_err(|e| format!("list: {e}"))?;
    let mut out = Vec::new();
    for entry in entries {
        let name = entry.file_name();
        if name == "." || name == ".." {
            continue;
        }
        let meta = entry.metadata();
        let is_dir = meta.is_dir();
        let size = if is_dir {
            "—".to_string()
        } else {
            human_size(meta.size.unwrap_or(0))
        };
        out.push(FileEntry {
            name,
            kind: if is_dir { "dir".into() } else { "file".into() },
            size,
        });
    }
    sort_entries(&mut out);
    Ok(out)
}

#[tauri::command]
async fn sftp_put(
    state: State<'_, SftpState>,
    id: String,
    local_path: String,
    remote_path: String,
    on_progress: Channel<u32>,
) -> Result<(), String> {
    use tokio::io::AsyncWriteExt;
    let sftp = sftp_of(&state, &id)?;
    let data = tokio::fs::read(&local_path)
        .await
        .map_err(|e| format!("read local: {e}"))?;
    let total = data.len();
    let mut file = sftp
        .create(&remote_path)
        .await
        .map_err(|e| format!("create remote: {e}"))?;
    let mut written = 0usize;
    let mut last = 0u32;
    for chunk in data.chunks(32768) {
        file.write_all(chunk).await.map_err(|e| format!("write: {e}"))?;
        written += chunk.len();
        let pct = if total == 0 { 100 } else { (written * 100 / total) as u32 };
        if pct != last {
            last = pct;
            let _ = on_progress.send(pct);
        }
    }
    file.flush().await.map_err(|e| format!("flush: {e}"))?;
    file.shutdown().await.ok();
    let _ = on_progress.send(100);
    Ok(())
}

#[tauri::command]
async fn sftp_get(
    state: State<'_, SftpState>,
    id: String,
    remote_path: String,
    local_path: String,
    on_progress: Channel<u32>,
) -> Result<(), String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let sftp = sftp_of(&state, &id)?;
    let total = sftp
        .metadata(&remote_path)
        .await
        .ok()
        .and_then(|m| m.size)
        .unwrap_or(0) as usize;
    let mut file = sftp
        .open(&remote_path)
        .await
        .map_err(|e| format!("open remote: {e}"))?;
    let mut out = tokio::fs::File::create(&local_path)
        .await
        .map_err(|e| format!("create local: {e}"))?;
    let mut buf = vec![0u8; 32768];
    let mut done = 0usize;
    let mut last = 0u32;
    loop {
        let n = file.read(&mut buf).await.map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            break;
        }
        out.write_all(&buf[..n])
            .await
            .map_err(|e| format!("write local: {e}"))?;
        done += n;
        if total > 0 {
            let pct = (done * 100 / total) as u32;
            if pct != last {
                last = pct;
                let _ = on_progress.send(pct);
            }
        }
    }
    out.flush().await.map_err(|e| format!("flush: {e}"))?;
    let _ = on_progress.send(100);
    Ok(())
}

#[tauri::command]
fn sftp_disconnect(state: State<'_, SftpState>, id: String) {
    state.0.lock().unwrap().remove(&id);
}

#[tauri::command]
fn local_list(path: String) -> Result<Vec<FileEntry>, String> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(&path).map_err(|e| format!("list: {e}"))? {
        let e = e.map_err(|e| e.to_string())?;
        let md = match e.metadata() {
            Ok(md) => md,
            Err(_) => continue,
        };
        let is_dir = md.is_dir();
        out.push(FileEntry {
            name: e.file_name().to_string_lossy().to_string(),
            kind: if is_dir { "dir".into() } else { "file".into() },
            size: if is_dir { "—".to_string() } else { human_size(md.len()) },
        });
    }
    sort_entries(&mut out);
    Ok(out)
}

#[tauri::command]
fn local_home() -> String {
    std::env::var("HOME").unwrap_or_else(|_| "/".to_string())
}

// Read/write an arbitrary file path — used for encrypted import/export, with the
// path chosen by the user via a native dialog. ponytail: unscoped on purpose;
// only our own (trusted) frontend can invoke it, and the payload is already
// ciphertext.
#[tauri::command]
fn write_file(path: String, data: String) -> Result<(), String> {
    std::fs::write(&path, data).map_err(|e| format!("write: {e}"))
}

#[tauri::command]
fn read_file(path: String) -> Result<String, String> {
    std::fs::read_to_string(&path).map_err(|e| format!("read: {e}"))
}

// ---- local shell (PTY) ----

#[tauri::command]
fn pty_spawn(
    state: State<'_, PtyState>,
    id: String,
    cols: u16,
    rows: u16,
    on_data: Channel<Vec<u8>>,
    on_close: Channel<String>,
) -> Result<(), String> {
    if let Some(mut slot) = state.0.lock().unwrap().remove(&id) {
        let _ = slot.child.kill();
    }
    let pty = native_pty_system();
    let pair = pty
        .openpty(PtySize { rows, cols, pixel_width: 0, pixel_height: 0 })
        .map_err(|e| e.to_string())?;
    let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/bash".to_string());
    let mut cmd = CommandBuilder::new(shell);
    cmd.env("TERM", "xterm-256color");
    if let Ok(home) = std::env::var("HOME") {
        cmd.cwd(home);
    }
    let child = pair.slave.spawn_command(cmd).map_err(|e| e.to_string())?;
    drop(pair.slave);
    let mut reader = pair.master.try_clone_reader().map_err(|e| e.to_string())?;
    let writer = pair.master.take_writer().map_err(|e| e.to_string())?;
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => {
                    let _ = on_close.send("closed".into());
                    break;
                }
                Ok(n) => {
                    if on_data.send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });
    state
        .0
        .lock()
        .unwrap()
        .insert(id, PtySlot { master: pair.master, writer, child });
    Ok(())
}

#[tauri::command]
fn pty_write(state: State<'_, PtyState>, id: String, data: String) -> Result<(), String> {
    if let Some(slot) = state.0.lock().unwrap().get_mut(&id) {
        slot.writer
            .write_all(data.as_bytes())
            .map_err(|e| e.to_string())?;
        slot.writer.flush().map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
fn pty_resize(state: State<'_, PtyState>, id: String, cols: u16, rows: u16) {
    if let Some(slot) = state.0.lock().unwrap().get(&id) {
        let _ = slot.master.resize(PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        });
    }
}

#[tauri::command]
fn pty_close(state: State<'_, PtyState>, id: String) {
    if let Some(mut slot) = state.0.lock().unwrap().remove(&id) {
        let _ = slot.child.kill();
    }
}

// ---- local port forwarding (-L): listen on 127.0.0.1:local_port, tunnel each
// connection to remote_host:remote_port over a dedicated SSH session ----

#[tauri::command]
async fn forward_start(
    state: State<'_, ForwardState>,
    id: String,
    host: String,
    port: u16,
    user: String,
    auth: String,
    secret: String,
    key_path: String,
    key_text: String,
    local_port: u16,
    remote_host: String,
    remote_port: u16,
) -> Result<(), String> {
    if let Some(h) = state.0.lock().unwrap().remove(&id) {
        h.abort();
    }
    let config = Arc::new(client::Config::default());
    let handler = Handler {
        host: host.clone(),
        port,
        issue: Arc::new(Mutex::new(None)),
    };
    let mut session = client::connect(config, (host, port), handler)
        .await
        .map_err(|e| format!("connect: {e}"))?;
    do_auth(&mut session, &user, &auth, &secret, &key_path, &key_text).await?;
    let session = Arc::new(session);

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", local_port))
        .await
        .map_err(|e| format!("bind 127.0.0.1:{local_port}: {e}"))?;

    let task = tauri::async_runtime::spawn(async move {
        let session = session; // keep the SSH connection alive for the task
        loop {
            let (mut socket, _) = match listener.accept().await {
                Ok(x) => x,
                Err(_) => break,
            };
            let session = session.clone();
            let rh = remote_host.clone();
            tokio::spawn(async move {
                let ch = match session
                    .channel_open_direct_tcpip(rh, remote_port as u32, "127.0.0.1".to_string(), local_port as u32)
                    .await
                {
                    Ok(c) => c,
                    Err(_) => return,
                };
                let mut stream = ch.into_stream();
                let _ = tokio::io::copy_bidirectional(&mut socket, &mut stream).await;
            });
        }
    });
    state.0.lock().unwrap().insert(id, task);
    Ok(())
}

#[tauri::command]
fn forward_stop(state: State<'_, ForwardState>, id: String) {
    if let Some(h) = state.0.lock().unwrap().remove(&id) {
        h.abort();
    }
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(SshState::default())
        .manage(SftpState::default())
        .manage(PtyState::default())
        .manage(ForwardState::default())
        .invoke_handler(tauri::generate_handler![
            ssh_connect,
            ssh_write,
            ssh_resize,
            ssh_disconnect,
            read_config,
            write_config,
            secret_get,
            secret_set,
            secret_delete,
            trust_host,
            sftp_connect,
            sftp_list,
            sftp_put,
            sftp_get,
            sftp_disconnect,
            local_list,
            local_home,
            write_file,
            read_file,
            pty_spawn,
            pty_write,
            pty_resize,
            pty_close,
            forward_start,
            forward_stop
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
