#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::{Arc, Mutex};

use russh::client;
use russh::client::{AuthResult, KeyboardInteractiveAuthResponse};
use russh::keys::ssh_key::PublicKey;
use russh::keys::agent::client::AgentClient;
use russh::keys::agent::AgentIdentity;
use russh::keys::known_hosts::{check_known_hosts, learn_known_hosts};
use russh::keys::{load_secret_key, PrivateKeyWithHashAlg};
use russh::ChannelMsg;
use tauri::ipc::Channel;
use tauri::State;
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};

struct Handler {
    host: String,
    port: u16,
}

impl client::Handler for Handler {
    type Error = russh::Error;

    // Trust-on-first-use, matching OpenSSH `StrictHostKeyChecking=accept-new`:
    //   known host, key matches  -> Ok(true)   (check_known_hosts)
    //   unknown host             -> Ok(false)  -> learn it, then accept
    //   known host, key CHANGED  -> Err(KeyChanged) -> `?` aborts the handshake
    // The mismatch MUST stay an error (never a silent relearn) — that is the
    // entire MITM protection. ponytail: auto-accept new keys instead of
    // prompting; add an interactive confirm dialog if you want stricter UX.
    async fn check_server_key(&mut self, key: &PublicKey) -> Result<bool, Self::Error> {
        if check_known_hosts(&self.host, self.port, key)? {
            Ok(true)
        } else {
            learn_known_hosts(&self.host, self.port, key)?;
            Ok(true)
        }
    }
}

enum SshCmd {
    Data(Vec<u8>),
    Resize(u32, u32),
    Close,
}

#[derive(Default)]
struct SshState(Mutex<Option<UnboundedSender<SshCmd>>>);

#[tauri::command]
async fn ssh_connect(
    state: State<'_, SshState>,
    host: String,
    port: u16,
    user: String,
    auth: String,
    secret: String,
    key_path: String,
    cols: u16,
    rows: u16,
    on_data: Channel<Vec<u8>>,
    on_close: Channel<String>,
) -> Result<(), String> {
    // Drop any previous session before starting a new one.
    if let Some(tx) = state.0.lock().unwrap().take() {
        let _ = tx.send(SshCmd::Close);
    }

    let config = Arc::new(client::Config::default());
    let handler = Handler {
        host: host.clone(),
        port,
    };
    let mut session = client::connect(config, (host, port), handler)
        .await
        .map_err(|e| format!("connect: {e}"))?;

    let auth = match auth.as_str() {
        "key" => {
            // Expand a leading ~/ since load_secret_key won't.
            let path = key_path
                .strip_prefix("~/")
                .map(|rest| format!("{}/{}", std::env::var("HOME").unwrap_or_default(), rest))
                .unwrap_or(key_path);
            let pass = if secret.is_empty() { None } else { Some(secret.as_str()) };
            let key = load_secret_key(path, pass).map_err(|e| format!("load key: {e}"))?;
            let hash = session
                .best_supported_rsa_hash()
                .await
                .map_err(|e| format!("auth: {e}"))?
                .flatten();
            session
                .authenticate_publickey(&user, PrivateKeyWithHashAlg::new(Arc::new(key), hash))
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
            // Offer each identity to the server until one is accepted.
            let mut last = None;
            for id in ids {
                let res = match id {
                    AgentIdentity::PublicKey { key, .. } => {
                        session
                            .authenticate_publickey_with(&user, key, hash, &mut agent)
                            .await
                    }
                    AgentIdentity::Certificate { certificate, .. } => {
                        session
                            .authenticate_certificate_with(&user, certificate, hash, &mut agent)
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
            // Plain `password` method first.
            let mut res = session
                .authenticate_password(&user, &secret)
                .await
                .map_err(|e| format!("auth: {e}"))?;
            // Fallback: many servers (PAM) accept passwords only via
            // keyboard-interactive — `ssh` tries this too, which is why the CLI
            // works where a bare password method fails.
            if !res.success() {
                let mut step = session
                    .authenticate_keyboard_interactive_start(&user, None::<String>)
                    .await
                    .map_err(|e| format!("auth: {e}"))?;
                // ponytail: cap rounds so a server that loops InfoRequests forever
                // can't hang us. Real exchanges are 1-2 rounds.
                for _ in 0..10 {
                    match step {
                        KeyboardInteractiveAuthResponse::Success => {
                            res = AuthResult::Success;
                            break;
                        }
                        KeyboardInteractiveAuthResponse::Failure { .. } => break,
                        KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                            let answers = vec![secret.clone(); prompts.len()];
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
    if !auth.success() {
        return Err(format!("authentication failed — server reports {auth:?}"));
    }

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
    *state.0.lock().unwrap() = Some(tx);

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
fn ssh_write(state: State<'_, SshState>, data: String) -> Result<(), String> {
    if let Some(tx) = state.0.lock().unwrap().as_ref() {
        tx.send(SshCmd::Data(data.into_bytes()))
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
fn ssh_resize(state: State<'_, SshState>, cols: u16, rows: u16) {
    if let Some(tx) = state.0.lock().unwrap().as_ref() {
        let _ = tx.send(SshCmd::Resize(cols as u32, rows as u32));
    }
}

#[tauri::command]
fn ssh_disconnect(state: State<'_, SshState>) {
    if let Some(tx) = state.0.lock().unwrap().take() {
        let _ = tx.send(SshCmd::Close);
    }
}

fn main() {
    tauri::Builder::default()
        .manage(SshState::default())
        .invoke_handler(tauri::generate_handler![
            ssh_connect,
            ssh_write,
            ssh_resize,
            ssh_disconnect
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
