// File: sshtether/src/connection.rs
// Author: Hadi Cahyadi <cumulus13@gmail.com>
// Date: 2026-11-18 14:35:08 SE Asia Standard Time
// Description:
// License: MIT

//! SSH connection establishment: TCP tuning, host-key policy and authentication.
//!
//! Authentication order mirrors OpenSSH/paramiko: every configured key file,
//! then the ssh-agent and the default `~/.ssh/id_*` keys (unless `--no-agent`),
//! and finally the password, if one was configured.

use crate::cli::{Cli, HostKeyPolicy};
use crate::config::{expand_path, ServerConfig};
use crate::error::ConnectError;
use crate::ui;
use russh::client::{self, DisconnectReason, Handle};
use russh::keys::agent::client::{AgentClient, AgentStream};
use russh::keys::agent::AgentIdentity;
use russh::keys::known_hosts::learn_known_hosts_path;
use russh::keys::{
    check_known_hosts_path, Algorithm, HashAlg, PrivateKey, PrivateKeyWithHashAlg, PublicKey,
    PublicKeyOrCertificate,
};
use russh::Disconnect;
use socket2::{SockRef, TcpKeepalive};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Tunables for establishing a connection.
#[derive(Debug, Clone)]
pub struct ConnectOpts {
    /// TCP connect timeout (handshake and auth get twice this).
    pub connect_timeout: Duration,
    /// SSH-level heartbeat interval.
    pub keepalive: Duration,
    /// Unanswered heartbeats tolerated before the link is declared dead.
    pub keepalive_max: usize,
    /// Host-key verification policy.
    pub host_key_policy: HostKeyPolicy,
    /// known_hosts file that is read and (for `accept-new`) appended to.
    pub known_hosts: PathBuf,
    /// Skip the agent / default-key fallback when key files are configured.
    pub no_agent: bool,
}

impl ConnectOpts {
    /// Derive the options from parsed command-line arguments.
    pub fn from_cli(cli: &Cli) -> Self {
        Self {
            connect_timeout: Duration::from_secs_f64(cli.connect_timeout),
            keepalive: Duration::from_secs_f64(cli.keepalive),
            keepalive_max: cli.keepalive_max as usize,
            host_key_policy: cli.host_key_policy,
            known_hosts: expand_path(&cli.known_hosts),
            no_agent: cli.no_agent,
        }
    }
}

#[derive(Default)]
struct Shared {
    /// Set when the host key was refused (permanent for this server).
    rejected: Mutex<Option<String>>,
    /// Why the transport went away, as reported by the SSH layer.
    disconnect: Mutex<Option<String>>,
}

/// Verifies the server key and records why a connection ended.
pub struct ClientHandler {
    host: String,
    port: u16,
    policy: HostKeyPolicy,
    known_hosts: PathBuf,
    shared: Arc<Shared>,
}

impl ClientHandler {
    fn reject(&self, why: String) -> bool {
        *self.shared.rejected.lock().unwrap() = Some(why);
        false
    }

    fn files(&self) -> Vec<PathBuf> {
        let mut v = vec![self.known_hosts.clone()];
        let system = if cfg!(windows) {
            std::env::var_os("ProgramData")
                .map(|p| PathBuf::from(p).join("ssh").join("ssh_known_hosts"))
        } else {
            Some(PathBuf::from("/etc/ssh/ssh_known_hosts"))
        };
        v.extend(system);
        v
    }

    fn verify(&self, key: &PublicKey) -> bool {
        let mut known = false;
        for path in self.files().iter().filter(|p| p.is_file()) {
            match check_known_hosts_path(&self.host, self.port, key, path) {
                Ok(true) => known = true,
                Ok(false) => {}
                Err(russh::keys::Error::KeyChanged { line }) => {
                    return self.reject(format!(
                        "HOST KEY CHANGED for {} ({}:{line}) - refusing to connect \
                         (possible man-in-the-middle attack)",
                        self.host,
                        path.display()
                    ));
                }
                Err(e) => ui::debug(format!("known_hosts {}: {e}", path.display())),
            }
        }
        if known {
            return true;
        }
        let fp = key.fingerprint(HashAlg::Sha256);
        match self.policy {
            HostKeyPolicy::Strict => self.reject(format!(
                "host {} ({fp}) is not in {} (policy: strict)",
                self.host,
                self.known_hosts.display()
            )),
            HostKeyPolicy::Insecure => {
                ui::debug(format!(
                    "accepting unknown host key for {} ({fp}), not saved",
                    self.host
                ));
                true
            }
            HostKeyPolicy::AcceptNew => {
                ui::warn(format!(
                    "New host key for {} ({}, {fp}) - saving.",
                    self.host,
                    key.algorithm()
                ));
                if let Err(e) =
                    learn_known_hosts_path(&self.host, self.port, key, &self.known_hosts)
                {
                    ui::warn(format!(
                        "could not write {}: {e}",
                        self.known_hosts.display()
                    ));
                }
                true
            }
        }
    }
}

impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let key = match server_public_key {
            PublicKeyOrCertificate::PublicKey { key, .. } => key.clone(),
            PublicKeyOrCertificate::Certificate(cert) => PublicKey::from(cert.public_key().clone()),
        };
        Ok(self.verify(&key))
    }

    async fn disconnected(
        &mut self,
        reason: DisconnectReason<Self::Error>,
    ) -> Result<(), Self::Error> {
        let text = match &reason {
            DisconnectReason::ReceivedDisconnect(info) => {
                format!("server closed the connection ({info:?})")
            }
            DisconnectReason::Error(e) => e.to_string(),
        };
        *self.shared.disconnect.lock().unwrap() = Some(text);
        match reason {
            DisconnectReason::ReceivedDisconnect(_) => Ok(()),
            DisconnectReason::Error(e) => Err(e),
        }
    }
}

enum Candidate {
    Key(Arc<PrivateKey>),
    /// ssh-agent identities, then default `~/.ssh` keys, then password only.
    Fallback,
}

/// An authenticated SSH connection.
pub struct Connection {
    handle: Handle<ClientHandler>,
    shared: Arc<Shared>,
}

impl Connection {
    /// Connect and authenticate, trying every credential source in turn.
    pub async fn open(server: &ServerConfig, opts: &ConnectOpts) -> Result<Self, ConnectError> {
        let mut keys = Vec::new();
        for path in &server.key_files {
            if !path.is_file() {
                ui::warn(format!("key file not found, skipping: {}", path.display()));
                continue;
            }
            keys.push(Arc::new(load_private_key(path).await?));
        }
        if !server.key_files.is_empty() && keys.is_empty() && server.password.is_none() {
            return Err(ConnectError::fatal(
                "none of the configured key files exist",
            ));
        }

        let skip_fallback = opts.no_agent && !keys.is_empty();
        let mut candidates: Vec<Candidate> = keys.into_iter().map(Candidate::Key).collect();
        if !skip_fallback {
            candidates.push(Candidate::Fallback);
        }

        let mut tried: Vec<String> = Vec::new();
        for cand in candidates {
            let what = match &cand {
                Candidate::Key(k) => format!(
                    "key {} {}",
                    k.algorithm(),
                    k.public_key().fingerprint(HashAlg::Sha256)
                ),
                Candidate::Fallback if opts.no_agent => "password".to_owned(),
                Candidate::Fallback => "ssh-agent / default keys in ~/.ssh".to_owned(),
            };
            let mut conn = Self::connect_transport(server, opts).await?;
            let attempt = timeout(
                opts.connect_timeout * 2,
                conn.authenticate(server, &cand, opts),
            )
            .await;
            match attempt {
                Err(_) => {
                    conn.close().await;
                    return Err(ConnectError::transient("authentication timed out"));
                }
                Ok(Err(e)) => {
                    conn.close().await;
                    return Err(e);
                }
                Ok(Ok(true)) => return Ok(conn),
                Ok(Ok(false)) => {
                    ui::debug(format!("auth rejected using {what}"));
                    tried.push(format!("{what}: rejected"));
                    conn.close().await;
                }
            }
        }
        Err(ConnectError::fatal(format!(
            "authentication failed. Tried: {} (check authorized_keys on the server, or run with -v)",
            if tried.is_empty() { "nothing".to_owned() } else { tried.join("; ") }
        )))
    }

    async fn connect_transport(
        server: &ServerConfig,
        opts: &ConnectOpts,
    ) -> Result<Self, ConnectError> {
        let ct = opts.connect_timeout;
        let stream = timeout(
            ct,
            TcpStream::connect((server.hostname.as_str(), server.port)),
        )
        .await
        .map_err(|_| {
            ConnectError::transient(format!("connect timed out after {:.0}s", ct.as_secs_f64()))
        })?
        .map_err(|e| ConnectError::transient(format!("{:?}: {e}", e.kind())))?;
        tune_socket(&stream);

        let shared = Arc::new(Shared::default());
        let handler = ClientHandler {
            host: server.hostname.clone(),
            port: server.port,
            policy: opts.host_key_policy,
            known_hosts: opts.known_hosts.clone(),
            shared: shared.clone(),
        };
        let config = Arc::new(client::Config {
            keepalive_interval: Some(opts.keepalive),
            keepalive_max: opts.keepalive_max,
            inactivity_timeout: None,
            nodelay: true,
            ..Default::default()
        });

        match timeout(ct * 2, client::connect_stream(config, stream, handler)).await {
            Err(_) => Err(ConnectError::transient("SSH handshake timed out")),
            Ok(Err(e)) => {
                let rejected = shared.rejected.lock().unwrap().take();
                Err(match rejected {
                    Some(why) => ConnectError::fatal(why),
                    None => ConnectError::transient(e.to_string()),
                })
            }
            Ok(Ok(handle)) => Ok(Self { handle, shared }),
        }
    }

    /// `Ok(true)` authenticated, `Ok(false)` every method was rejected.
    async fn authenticate(
        &mut self,
        server: &ServerConfig,
        cand: &Candidate,
        opts: &ConnectOpts,
    ) -> Result<bool, ConnectError> {
        let user = server.username.as_str();
        let mut rejected = 0usize;

        match cand {
            Candidate::Key(key) => {
                let hash = self.rsa_hash(key.public_key()).await;
                match self
                    .handle
                    .authenticate_publickey(user, PrivateKeyWithHashAlg::new(key.clone(), hash))
                    .await
                {
                    Ok(r) if r.success() => return Ok(true),
                    Ok(_) => rejected += 1,
                    Err(e) => return self.auth_error(rejected, e.to_string()),
                }
            }
            Candidate::Fallback if !opts.no_agent => {
                match self.try_agent(user, &mut rejected).await {
                    Ok(true) => return Ok(true),
                    Ok(false) => {}
                    Err(e) => return self.auth_error(rejected, e),
                }
                match self.try_default_keys(user, &mut rejected).await {
                    Ok(true) => return Ok(true),
                    Ok(false) => {}
                    Err(e) => return self.auth_error(rejected, e),
                }
            }
            Candidate::Fallback => {}
        }

        if let Some(password) = &server.password {
            match self
                .handle
                .authenticate_password(user, password.clone())
                .await
            {
                Ok(r) if r.success() => return Ok(true),
                Ok(_) => {}
                Err(e) => return self.auth_error(rejected, e.to_string()),
            }
        }
        Ok(false)
    }

    /// A transport error mid-authentication: transient if nothing was refused
    /// yet (network blip), otherwise treated as the server giving up on us
    /// (e.g. `MaxAuthTries`), which retrying would only repeat.
    fn auth_error(&self, rejected: usize, err: String) -> Result<bool, ConnectError> {
        if rejected == 0 {
            Err(ConnectError::transient(err))
        } else {
            ui::debug(format!(
                "server dropped the connection after {rejected} rejected key(s): {err}"
            ));
            Ok(false)
        }
    }

    async fn rsa_hash(&self, key: &PublicKey) -> Option<HashAlg> {
        if matches!(key.algorithm(), Algorithm::Rsa { .. }) {
            self.handle
                .best_supported_rsa_hash()
                .await
                .ok()
                .flatten()
                .flatten()
        } else {
            None
        }
    }

    async fn try_agent(&mut self, user: &str, rejected: &mut usize) -> Result<bool, String> {
        let mut agent = match connect_agent().await {
            Ok(a) => a,
            Err(e) => {
                ui::debug(format!("no ssh-agent: {e}"));
                return Ok(false);
            }
        };
        let identities = match agent.request_identities().await {
            Ok(i) => i,
            Err(e) => {
                ui::debug(format!("ssh-agent refused identity listing: {e}"));
                return Ok(false);
            }
        };
        for id in identities {
            let AgentIdentity::PublicKey { key, comment } = id else {
                continue;
            };
            let hash = self.rsa_hash(&key).await;
            match self
                .handle
                .authenticate_publickey_with(user, key, hash, &mut agent)
                .await
            {
                Ok(r) if r.success() => return Ok(true),
                Ok(_) => {
                    *rejected += 1;
                    ui::debug(format!("agent key '{comment}' rejected"));
                }
                Err(e) if self.is_closed() => return Err(e.to_string()),
                Err(e) => ui::debug(format!("agent key '{comment}' unusable: {e}")),
            }
        }
        Ok(false)
    }

    async fn try_default_keys(&mut self, user: &str, rejected: &mut usize) -> Result<bool, String> {
        let Some(home) = dirs::home_dir() else {
            return Ok(false);
        };
        let passphrase = std::env::var("SSHTETHER_KEY_PASSPHRASE").ok();
        for name in ["id_ed25519", "id_ecdsa", "id_rsa"] {
            let path = home.join(".ssh").join(name);
            if !path.is_file() {
                continue;
            }
            // Encrypted default keys are skipped silently: prompting here would be a
            // surprise (use the agent or list the key explicitly in the config).
            let Ok(key) = russh::keys::load_secret_key(&path, passphrase.as_deref()) else {
                ui::debug(format!(
                    "skipping default key {} (unreadable or encrypted)",
                    path.display()
                ));
                continue;
            };
            let hash = self.rsa_hash(key.public_key()).await;
            match self
                .handle
                .authenticate_publickey(user, PrivateKeyWithHashAlg::new(Arc::new(key), hash))
                .await
            {
                Ok(r) if r.success() => return Ok(true),
                Ok(_) => *rejected += 1,
                Err(e) => return Err(e.to_string()),
            }
        }
        Ok(false)
    }

    /// The underlying russh handle (used to open channels).
    pub fn handle(&self) -> &Handle<ClientHandler> {
        &self.handle
    }

    /// `true` once the transport is gone.
    pub fn is_closed(&self) -> bool {
        self.handle.is_closed()
    }

    /// Human-readable reason the link ended, if the SSH layer reported one.
    pub fn disconnect_reason(&self) -> String {
        self.shared
            .disconnect
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| "connection closed unexpectedly".to_owned())
    }

    /// Politely disconnect (bounded, never hangs on a dead link).
    pub async fn close(&self) {
        let _ = timeout(
            Duration::from_secs(2),
            self.handle.disconnect(Disconnect::ByApplication, "", "en"),
        )
        .await;
    }
}

/// TCP-level dead-peer detection in addition to the SSH-level heartbeat.
fn tune_socket(stream: &TcpStream) {
    const IDLE: Duration = Duration::from_secs(10);
    const INTERVAL: Duration = Duration::from_secs(5);
    const COUNT: u32 = 3;

    let sock = SockRef::from(stream);
    let _ = sock.set_tcp_nodelay(true);
    let ka = TcpKeepalive::new().with_time(IDLE);
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "windows"
    ))]
    let ka = ka.with_interval(INTERVAL);
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd"
    ))]
    let ka = ka.with_retries(COUNT);
    let _ = sock.set_tcp_keepalive(&ka);
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let _ = sock.set_tcp_user_timeout(Some(IDLE + INTERVAL * COUNT));
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let _ = (INTERVAL, COUNT);
}

async fn connect_agent(
) -> Result<AgentClient<Box<dyn AgentStream + Send + Unpin>>, russh::keys::Error> {
    #[cfg(unix)]
    {
        Ok(AgentClient::connect_env().await?.dynamic())
    }
    #[cfg(windows)]
    {
        match AgentClient::connect_named_pipe(r"\\.\pipe\openssh-ssh-agent").await {
            Ok(c) => Ok(c.dynamic()),
            Err(_) => Ok(AgentClient::connect_pageant().await?.dynamic()),
        }
    }
}

fn passphrase_cache() -> &'static Mutex<HashMap<PathBuf, String>> {
    static CACHE: OnceLock<Mutex<HashMap<PathBuf, String>>> = OnceLock::new();
    CACHE.get_or_init(Default::default)
}

/// Load a private key, asking for the passphrase once if it is encrypted.
///
/// Order: cached → `SSHTETHER_KEY_PASSPHRASE` → interactive prompt (TTY only).
async fn load_private_key(path: &Path) -> Result<PrivateKey, ConnectError> {
    use std::io::IsTerminal;

    let mut passphrase = passphrase_cache()
        .lock()
        .unwrap()
        .get(path)
        .cloned()
        .or_else(|| {
            std::env::var("SSHTETHER_KEY_PASSPHRASE")
                .ok()
                .filter(|p| !p.is_empty())
        });

    for attempt in 0..2 {
        match russh::keys::load_secret_key(path, passphrase.as_deref()) {
            Ok(key) => {
                if let Some(p) = passphrase {
                    passphrase_cache()
                        .lock()
                        .unwrap()
                        .insert(path.to_owned(), p);
                }
                return Ok(key);
            }
            Err(russh::keys::Error::KeyIsEncrypted) if passphrase.is_none() && attempt == 0 => {
                if !std::io::stdin().is_terminal() {
                    return Err(ConnectError::fatal(format!(
                        "{}: key is encrypted (set SSHTETHER_KEY_PASSPHRASE or use ssh-agent)",
                        path.display()
                    )));
                }
                let prompt = format!("Passphrase for {}: ", path.display());
                let entered =
                    tokio::task::spawn_blocking(move || rpassword::prompt_password(prompt))
                        .await
                        .map_err(|e| ConnectError::fatal(e.to_string()))?
                        .map_err(|e| ConnectError::fatal(format!("cannot read passphrase: {e}")))?;
                passphrase = Some(entered);
            }
            Err(e) => {
                let hint = if passphrase.is_some() {
                    " - wrong passphrase?"
                } else {
                    ""
                };
                return Err(ConnectError::fatal(format!(
                    "{}: cannot load key ({e}){hint}",
                    path.display()
                )));
            }
        }
    }
    Err(ConnectError::fatal(format!(
        "{}: cannot load key",
        path.display()
    )))
}
