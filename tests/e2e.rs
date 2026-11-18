//! End-to-end tests against an in-process russh SSH server.
//!
//! The server understands a tiny command language so each scenario can be
//! provoked deterministically:
//!
//! * `exit N`  – print a line, then exit with status N
//! * `flaky`   – the first execution kills the TCP connection mid-run, later
//!   executions exit 0 (simulates a dropped link)
//! * `sleep`   – run forever (used for the silent-network-death test)

use russh::keys::known_hosts::learn_known_hosts_path;
use russh::keys::ssh_key::LineEnding;
use russh::keys::{Algorithm, PrivateKey};
use russh::server::{self, Auth, Msg, Session, VerifiedPublicKey};
use russh::{Channel, ChannelId};
use sshtether::cli::HostKeyPolicy;
use sshtether::command::RemoteCommand;
use sshtether::config::ServerConfig;
use sshtether::connection::ConnectOpts;
use sshtether::session::SessionOpts;
use sshtether::supervisor::{RetryOpts, Supervisor};
use sshtether::terminal::InputPump;
use sshtether::{EXIT_GIVE_UP, EXIT_OK};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

const PASSWORD: &str = "s3cret";

#[derive(Default)]
struct State {
    execs: Mutex<Vec<String>>,
    flaky_calls: AtomicUsize,
    /// Connections currently open on the server (leak detector).
    live: AtomicUsize,
}

struct TestServer {
    addr: SocketAddr,
    state: Arc<State>,
    host_key: PrivateKey,
}

impl TestServer {
    async fn wait_no_live_connections(&self) {
        let t = Instant::now();
        while self.state.live.load(Ordering::SeqCst) != 0 {
            assert!(
                t.elapsed() < Duration::from_secs(5),
                "leaked connection(s): {}",
                self.state.live.load(Ordering::SeqCst)
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    fn execs(&self) -> Vec<String> {
        self.state.execs.lock().unwrap().clone()
    }
}

struct Handler {
    state: Arc<State>,
    kill: Arc<Mutex<Option<oneshot::Sender<()>>>>,
}

impl server::Handler for Handler {
    type Error = russh::Error;

    async fn auth_password(&mut self, _user: &str, password: &str) -> Result<Auth, Self::Error> {
        Ok(if password == PASSWORD {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    async fn auth_publickey(
        &mut self,
        _user: &str,
        _key: VerifiedPublicKey<'_>,
    ) -> Result<Auth, Self::Error> {
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let full = String::from_utf8_lossy(data).into_owned();
        // Strip the `export LANG=..; ` prefix when present.
        let cmd = full
            .strip_prefix("export ")
            .and_then(|r| r.split_once("; ").map(|(_, c)| c.to_owned()))
            .unwrap_or(full);
        self.state.execs.lock().unwrap().push(cmd.clone());
        session.channel_success(channel)?;

        let finish = |session: &mut Session, code: u32| -> Result<(), russh::Error> {
            session.data(channel, b"bye\r\n".to_vec())?;
            session.exit_status_request(channel, code)?;
            session.eof(channel)?;
            session.close(channel)?;
            Ok(())
        };

        match cmd.as_str() {
            "sleep" => Ok(()),
            "flaky" => {
                if self.state.flaky_calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    session.data(channel, b"partial output...\r\n".to_vec())?;
                    if let Some(tx) = self.kill.lock().unwrap().take() {
                        let _ = tx.send(());
                    }
                    Ok(())
                } else {
                    finish(session, 0)
                }
            }
            c if c.starts_with("exit ") => finish(session, c[5..].parse().unwrap_or(1)),
            _ => finish(session, 0),
        }
    }
}

async fn start_server() -> TestServer {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let host_key = PrivateKey::random(&mut rand10::rng(), Algorithm::Ed25519).unwrap();
    let state = Arc::new(State::default());
    let config = Arc::new(server::Config {
        keys: vec![host_key.clone()],
        auth_rejection_time: Duration::from_millis(0),
        auth_rejection_time_initial: Some(Duration::from_millis(0)),
        ..Default::default()
    });

    let st = state.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let (ktx, krx) = oneshot::channel();
            let handler = Handler {
                state: st.clone(),
                kill: Arc::new(Mutex::new(Some(ktx))),
            };
            let config = config.clone();
            st.live.fetch_add(1, Ordering::SeqCst);
            let st2 = st.clone();
            // The SSH session talks to an in-memory pipe that is relayed to the real
            // socket, so aborting the relay closes the TCP connection abruptly.
            let (srv_side, mut relay_side) = tokio::io::duplex(64 * 1024);
            let mut tcp = stream;
            let relay = tokio::spawn(async move {
                let _ = tokio::io::copy_bidirectional(&mut tcp, &mut relay_side).await;
            });
            tokio::spawn(async move {
                if let Ok(running) = server::run_stream(config, srv_side, handler).await {
                    tokio::select! {
                        _ = running => {}
                        _ = krx => relay.abort(),
                    }
                }
                st2.live.fetch_sub(1, Ordering::SeqCst);
            });
        }
    });
    TestServer {
        addr,
        state,
        host_key,
    }
}

async fn relay(
    mut from: tokio::net::tcp::OwnedReadHalf,
    mut to: tokio::net::tcp::OwnedWriteHalf,
    freeze: Arc<AtomicBool>,
) {
    let mut buf = [0u8; 8192];
    loop {
        match from.read(&mut buf).await {
            Ok(n) if n > 0 => {
                while freeze.load(Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                if to.write_all(&buf[..n]).await.is_err() {
                    return;
                }
            }
            _ => return,
        }
    }
}

/// A TCP relay that can be frozen to simulate silent network death.
async fn start_proxy(target: SocketAddr) -> (SocketAddr, Arc<AtomicBool>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let freeze = Arc::new(AtomicBool::new(false));
    let fr = freeze.clone();
    tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            let Ok(upstream) = TcpStream::connect(target).await else {
                continue;
            };
            let (cr, cw) = client.into_split();
            let (ur, uw) = upstream.into_split();
            tokio::spawn(relay(cr, uw, fr.clone()));
            tokio::spawn(relay(ur, cw, fr.clone()));
        }
    });
    (addr, freeze)
}

fn server_cfg(addr: SocketAddr, password: &str) -> ServerConfig {
    ServerConfig {
        name: format!("test-{}", addr.port()),
        hostname: addr.ip().to_string(),
        username: "tester".into(),
        port: addr.port(),
        key_files: vec![],
        password: Some(password.into()),
    }
}

fn connect_opts(known_hosts: &Path, policy: HostKeyPolicy) -> ConnectOpts {
    ConnectOpts {
        connect_timeout: Duration::from_secs(3),
        keepalive: Duration::from_millis(300),
        keepalive_max: 2,
        host_key_policy: policy,
        known_hosts: known_hosts.to_owned(),
        no_agent: true,
    }
}

fn fast_retry(infinite: bool) -> RetryOpts {
    RetryOpts {
        infinite,
        max_retries: 2,
        delay: 0.05,
        max_delay: 0.1,
        no_rerun: false,
    }
}

async fn run(servers: Vec<ServerConfig>, cmd: &str, connect: ConnectOpts, retry: RetryOpts) -> i32 {
    let sup = Supervisor::new(
        servers,
        RemoteCommand {
            command: cmd.into(),
            resumable: false,
        },
        connect,
        SessionOpts {
            term: "xterm".into(),
            lang: "C.UTF-8".into(),
            run_id: None,
        },
        retry,
    );
    let mut input = InputPump::start();
    tokio::time::timeout(Duration::from_secs(30), sup.run(&mut input))
        .await
        .expect("supervisor hung")
}

fn tmp_known_hosts(dir: &tempfile::TempDir) -> PathBuf {
    dir.path().join("known_hosts")
}

#[tokio::test(flavor = "multi_thread")]
async fn propagates_remote_exit_status() {
    let srv = start_server().await;
    let dir = tempfile::tempdir().unwrap();
    let kh = tmp_known_hosts(&dir);
    let code = run(
        vec![server_cfg(srv.addr, PASSWORD)],
        "exit 7",
        connect_opts(&kh, HostKeyPolicy::AcceptNew),
        fast_retry(true),
    )
    .await;
    assert_eq!(code, 7);
    assert_eq!(
        srv.execs(),
        ["exit 7"],
        "LANG export prefix must reach the server"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn zero_exit_and_trust_on_first_use_saves_host_key() {
    let srv = start_server().await;
    let dir = tempfile::tempdir().unwrap();
    let kh = tmp_known_hosts(&dir);
    let code = run(
        vec![server_cfg(srv.addr, PASSWORD)],
        "true",
        connect_opts(&kh, HostKeyPolicy::AcceptNew),
        fast_retry(true),
    )
    .await;
    assert_eq!(code, EXIT_OK);
    let saved = std::fs::read_to_string(&kh).unwrap();
    assert!(saved.contains("ssh-ed25519"), "known_hosts: {saved}");
    assert!(saved.contains(&format!("[127.0.0.1]:{}", srv.addr.port())));

    // A second run now succeeds even under the strict policy.
    let code = run(
        vec![server_cfg(srv.addr, PASSWORD)],
        "true",
        connect_opts(&kh, HostKeyPolicy::Strict),
        fast_retry(false),
    )
    .await;
    assert_eq!(code, EXIT_OK);
}

#[tokio::test(flavor = "multi_thread")]
async fn strict_policy_refuses_unknown_host() {
    let srv = start_server().await;
    let dir = tempfile::tempdir().unwrap();
    let kh = tmp_known_hosts(&dir);
    let code = run(
        vec![server_cfg(srv.addr, PASSWORD)],
        "true",
        connect_opts(&kh, HostKeyPolicy::Strict),
        fast_retry(true),
    )
    .await;
    assert_eq!(
        code, EXIT_GIVE_UP,
        "fatal error must not be retried forever"
    );
    assert!(srv.execs().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn changed_host_key_is_refused_even_with_insecure_policy() {
    let srv = start_server().await;
    let dir = tempfile::tempdir().unwrap();
    let kh = tmp_known_hosts(&dir);
    let other = PrivateKey::random(&mut rand10::rng(), Algorithm::Ed25519).unwrap();
    learn_known_hosts_path("127.0.0.1", srv.addr.port(), other.public_key(), &kh).unwrap();
    assert_ne!(other.public_key(), srv.host_key.public_key());

    let code = run(
        vec![server_cfg(srv.addr, PASSWORD)],
        "true",
        connect_opts(&kh, HostKeyPolicy::Insecure),
        fast_retry(true),
    )
    .await;
    assert_eq!(code, EXIT_GIVE_UP);
    assert!(
        srv.execs().is_empty(),
        "must not run anything on a spoofed host"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_password_disables_server_instead_of_retrying_forever() {
    let srv = start_server().await;
    let dir = tempfile::tempdir().unwrap();
    let kh = tmp_known_hosts(&dir);
    let started = Instant::now();
    let code = run(
        vec![server_cfg(srv.addr, "nope")],
        "true",
        connect_opts(&kh, HostKeyPolicy::AcceptNew),
        fast_retry(true),
    )
    .await;
    assert_eq!(code, EXIT_GIVE_UP);
    assert!(started.elapsed() < Duration::from_secs(10));
    assert!(srv.execs().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn authenticates_with_a_private_key_file() {
    let srv = start_server().await;
    let dir = tempfile::tempdir().unwrap();
    let kh = tmp_known_hosts(&dir);
    let key = PrivateKey::random(&mut rand10::rng(), Algorithm::Ed25519).unwrap();
    let key_path = dir.path().join("id_ed25519");
    std::fs::write(
        &key_path,
        key.to_openssh(LineEnding::LF).unwrap().as_bytes(),
    )
    .unwrap();

    let mut cfg = server_cfg(srv.addr, "irrelevant");
    cfg.password = None;
    cfg.key_files = vec![key_path];
    let code = run(
        vec![cfg],
        "exit 3",
        connect_opts(&kh, HostKeyPolicy::AcceptNew),
        fast_retry(true),
    )
    .await;
    assert_eq!(code, 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_key_file_without_password_is_fatal() {
    let srv = start_server().await;
    let dir = tempfile::tempdir().unwrap();
    let kh = tmp_known_hosts(&dir);
    let mut cfg = server_cfg(srv.addr, "x");
    cfg.password = None;
    cfg.key_files = vec![dir.path().join("does-not-exist")];
    let code = run(
        vec![cfg],
        "true",
        connect_opts(&kh, HostKeyPolicy::AcceptNew),
        fast_retry(true),
    )
    .await;
    assert_eq!(code, EXIT_GIVE_UP);
}

#[tokio::test(flavor = "multi_thread")]
async fn reconnects_and_reruns_after_a_mid_run_drop() {
    let srv = start_server().await;
    let dir = tempfile::tempdir().unwrap();
    let kh = tmp_known_hosts(&dir);
    let code = run(
        vec![server_cfg(srv.addr, PASSWORD)],
        "flaky",
        connect_opts(&kh, HostKeyPolicy::AcceptNew),
        fast_retry(true),
    )
    .await;
    assert_eq!(code, EXIT_OK);
    assert_eq!(
        srv.execs(),
        ["flaky", "flaky"],
        "command must be re-executed once after the drop"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn no_rerun_gives_up_after_a_drop() {
    let srv = start_server().await;
    let dir = tempfile::tempdir().unwrap();
    let kh = tmp_known_hosts(&dir);
    let mut retry = fast_retry(true);
    retry.no_rerun = true;
    let code = run(
        vec![server_cfg(srv.addr, PASSWORD)],
        "flaky",
        connect_opts(&kh, HostKeyPolicy::AcceptNew),
        retry,
    )
    .await;
    assert_eq!(code, EXIT_GIVE_UP);
    assert_eq!(srv.execs(), ["flaky"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn fails_over_to_the_next_server() {
    let dead = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap() // listener dropped: connection refused
    };
    let live = start_server().await;
    let dir = tempfile::tempdir().unwrap();
    let kh = tmp_known_hosts(&dir);
    let code = run(
        vec![server_cfg(dead, PASSWORD), server_cfg(live.addr, PASSWORD)],
        "exit 5",
        connect_opts(&kh, HostKeyPolicy::AcceptNew),
        fast_retry(true),
    )
    .await;
    assert_eq!(code, 5);
    assert_eq!(live.execs(), ["exit 5"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn max_mode_gives_up_when_nothing_is_reachable() {
    let dead = {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        l.local_addr().unwrap()
    };
    let dir = tempfile::tempdir().unwrap();
    let kh = tmp_known_hosts(&dir);
    let started = Instant::now();
    let code = run(
        vec![server_cfg(dead, PASSWORD)],
        "true",
        connect_opts(&kh, HostKeyPolicy::AcceptNew),
        fast_retry(false),
    )
    .await;
    assert_eq!(code, EXIT_GIVE_UP);
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[tokio::test(flavor = "multi_thread")]
async fn detects_silent_network_death_via_heartbeat() {
    let srv = start_server().await;
    let (proxy, freeze) = start_proxy(srv.addr).await;
    let dir = tempfile::tempdir().unwrap();
    let kh = tmp_known_hosts(&dir);

    let mut retry = fast_retry(true);
    retry.no_rerun = true; // report the drop instead of reconnecting
    let started = Instant::now();
    let task = tokio::spawn(async move {
        run(
            vec![server_cfg(proxy, PASSWORD)],
            "sleep",
            connect_opts(&kh, HostKeyPolicy::AcceptNew),
            retry,
        )
        .await
    });

    // Wait until the command is running, then black-hole the link (no FIN, no RST).
    let t0 = Instant::now();
    while srv.execs().is_empty() {
        assert!(
            t0.elapsed() < Duration::from_secs(10),
            "command never started"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    freeze.store(true, Ordering::SeqCst);

    let code = tokio::time::timeout(Duration::from_secs(15), task)
        .await
        .expect("heartbeat did not fire")
        .unwrap();
    assert_eq!(code, EXIT_GIVE_UP);
    assert!(
        started.elapsed() < Duration::from_secs(12),
        "took {:?}",
        started.elapsed()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn command_goes_through_the_single_instance_wrapper_and_connections_are_closed() {
    let srv = start_server().await;
    let dir = tempfile::tempdir().unwrap();
    let kh = tmp_known_hosts(&dir);
    let sup = Supervisor::new(
        vec![server_cfg(srv.addr, PASSWORD)],
        RemoteCommand {
            command: "echo hi".into(),
            resumable: false,
        },
        connect_opts(&kh, HostKeyPolicy::AcceptNew),
        SessionOpts {
            term: "xterm".into(),
            lang: String::new(),
            run_id: Some("deadbeef".into()),
        },
        fast_retry(true),
    );
    let mut input = InputPump::start();
    let code = tokio::time::timeout(Duration::from_secs(30), sup.run(&mut input))
        .await
        .unwrap();
    assert_eq!(code, EXIT_OK);
    let execs = srv.execs();
    assert_eq!(execs.len(), 1);
    assert!(execs[0].starts_with("sh -c "), "wrapped: {}", execs[0]);
    assert!(execs[0].contains("sshtether-deadbeef"));
    assert!(execs[0].ends_with("'echo hi'"));
    srv.wait_no_live_connections().await;
}
