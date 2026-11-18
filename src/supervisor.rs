// File: sshtether/src/supervisor.rs
// Author: Hadi Cahyadi <cumulus13@gmail.com>
// Date: 2026-11-18 14:35:08 SE Asia Standard Time
// Description:
// License: MIT

//! The connect → run → reconnect loop, with failover between servers and
//! jittered exponential backoff.

use crate::cli::{Cli, RetryMode};
use crate::command::RemoteCommand;
use crate::config::ServerConfig;
use crate::connection::{ConnectOpts, Connection};
use crate::error::ConnectError;
use crate::session::{run_session, Outcome, SessionOpts};
use crate::terminal::{reset_local_terminal, InputPump};
use crate::{ui, EXIT_ERROR, EXIT_GIVE_UP, EXIT_OK};
use rand::Rng;
use std::collections::HashSet;
use std::time::{Duration, Instant};

/// A session that lived at least this long counts as healthy and resets backoff.
pub const STABLE_AFTER: Duration = Duration::from_secs(15);

/// Retry policy.
#[derive(Debug, Clone)]
pub struct RetryOpts {
    /// Retry forever.
    pub infinite: bool,
    /// Failed attempts per server before giving up (when not infinite).
    pub max_retries: u32,
    /// Base delay in seconds, doubled each full round over the servers.
    pub delay: f64,
    /// Backoff ceiling in seconds.
    pub max_delay: f64,
    /// Do not re-run the command after a mid-run drop.
    pub no_rerun: bool,
}

impl RetryOpts {
    /// Derive the policy from parsed command-line arguments.
    pub fn from_cli(cli: &Cli) -> Self {
        Self {
            infinite: cli.retry == RetryMode::Infinity,
            max_retries: cli.max_retries,
            delay: cli.delay,
            max_delay: cli.max_delay,
            no_rerun: cli.no_rerun,
        }
    }

    /// Seconds to wait after `bad` consecutive failures with `servers` usable
    /// servers. `jitter` is a multiplier (normally in 0.8..1.2).
    pub fn backoff(&self, bad: u32, servers: usize, jitter: f64) -> f64 {
        let servers = servers.max(1) as u32;
        if bad == 0 {
            return 1.0; // a healthy session dropped: reconnect almost immediately
        }
        // `%` rather than `is_multiple_of`, which is newer than our MSRV.
        #[allow(clippy::manual_is_multiple_of)]
        let mid_round = servers > 1 && bad % servers != 0;
        if mid_round {
            return 0.5; // try the next server right away
        }
        let rounds = (bad / servers).max(1);
        let exp = f64::from((rounds - 1).min(30));
        (self.max_delay.min(self.delay * 2f64.powf(exp))) * jitter
    }

    /// Whether to stop after `bad` consecutive failures.
    pub fn give_up(&self, bad: u32, active_servers: usize) -> bool {
        !self.infinite && u64::from(bad) >= u64::from(self.max_retries) * active_servers as u64
    }
}

/// Drives the whole run.
pub struct Supervisor {
    servers: Vec<ServerConfig>,
    command: RemoteCommand,
    connect: ConnectOpts,
    session: SessionOpts,
    retry: RetryOpts,
}

impl Supervisor {
    /// Assemble a supervisor.
    pub fn new(
        servers: Vec<ServerConfig>,
        command: RemoteCommand,
        connect: ConnectOpts,
        session: SessionOpts,
        retry: RetryOpts,
    ) -> Self {
        Self {
            servers,
            command,
            connect,
            session,
            retry,
        }
    }

    /// Run until the command exits, the user quits or we give up.
    /// Returns the process exit code.
    pub async fn run(&self, input: &mut InputPump) -> i32 {
        let n = self.servers.len();
        let mut disabled: HashSet<usize> = HashSet::new();
        let (mut idx, mut bad, mut attempt) = (0usize, 0u32, 0u32);
        let mut warned_rerun = false;

        loop {
            let active = n - disabled.len();
            if active == 0 {
                ui::error("No usable servers left (all failed permanently).");
                return EXIT_GIVE_UP;
            }
            idx = next_active(idx, &disabled, n);
            let server = &self.servers[idx];

            attempt += 1;
            ui::info(format!(
                "Connecting to {} (attempt {attempt})",
                server.label()
            ));
            let conn = match Connection::open(server, &self.connect).await {
                Ok(c) => c,
                Err(ConnectError::Fatal(e)) => {
                    ui::error(format!("{}: {e} - disabling this server.", server.name));
                    disabled.insert(idx);
                    idx = (idx + 1) % n;
                    continue;
                }
                Err(ConnectError::Transient(e)) => {
                    bad += 1;
                    ui::warn(format!("{}: connect failed: {e}", server.name));
                    idx = (idx + 1) % n;
                    if self.retry.give_up(bad, active) {
                        ui::error(format!("Giving up after {bad} failed attempt(s)."));
                        return EXIT_GIVE_UP;
                    }
                    self.sleep(self.retry.backoff(bad, active, jitter())).await;
                    continue;
                }
            };

            ui::ok(format!("Connected to {}", server.name));
            if attempt == 1 {
                ui::info("Type  Enter ~.  to disconnect, ~? for help.");
            }
            ui::info(format!("Running: {}", self.command.command));
            let started = Instant::now();
            let result = run_session(&conn, &self.command.command, &self.session, input).await;
            conn.close().await;
            let lived = started.elapsed();

            match result.outcome {
                Outcome::Exited => {
                    if !result.reason.is_empty() {
                        ui::warn(&result.reason);
                    }
                    ui::info(format!("Command exited with status {}.", result.exit_code));
                    return result.exit_code;
                }
                Outcome::Quit => {
                    reset_local_terminal();
                    ui::info("Disconnected by user.");
                    return EXIT_OK;
                }
                Outcome::Error => {
                    reset_local_terminal();
                    ui::error(format!("Non-retryable error: {}", result.reason));
                    return EXIT_ERROR;
                }
                Outcome::Dropped => {}
            }

            reset_local_terminal();
            ui::warn(format!(
                "Connection to {} lost after {:.0}s: {}",
                server.name,
                lived.as_secs_f64(),
                result.reason
            ));
            if self.retry.no_rerun {
                ui::error("--no-rerun set; not reconnecting.");
                return EXIT_GIVE_UP;
            }
            if !self.command.resumable && !warned_rerun {
                ui::warn(
                    "Command is not resumable: it will restart from scratch on reconnect \
                     (use --persist tmux to keep it running on the server).",
                );
                warned_rerun = true;
            }

            if lived >= STABLE_AFTER {
                bad = 0;
            } else {
                bad += 1;
                if n > 1 {
                    idx = (idx + 1) % n;
                }
            }
            if self.retry.give_up(bad, active) {
                ui::error("Giving up: connection keeps failing.");
                return EXIT_GIVE_UP;
            }
            self.sleep(self.retry.backoff(bad, active, jitter())).await;
        }
    }

    async fn sleep(&self, seconds: f64) {
        ui::info(format!("Retrying in {seconds:.1}s ... (Ctrl+C to cancel)"));
        tokio::time::sleep(Duration::from_secs_f64(seconds)).await;
    }
}

fn jitter() -> f64 {
    rand::rng().random_range(0.8..1.2)
}

/// First non-disabled index at or after `idx` (cyclic).
fn next_active(idx: usize, disabled: &HashSet<usize>, n: usize) -> usize {
    (0..n)
        .map(|o| (idx + o) % n)
        .find(|i| !disabled.contains(i))
        .unwrap_or(idx)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(infinite: bool) -> RetryOpts {
        RetryOpts {
            infinite,
            max_retries: 3,
            delay: 3.0,
            max_delay: 30.0,
            no_rerun: false,
        }
    }

    #[test]
    fn healthy_drop_reconnects_fast() {
        assert_eq!(opts(true).backoff(0, 1, 1.0), 1.0);
    }

    #[test]
    fn single_server_backoff_doubles_and_caps() {
        let o = opts(true);
        assert_eq!(o.backoff(1, 1, 1.0), 3.0);
        assert_eq!(o.backoff(2, 1, 1.0), 6.0);
        assert_eq!(o.backoff(3, 1, 1.0), 12.0);
        assert_eq!(o.backoff(4, 1, 1.0), 24.0);
        assert_eq!(o.backoff(5, 1, 1.0), 30.0);
        assert_eq!(o.backoff(500, 1, 1.0), 30.0, "no overflow, stays capped");
    }

    #[test]
    fn failover_tries_next_server_immediately() {
        let o = opts(true);
        assert_eq!(o.backoff(1, 2, 1.0), 0.5);
        assert_eq!(o.backoff(2, 2, 1.0), 3.0, "full round done: back off");
        assert_eq!(o.backoff(3, 2, 1.0), 0.5);
        assert_eq!(o.backoff(4, 2, 1.0), 6.0);
    }

    #[test]
    fn give_up_only_in_max_mode() {
        assert!(!opts(true).give_up(1000, 2));
        let o = opts(false);
        assert!(!o.give_up(2, 1));
        assert!(o.give_up(3, 1));
        assert!(!o.give_up(5, 2));
        assert!(o.give_up(6, 2));
    }

    #[test]
    fn next_active_skips_disabled() {
        let d: HashSet<usize> = [1].into_iter().collect();
        assert_eq!(next_active(1, &d, 3), 2);
        assert_eq!(next_active(2, &d, 3), 2);
        let d: HashSet<usize> = [0, 2].into_iter().collect();
        assert_eq!(next_active(2, &d, 3), 1);
    }
}
