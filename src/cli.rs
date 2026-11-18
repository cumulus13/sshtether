//! Command-line interface definition.

use clap::{Parser, ValueEnum};
use std::path::PathBuf;

/// How long to keep trying before giving up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum RetryMode {
    /// Give up after `--max-retries` failed attempts per server.
    #[value(alias = "0")]
    Max,
    /// Keep trying forever (default).
    #[value(alias = "1")]
    Infinity,
}

/// Server host-key verification policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum HostKeyPolicy {
    /// Trust on first use: unknown hosts are saved, changed keys are refused.
    AcceptNew,
    /// Refuse any host that is not already in known_hosts.
    Strict,
    /// Accept unknown hosts without saving them (changed keys are still refused).
    Insecure,
}

/// Wrap the command in a terminal multiplexer on the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Persist {
    /// Run the command directly.
    None,
    /// Run inside `tmux`, so it keeps running when the link drops.
    Tmux,
    /// Run inside GNU `screen`.
    Screen,
}

/// Remote command runner over SSH with auto-reconnect.
#[derive(Parser, Debug)]
#[command(
    name = "sshtether",
    version,
    about = "Remote command runner over SSH with auto-reconnect \
             (survives failed connects, mid-run drops and silent network death)",
    after_help = "Escape sequences (start of a line):  ~. quit   ~? help   ~~ literal ~\n\
                  Exit codes: remote command's own code | 0 on ~. | 1 local error | \
                  130 Ctrl+C | 255 gave up",
    override_usage = "sshtether [OPTIONS] [--] <COMMAND>..."
)]
pub struct Cli {
    /// 'infinity'/'1' keep trying forever; 'max'/'0' give up after --max-retries
    #[arg(
        short = 'r',
        long,
        value_enum,
        default_value = "infinity",
        help_heading = "Retry"
    )]
    pub retry: RetryMode,

    /// Attempts per server in 'max' mode
    #[arg(short = 'm', long, default_value_t = 3, help_heading = "Retry")]
    pub max_retries: u32,

    /// Base backoff delay in seconds, doubled each round
    #[arg(short = 'd', long, default_value_t = 3.0, value_parser = positive_secs, help_heading = "Retry")]
    pub delay: f64,

    /// Backoff ceiling in seconds
    #[arg(long, default_value_t = 30.0, value_parser = positive_secs, help_heading = "Retry")]
    pub max_delay: f64,

    /// Do not re-execute the command after a mid-run drop
    #[arg(long, help_heading = "Retry")]
    pub no_rerun: bool,

    /// TOML/JSON file with the server list
    #[arg(
        short = 'c',
        long,
        value_name = "FILE",
        help_heading = "Target (overrides config file)"
    )]
    pub config: Option<PathBuf>,

    /// Connect to this host instead of the configured servers
    #[arg(
        short = 'H',
        long,
        value_name = "HOST",
        help_heading = "Target (overrides config file)"
    )]
    pub host: Option<String>,

    /// Username (with --host) [default: current user]
    #[arg(
        short = 'u',
        long,
        value_name = "USER",
        help_heading = "Target (overrides config file)"
    )]
    pub user: Option<String>,

    /// Port (with --host)
    #[arg(
        short = 'p',
        long,
        default_value_t = 22,
        help_heading = "Target (overrides config file)"
    )]
    pub port: u16,

    /// Private key file, repeatable (with --host)
    #[arg(
        short = 'i',
        long,
        value_name = "FILE",
        help_heading = "Target (overrides config file)"
    )]
    pub identity: Vec<PathBuf>,

    /// Connect timeout in seconds
    #[arg(short = 't', long, default_value_t = 10.0, value_parser = positive_secs, help_heading = "Connection")]
    pub connect_timeout: f64,

    /// Heartbeat interval in seconds
    #[arg(long, default_value_t = 5.0, value_parser = positive_secs, help_heading = "Connection")]
    pub keepalive: f64,

    /// Missed heartbeats before the link is declared dead
    #[arg(long, default_value_t = 3, value_parser = clap::value_parser!(u32).range(1..), help_heading = "Connection")]
    pub keepalive_max: u32,

    /// Host-key verification policy
    #[arg(
        long,
        value_enum,
        default_value = "accept-new",
        help_heading = "Connection"
    )]
    pub host_key_policy: HostKeyPolicy,

    /// known_hosts file used (and updated) for host-key checks
    #[arg(
        long,
        default_value = "~/.ssh/known_hosts",
        value_name = "FILE",
        help_heading = "Connection"
    )]
    pub known_hosts: String,

    /// Use only the configured key files (no ssh-agent / ~/.ssh fallback)
    #[arg(long, help_heading = "Connection")]
    pub no_agent: bool,

    /// Wrap the command in tmux/screen on the server so it survives disconnects
    #[arg(long, value_enum, default_value = "none", help_heading = "Session")]
    pub persist: Persist,

    /// tmux/screen session name [default: derived from the command]
    #[arg(long, value_name = "NAME", help_heading = "Session")]
    pub session_name: Option<String>,

    /// Do not stop the previous instance of the command on reconnect
    #[arg(long, help_heading = "Session")]
    pub allow_duplicates: bool,

    /// TERM for the remote PTY
    #[arg(long, default_value = "xterm-256color", help_heading = "Session")]
    pub term: String,

    /// LANG/LC_ALL for the remote (empty to disable)
    #[arg(long, default_value = "C.UTF-8", help_heading = "Session")]
    pub lang: String,

    /// Verbose diagnostics
    #[arg(short = 'v', long, help_heading = "Output")]
    pub verbose: bool,

    /// Only show warnings and errors
    #[arg(short = 'q', long, help_heading = "Output")]
    pub quiet: bool,

    /// Remote command, e.g.  htop  |  tmux attach -t main
    #[arg(
        value_name = "COMMAND",
        trailing_var_arg = true,
        allow_hyphen_values = true
    )]
    pub command: Vec<String>,
}

/// Parse a strictly positive, finite number of seconds.
fn positive_secs(s: &str) -> Result<f64, String> {
    let v: f64 = s.parse().map_err(|_| format!("'{s}' is not a number"))?;
    if v.is_finite() && v > 0.0 {
        Ok(v)
    } else {
        Err("must be a positive number".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn command_after_double_dash_keeps_its_flags() {
        let c =
            Cli::try_parse_from(["sshtether", "-H", "h", "--", "journalctl", "-f", "-v"]).unwrap();
        assert_eq!(c.host.as_deref(), Some("h"));
        assert_eq!(c.command, ["journalctl", "-f", "-v"]);
        assert!(!c.verbose);
    }

    #[test]
    fn flags_after_first_command_word_belong_to_the_command() {
        let c = Cli::try_parse_from(["sshtether", "tmux", "attach", "-t", "main"]).unwrap();
        assert_eq!(c.command, ["tmux", "attach", "-t", "main"]);
    }

    #[test]
    fn numeric_retry_aliases() {
        let c = Cli::try_parse_from(["sshtether", "-r", "0", "x"]).unwrap();
        assert_eq!(c.retry, RetryMode::Max);
        let c = Cli::try_parse_from(["sshtether", "-r", "1", "x"]).unwrap();
        assert_eq!(c.retry, RetryMode::Infinity);
    }

    #[test]
    fn rejects_non_positive_durations() {
        assert!(Cli::try_parse_from(["sshtether", "-d", "0", "x"]).is_err());
        assert!(Cli::try_parse_from(["sshtether", "--keepalive", "-1", "x"]).is_err());
    }
}
