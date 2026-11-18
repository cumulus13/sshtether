// File: sshtether/src/error.rs
// Author: Hadi Cahyadi <cumulus13@gmail.com>
// Date: 2026-11-18 14:35:08 SE Asia Standard Time
// Description:
// License: MIT

//! Error types shared by the connection layer and the supervisor.

use thiserror::Error;

/// A failure while establishing an SSH connection.
///
/// The distinction drives the supervisor: [`Transient`](Self::Transient)
/// failures are retried with backoff, [`Fatal`](Self::Fatal) failures disable
/// the server for the rest of the run (bad key, denied auth, changed host key).
#[derive(Debug, Error)]
pub enum ConnectError {
    /// Worth retrying (network down, timeout, server rebooting, ...).
    #[error("{0}")]
    Transient(String),
    /// Retrying cannot help (authentication denied, host key changed, ...).
    #[error("{0}")]
    Fatal(String),
}

impl ConnectError {
    /// Build a [`ConnectError::Transient`].
    pub fn transient(msg: impl Into<String>) -> Self {
        Self::Transient(msg.into())
    }

    /// Build a [`ConnectError::Fatal`].
    pub fn fatal(msg: impl Into<String>) -> Self {
        Self::Fatal(msg.into())
    }
}

/// A failure while loading or validating the server configuration.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// `--config` pointed at a file that does not exist.
    #[error("config file not found: {0}")]
    NotFound(String),
    /// The file exists but is not valid (syntax or content).
    #[error("invalid config {path}: {reason}")]
    Invalid {
        /// The offending file.
        path: String,
        /// What is wrong with it.
        reason: String,
    },
    /// Neither `--host` nor any config file was provided.
    #[error("no server specified: use --host, --config, $SSHTETHER_CONFIG or create one of:\n{0}")]
    NoServers(String),
}
