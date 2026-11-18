// File: sshtether/src/lib.rs
// Author: Hadi Cahyadi <cumulus13@gmail.com>
// Date: 2026-11-18 14:35:08 SE Asia Standard Time
// Description:
// License: MIT

//! # sshtether
//!
//! A remote command runner over SSH that stays *tethered*: it survives failed
//! connects, mid-run drops, silent network death, sleeping laptops and
//! rebooting servers by reconnecting (with failover and exponential backoff)
//! and re-running or re-attaching to the remote command.
//!
//! The crate is primarily a command-line tool (`sshtether`), but the building
//! blocks are public so they can be reused and tested:
//!
//! * [`config`] – server list loading (TOML / JSON) and path expansion
//! * [`command`] – remote command construction (`--persist tmux|screen`)
//! * [`connection`] – TCP tuning, host-key policy and authentication
//! * [`session`] – one connected run of the remote command (PTY, I/O pump)
//! * [`supervisor`] – connect → run → reconnect loop with failover/backoff
//! * [`terminal`] / [`escape`] – local terminal handling and `~.` escapes
//!
//! ## Exit codes
//!
//! | code | meaning                                   |
//! |------|-------------------------------------------|
//! | *n*  | the remote command's own exit status      |
//! | 0    | user typed `~.`                           |
//! | 1    | local error                               |
//! | 130  | Ctrl+C while not attached to the remote   |
//! | 255  | gave up connecting / no usable servers    |

#![forbid(unsafe_op_in_unsafe_fn)]

pub mod cli;
pub mod command;
pub mod config;
pub mod connection;
pub mod error;
pub mod escape;
pub mod session;
pub mod supervisor;
pub mod terminal;
pub mod ui;

/// The remote command succeeded, or the user detached with `~.`.
pub const EXIT_OK: i32 = 0;
/// A local, non-retryable error.
pub const EXIT_ERROR: i32 = 1;
/// Interrupted (Ctrl+C) while not attached to the remote command.
pub const EXIT_INTERRUPTED: i32 = 130;
/// Gave up connecting, or every configured server failed permanently.
pub const EXIT_GIVE_UP: i32 = 255;
