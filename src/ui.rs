// File: sshtether/src/ui.rs
// Author: Hadi Cahyadi <cumulus13@gmail.com>
// Date: 2026-11-18 14:35:08 SE Asia Standard Time
// Description:
// License: MIT

//! Timestamped, optionally coloured diagnostics on **stderr**.
//!
//! Nothing here is ever printed while the terminal is in raw mode, and remote
//! output (stdout) is never mixed with local diagnostics.

use std::fmt::Display;
use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};

static QUIET: AtomicBool = AtomicBool::new(false);
static VERBOSE: AtomicBool = AtomicBool::new(false);
static COLOR: AtomicBool = AtomicBool::new(false);

/// Configure verbosity and colour. Colour is on only for a terminal stderr and
/// when `NO_COLOR` is unset or empty.
pub fn init(quiet: bool, verbose: bool) {
    QUIET.store(quiet, Ordering::Relaxed);
    VERBOSE.store(verbose, Ordering::Relaxed);
    let no_color = std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty());
    COLOR.store(
        std::io::stderr().is_terminal() && !no_color,
        Ordering::Relaxed,
    );
}

fn emit(tag: &str, code: &str, msg: &dyn Display) {
    let ts = chrono::Local::now().format("%H:%M:%S");
    let line = if COLOR.load(Ordering::Relaxed) {
        format!("\x1b[2m{ts}\x1b[0m \x1b[{code}m{tag:<4}\x1b[0m {msg}\n")
    } else {
        format!("{ts} {tag:<4} {msg}\n")
    };
    let mut err = std::io::stderr().lock();
    // A closed stderr must never take the program down.
    let _ = err.write_all(line.as_bytes());
    let _ = err.flush();
}

/// Informational message (suppressed by `--quiet`).
pub fn info(msg: impl Display) {
    if !QUIET.load(Ordering::Relaxed) {
        emit("INFO", "36", &msg);
    }
}

/// Success message (suppressed by `--quiet`).
pub fn ok(msg: impl Display) {
    if !QUIET.load(Ordering::Relaxed) {
        emit("OK", "32", &msg);
    }
}

/// Warning (always shown).
pub fn warn(msg: impl Display) {
    emit("WARN", "33", &msg);
}

/// Error (always shown).
pub fn error(msg: impl Display) {
    emit("ERR", "31", &msg);
}

/// Debug message (only with `--verbose`).
pub fn debug(msg: impl Display) {
    if VERBOSE.load(Ordering::Relaxed) {
        emit("DBG", "90", &msg);
    }
}
