// File: sshtether/src/main.rs
// Author: Hadi Cahyadi <cumulus13@gmail.com>
// Date: 2026-11-18 14:35:08 SE Asia Standard Time
// Description:
// License: MIT

use clap::{CommandFactory, Parser};
use clap_version_flag::colorful_version;
use sshtether::cli::Cli;
use sshtether::command::build_remote_command;
use sshtether::config::load_servers;
use sshtether::connection::ConnectOpts;
use sshtether::session::SessionOpts;
use sshtether::supervisor::{RetryOpts, Supervisor};
use sshtether::terminal::{self, InputPump};
use sshtether::{ui, EXIT_ERROR, EXIT_INTERRUPTED};
use std::process::ExitCode;
use std::time::Duration;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 2 && (args[1] == "-V" || args[1] == "--version") {
        let version = colorful_version!();
        version.print_and_exit();
    }
    if std::env::args_os().len() == 1 {
        let _ = Cli::command().print_help();
        return ExitCode::SUCCESS;
    }
    let cli = Cli::parse();
    ui::init(cli.quiet, cli.verbose);

    if cli.command.is_empty() {
        ui::error(
            "No command specified. Example: sshtether htop   |   sshtether tmux attach -t main",
        );
        return ExitCode::from(EXIT_ERROR as u8);
    }

    terminal::enable_windows_vt();
    terminal::install_panic_hook();

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            ui::error(format!("cannot start async runtime: {e}"));
            return ExitCode::from(EXIT_ERROR as u8);
        }
    };
    let code = runtime.block_on(run(cli));
    // Do not wait for a blocked passphrase prompt or stdin read.
    runtime.shutdown_timeout(Duration::from_millis(200));
    ExitCode::from(u8::try_from(code).unwrap_or(255))
}

async fn run(cli: Cli) -> i32 {
    let servers = match load_servers(&cli) {
        Ok(s) => s,
        Err(e) => {
            ui::error(e);
            return EXIT_ERROR;
        }
    };
    let remote = build_remote_command(&cli.command, cli.persist, cli.session_name.as_deref());
    let supervisor = Supervisor::new(
        servers,
        remote,
        ConnectOpts::from_cli(&cli),
        SessionOpts {
            term: cli.term.clone(),
            lang: cli.lang.clone(),
            run_id: (!cli.allow_duplicates).then(sshtether::command::new_run_id),
        },
        RetryOpts::from_cli(&cli),
    );
    let mut input = InputPump::start();

    // Dropping the supervisor future on a signal unwinds through the raw-mode
    // guard, so the terminal is always restored.
    tokio::select! {
        code = supervisor.run(&mut input) => code,
        _ = tokio::signal::ctrl_c() => {
            terminal::reset_local_terminal();
            ui::info("Cancelled by user.");
            EXIT_INTERRUPTED
        }
        signum = terminate() => {
            terminal::reset_local_terminal();
            128 + signum
        }
    }
}

#[cfg(unix)]
async fn terminate() -> i32 {
    use tokio::signal::unix::{signal, SignalKind};
    let (Ok(mut term), Ok(mut hup)) = (
        signal(SignalKind::terminate()),
        signal(SignalKind::hangup()),
    ) else {
        return std::future::pending().await;
    };
    tokio::select! {
        _ = term.recv() => 15,
        _ = hup.recv() => 1,
    }
}

#[cfg(not(unix))]
async fn terminate() -> i32 {
    std::future::pending().await
}
