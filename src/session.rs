//! One connected run of the remote command: PTY allocation, bidirectional I/O
//! pumping, window-resize forwarding and classification of how the run ended.

use crate::connection::Connection;
use crate::escape::{EscapeAction, EscapeFilter, HELP};
use crate::terminal::{self, InputPump, RawGuard};
use crate::{EXIT_ERROR, EXIT_GIVE_UP};
use russh::{ChannelMsg, Sig};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{interval, sleep, timeout, MissedTickBehavior};

/// How a session ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The remote command finished; `exit_code` is meaningful.
    Exited,
    /// The link died mid-run: reconnect.
    Dropped,
    /// The user typed `~.`.
    Quit,
    /// A local, non-retryable problem.
    Error,
}

/// Result of [`run_session`].
#[derive(Debug, Clone)]
pub struct SessionResult {
    /// What happened.
    pub outcome: Outcome,
    /// Remote exit status (only meaningful for [`Outcome::Exited`]).
    pub exit_code: i32,
    /// Human-readable detail (may be empty).
    pub reason: String,
}

impl SessionResult {
    fn new(outcome: Outcome, exit_code: i32, reason: impl Into<String>) -> Self {
        Self {
            outcome,
            exit_code,
            reason: reason.into(),
        }
    }
    fn dropped(reason: impl Into<String>) -> Self {
        Self::new(Outcome::Dropped, 0, reason)
    }
    fn error(reason: impl Into<String>) -> Self {
        Self::new(Outcome::Error, EXIT_ERROR, reason)
    }
}

/// Per-session options.
#[derive(Debug, Clone)]
pub struct SessionOpts {
    /// `TERM` for the remote PTY.
    pub term: String,
    /// `LANG`/`LC_ALL` for the remote; empty disables the export.
    pub lang: String,
    /// When set, the command is wrapped so a reconnect first stops the lingering
    /// process of the previous connection of this run (no duplicate processes).
    pub run_id: Option<String>,
}

enum End {
    RemoteClosed(Option<i32>),
    Quit,
    Dropped(String),
    LocalIo(String),
    Refused,
}

/// Run `command` on an authenticated connection until it ends one way or another.
pub async fn run_session(
    conn: &Connection,
    command: &str,
    opts: &SessionOpts,
    input: &mut InputPump,
) -> SessionResult {
    let link_or_error = |what: &str, e: String| {
        if conn.is_closed() {
            SessionResult::dropped(format!("{what}: {}", conn.disconnect_reason()))
        } else {
            SessionResult::error(format!("{what}: {e}"))
        }
    };

    let mut channel = match timeout(
        Duration::from_secs(15),
        conn.handle().channel_open_session(),
    )
    .await
    {
        Err(_) => return SessionResult::dropped("timed out opening a session channel"),
        Ok(Err(e)) => return link_or_error("open session", e.to_string()),
        Ok(Ok(c)) => c,
    };

    let (cols, rows) = terminal::size();
    if let Err(e) = channel
        .request_pty(
            false,
            &opts.term,
            u32::from(cols),
            u32::from(rows),
            0,
            0,
            &[],
        )
        .await
    {
        return link_or_error("request pty", e.to_string());
    }
    let command = match &opts.run_id {
        Some(id) => crate::command::single_instance_command(command, id),
        None => command.to_owned(),
    };
    let full = if opts.lang.is_empty() {
        command
    } else {
        let q = shell_words::quote(&opts.lang);
        format!("export LANG={q} LC_ALL={q}; {command}")
    };
    if let Err(e) = channel.exec(true, full).await {
        return link_or_error("exec", e.to_string());
    }

    let guard = match RawGuard::enter() {
        Ok(g) => g,
        Err(e) => {
            let _ = timeout(Duration::from_secs(1), channel.close()).await;
            return SessionResult::error(format!("cannot enter raw terminal mode: {e}"));
        }
    };
    input.begin();
    let end = pump(&mut channel, input).await;
    input.end();
    drop(guard); // restore the terminal before anything is logged
    let _ = timeout(Duration::from_secs(1), channel.close()).await;

    match end {
        End::Quit => SessionResult::new(Outcome::Quit, 0, ""),
        End::LocalIo(r) => SessionResult::error(r),
        End::Refused => SessionResult::error("the server refused to run the command"),
        End::Dropped(r) => SessionResult::dropped(r),
        End::RemoteClosed(Some(code)) => SessionResult::new(Outcome::Exited, code, ""),
        End::RemoteClosed(None) => {
            // The channel closed without an exit status: either the whole link died
            // (the transport may lag the channel by a few ms) or the server is odd.
            for _ in 0..20 {
                if conn.is_closed() {
                    return SessionResult::dropped(conn.disconnect_reason());
                }
                sleep(Duration::from_millis(50)).await;
            }
            SessionResult::new(
                Outcome::Exited,
                EXIT_GIVE_UP,
                "remote closed without exit status",
            )
        }
    }
}

async fn pump(channel: &mut russh::Channel<russh::client::Msg>, input: &mut InputPump) -> End {
    // Keystrokes go through a dedicated task so a congested link can never stall
    // the output side of the loop.
    let writer = channel.make_writer();
    let (wtx, mut wrx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (etx, mut erx) = oneshot::channel::<String>();
    let wtask = tokio::spawn(async move {
        let mut w = Box::pin(writer);
        while let Some(buf) = wrx.recv().await {
            if let Err(e) = w.write_all(&buf).await {
                let _ = etx.send(e.to_string());
                return;
            }
            let _ = w.flush().await;
        }
    });
    let mut writer_alive = true;

    let mut stdout = tokio::io::stdout();
    let mut esc = EscapeFilter::new();
    let mut exit_code: Option<i32> = None;
    let mut last_size = terminal::size();
    let mut closed_ticks = 0u32;
    let mut tick = interval(Duration::from_millis(100));
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);

    let mut stdin_eof = input.at_eof();
    if stdin_eof {
        let _ = wtx.send(vec![0x04]);
    }

    let end = loop {
        tokio::select! {
            msg = channel.wait() => match msg {
                Some(ChannelMsg::Data { data }) | Some(ChannelMsg::ExtendedData { data, .. }) => {
                    if let Err(e) = write_out(&mut stdout, &data).await {
                        break End::LocalIo(format!("stdout: {e}"));
                    }
                }
                Some(ChannelMsg::ExitStatus { exit_status }) => {
                    exit_code = Some(i32::try_from(exit_status).unwrap_or(EXIT_GIVE_UP));
                }
                Some(ChannelMsg::ExitSignal { signal_name, .. }) => {
                    exit_code = Some(signal_exit_code(&signal_name));
                }
                Some(ChannelMsg::Failure) => break End::Refused,
                Some(ChannelMsg::Close) | None => break End::RemoteClosed(exit_code),
                Some(_) => {}
            },

            chunk = input.recv(), if !stdin_eof => match chunk {
                Some(data) if !data.is_empty() => {
                    let (payload, action) = esc.feed(&data);
                    if action == Some(EscapeAction::Quit) {
                        break End::Quit;
                    }
                    if action == Some(EscapeAction::Help) {
                        let _ = write_out(&mut stdout, HELP).await;
                    }
                    if !payload.is_empty() {
                        let _ = wtx.send(payload);
                    }
                }
                // End of stdin: forward EOF (Ctrl-D) to the remote PTY once.
                _ => {
                    stdin_eof = true;
                    let _ = wtx.send(vec![0x04]);
                }
            },

            res = &mut erx, if writer_alive => {
                writer_alive = false;
                if let Ok(why) = res {
                    break End::Dropped(format!("send failed: {why}"));
                }
            }

            _ = tick.tick() => {
                let size = terminal::size();
                if size != last_size {
                    last_size = size;
                    let _ = channel.window_change(u32::from(size.0), u32::from(size.1), 0, 0).await;
                }
                // Normally channel.wait() reports the end; this is only a backstop
                // for a transport that is gone but never closed the channel.
                if channel_transport_gone(&wtx, &wtask) {
                    closed_ticks += 1;
                    if closed_ticks > 20 {
                        break End::Dropped("connection lost".into());
                    }
                } else {
                    closed_ticks = 0;
                }
            }
        }
    };

    wtask.abort();
    end
}

fn channel_transport_gone(
    wtx: &mpsc::UnboundedSender<Vec<u8>>,
    wtask: &tokio::task::JoinHandle<()>,
) -> bool {
    wtx.is_closed() || wtask.is_finished()
}

async fn write_out(out: &mut tokio::io::Stdout, data: &[u8]) -> std::io::Result<()> {
    out.write_all(data).await?;
    out.flush().await
}

/// Shell-style exit code for a remote process killed by a signal.
fn signal_exit_code(sig: &Sig) -> i32 {
    128 + match sig {
        Sig::HUP => 1,
        Sig::INT => 2,
        Sig::QUIT => 3,
        Sig::ILL => 4,
        Sig::ABRT => 6,
        Sig::FPE => 8,
        Sig::KILL => 9,
        Sig::USR1 => 10,
        Sig::SEGV => 11,
        Sig::PIPE => 13,
        Sig::ALRM => 14,
        Sig::TERM => 15,
        Sig::Custom(_) => 127, // unknown: 255
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_codes_follow_shell_convention() {
        assert_eq!(signal_exit_code(&Sig::KILL), 137);
        assert_eq!(signal_exit_code(&Sig::TERM), 143);
        assert_eq!(signal_exit_code(&Sig::INT), 130);
        assert_eq!(signal_exit_code(&Sig::Custom("X".into())), 255);
    }
}
