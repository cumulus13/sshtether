//! Building the command line that is executed on the server.

use crate::cli::Persist;
use sha1::{Digest, Sha1};
use std::path::Path;

/// Programs that are already session managers: re-running them after a
/// reconnect re-attaches instead of restarting work.
const RESUMABLE: [&str; 4] = ["tmux", "screen", "byobu", "zellij"];

/// A remote command plus whether re-running it after a reconnect is safe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteCommand {
    /// The exact string passed to the remote shell.
    pub command: String,
    /// `true` when a re-run resumes state (tmux/screen) rather than restarting.
    pub resumable: bool,
}

/// Turn the user's argv into a [`RemoteCommand`].
///
/// * a single argument is used verbatim (so `"ls | wc -l"` works as a shell line);
/// * several arguments are shell-quoted and joined;
/// * with `--persist tmux|screen` a non-resumable command is wrapped in a named
///   session so it keeps running on the server when the link drops.
pub fn build_remote_command(
    argv: &[String],
    persist: Persist,
    session_name: Option<&str>,
) -> RemoteCommand {
    let mut command = match argv {
        [single] => single.clone(),
        _ => shell_words::join(argv),
    };

    let first = shell_words::split(&command)
        .ok()
        .and_then(|w| w.into_iter().next())
        .map(|w| {
            Path::new(&w)
                .file_name()
                .map(|f| f.to_string_lossy().into_owned())
                .unwrap_or(w)
        })
        .unwrap_or_default();
    let mut resumable = RESUMABLE.contains(&first.as_str());

    if persist != Persist::None && !resumable {
        let name = match session_name {
            Some(n) => n.to_owned(),
            None => format!("sshtether-{}", short_hash(&command)),
        };
        let qn = shell_words::quote(&name);
        let qc = shell_words::quote(&command);
        command = match persist {
            Persist::Tmux => format!("tmux -u new-session -A -s {qn} {qc}"),
            Persist::Screen => format!("screen -xRR -S {qn} sh -c {qc}"),
            Persist::None => unreachable!("guarded above"),
        };
        resumable = true;
    }
    RemoteCommand { command, resumable }
}

/// POSIX `sh` script that guarantees at most one live instance per run.
///
/// `$0` is the run tag, `$1` the user's command. Before starting, it looks for
/// a pidfile left by an earlier session *of the same run* (the previous
/// connection, which the server may not have noticed is dead yet) and, only if
/// that pid is still alive **and** its command line contains the tag (so a
/// recycled pid is never touched), terminates its whole process group. It then
/// records its own pid and runs the command, removing the pidfile on exit.
const TAKEOVER_SCRIPT: &str = r#"tag="$0"
d="${TMPDIR:-/tmp}/sshtether-$(id -u)"
mkdir -p "$d" 2>/dev/null && chmod 700 "$d" 2>/dev/null
f="$d/$tag.pid"
if [ -r "$f" ]; then
  old=$(cat "$f" 2>/dev/null)
  case "$old" in
    ''|*[!0-9]*) ;;
    *)
      if [ "$old" != "$$" ] && ps -p "$old" -o args= 2>/dev/null | grep -qF -- "$tag"; then
        pg=$(ps -p "$old" -o pgid= 2>/dev/null | tr -d ' ')
        mine=$(ps -p "$$" -o pgid= 2>/dev/null | tr -d ' ')
        if [ -n "$pg" ] && [ "$pg" != "$mine" ]; then kill -s TERM -- "-$pg" 2>/dev/null; else kill -s TERM "$old" 2>/dev/null; fi
        i=0
        while [ "$i" -lt 30 ] && kill -0 "$old" 2>/dev/null; do sleep 0.1 2>/dev/null || sleep 1; i=$((i+1)); done
        if kill -0 "$old" 2>/dev/null; then
          if [ -n "$pg" ] && [ "$pg" != "$mine" ]; then kill -s KILL -- "-$pg" 2>/dev/null; else kill -s KILL "$old" 2>/dev/null; fi
        fi
      fi
      ;;
  esac
fi
echo "$$" > "$f"
trap 'rm -f "$f"' EXIT
eval "$1""#;

/// Wrap `command` so that a reconnect first stops the lingering process of the
/// previous connection of the same run instead of piling up a duplicate.
///
/// `run_id` must be stable for the whole sshtether run and unique per run, so
/// concurrent runs (or other users' work) are never affected.
pub fn single_instance_command(command: &str, run_id: &str) -> String {
    let tag = format!("sshtether-{run_id}");
    format!(
        "sh -c {} {} {}",
        shell_words::quote(TAKEOVER_SCRIPT),
        shell_words::quote(&tag),
        shell_words::quote(command)
    )
}

/// A fresh random run identifier (8 hex chars).
pub fn new_run_id() -> String {
    use rand::Rng;
    format!("{:08x}", rand::rng().random::<u32>())
}

fn short_hash(s: &str) -> String {
    let digest = Sha1::digest(s.as_bytes());
    digest.iter().take(4).map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn single_argument_is_verbatim() {
        let c = build_remote_command(&v(&["ls -la | wc -l"]), Persist::None, None);
        assert_eq!(c.command, "ls -la | wc -l");
        assert!(!c.resumable);
    }

    #[test]
    fn multiple_arguments_are_quoted() {
        let c = build_remote_command(&v(&["echo", "a b", "it's"]), Persist::None, None);
        assert_eq!(c.command, r"echo 'a b' 'it'\''s'");
    }

    #[test]
    fn tmux_is_resumable() {
        let c = build_remote_command(&v(&["tmux", "attach", "-t", "main"]), Persist::None, None);
        assert!(c.resumable);
        let c = build_remote_command(&v(&["/usr/bin/tmux"]), Persist::Tmux, None);
        assert!(c.resumable);
        assert_eq!(c.command, "/usr/bin/tmux", "must not be double-wrapped");
    }

    #[test]
    fn persist_tmux_wraps_and_is_deterministic() {
        let a = build_remote_command(&v(&["htop"]), Persist::Tmux, None);
        let b = build_remote_command(&v(&["htop"]), Persist::Tmux, None);
        assert_eq!(a, b);
        assert!(a.resumable);
        assert!(a
            .command
            .starts_with("tmux -u new-session -A -s sshtether-"));
        assert!(a.command.ends_with(" htop"));
    }

    #[test]
    fn persist_screen_with_custom_name() {
        let c = build_remote_command(&v(&["bash", "-l"]), Persist::Screen, Some("my sess"));
        assert_eq!(c.command, "screen -xRR -S 'my sess' sh -c 'bash -l'");
    }

    #[cfg(unix)]
    mod takeover {
        use super::super::*;
        use std::os::unix::process::CommandExt;
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};

        fn alive(pid: u32) -> bool {
            Command::new("kill")
                .args(["-0", &pid.to_string()])
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|s| s.success())
        }

        fn spawn(tmp: &std::path::Path, cmd: &str, run: &str) -> std::process::Child {
            let mut c = Command::new("sh");
            c.arg("-c")
                .arg(single_instance_command(cmd, run))
                .env("TMPDIR", tmp)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .process_group(0); // own session-like group, as sshd would give each connection
            c.spawn().unwrap()
        }

        fn wait_for(mut pred: impl FnMut() -> bool) -> bool {
            let t = Instant::now();
            while t.elapsed() < Duration::from_secs(10) {
                if pred() {
                    return true;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            false
        }

        #[test]
        fn second_start_stops_the_first_and_leaves_no_duplicates() {
            let dir = tempfile::tempdir().unwrap();
            let marker = "sleep 31337";
            let mut first = spawn(dir.path(), marker, "t1");
            let first_pid = first.id();
            let pidfile = dir
                .path()
                .join(format!("sshtether-{}", unsafe_uid()))
                .join("sshtether-t1.pid");
            assert!(wait_for(|| pidfile.exists()), "pidfile not written");

            // Simulates the reconnect: same run id, previous session still alive.
            let mut second = spawn(dir.path(), marker, "t1");
            assert!(
                wait_for(|| first.try_wait().unwrap().is_some()),
                "old instance still running"
            );
            assert!(!alive(first_pid));

            assert!(
                wait_for(|| count_procs(marker) == 1),
                "new instance never became the only one"
            );
            std::thread::sleep(Duration::from_millis(500));
            let n = count_procs(marker);
            assert_eq!(n, 1, "exactly one instance must remain, found {n}");
            second.kill().ok();
            let _ = second.wait();
            // Clean up any leftover child of the killed wrapper.
            let _ = Command::new("pkill").args(["-f", marker]).status();
        }

        #[test]
        fn different_runs_do_not_touch_each_other() {
            let dir = tempfile::tempdir().unwrap();
            let marker = "sleep 31338";
            let mut a = spawn(dir.path(), marker, "runA");
            let pidfile = dir
                .path()
                .join(format!("sshtether-{}", unsafe_uid()))
                .join("sshtether-runA.pid");
            assert!(wait_for(|| pidfile.exists()));
            let mut b = spawn(dir.path(), marker, "runB");
            std::thread::sleep(Duration::from_millis(800));
            assert!(a.try_wait().unwrap().is_none(), "run A must survive run B");
            assert!(b.try_wait().unwrap().is_none());
            let _ = Command::new("pkill").args(["-f", marker]).status();
            let _ = a.wait();
            let _ = b.wait();
        }

        #[test]
        fn stale_pidfile_with_recycled_pid_is_ignored_and_exit_status_preserved() {
            let dir = tempfile::tempdir().unwrap();
            // Our own pid is alive but its command line does not carry the tag.
            let d = dir.path().join(format!("sshtether-{}", unsafe_uid()));
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("sshtether-t3.pid"), std::process::id().to_string()).unwrap();
            let status = spawn(dir.path(), "exit 5", "t3").wait().unwrap();
            assert_eq!(
                status.code(),
                Some(5),
                "exit status must pass through the wrapper"
            );
            assert!(
                !d.join("sshtether-t3.pid").exists(),
                "pidfile removed on exit"
            );
        }

        fn unsafe_uid() -> String {
            let out = Command::new("id").arg("-u").output().unwrap();
            String::from_utf8_lossy(&out.stdout).trim().to_owned()
        }

        fn count_procs(marker: &str) -> usize {
            // Portable (Linux + macOS): list every command line and count exact matches,
            // so the `sh -c` wrappers whose argv merely mention the text are not counted.
            let out = Command::new("ps")
                .args(["-A", "-o", "args="])
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .filter(|l| l.trim() == marker)
                .count()
        }
    }
}
