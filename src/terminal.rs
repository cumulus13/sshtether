//! Local terminal handling: raw mode, non-blocking keyboard input, size and
//! cleanup after a remote application died while holding the terminal.

use std::io::{IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};

/// Undo alt-screen / mouse / bracketed-paste modes left behind by a dead
/// remote application, and show the cursor again.
const TERM_RESET: &[u8] = b"\x1b[?1049l\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\
\x1b[?2004l\x1b[?1l\x1b>\x1b[?25h\x1b[0m";

/// Reset the local terminal state (no-op when stdout is not a terminal).
pub fn reset_local_terminal() {
    let out = std::io::stdout();
    if out.is_terminal() {
        let mut out = out.lock();
        let _ = out.write_all(TERM_RESET);
        let _ = out.write_all(b"\r\n");
        let _ = out.flush();
    }
}

/// Current terminal size as `(columns, rows)`, falling back to 80x24.
pub fn size() -> (u16, u16) {
    match crossterm::terminal::size() {
        Ok((c, r)) if c > 0 && r > 0 => (c, r),
        _ => (80, 24),
    }
}

/// Make native Windows consoles understand ANSI/VT sequences and UTF-8.
/// Does nothing on other platforms.
pub fn enable_windows_vt() {
    #[cfg(windows)]
    {
        use windows_sys::Win32::System::Console::{
            GetConsoleMode, GetStdHandle, SetConsoleMode, SetConsoleOutputCP,
            ENABLE_VIRTUAL_TERMINAL_PROCESSING, STD_ERROR_HANDLE, STD_OUTPUT_HANDLE,
        };
        // SAFETY: plain Win32 calls with valid constants and a stack out-pointer.
        unsafe {
            SetConsoleOutputCP(65001);
            for std in [STD_OUTPUT_HANDLE, STD_ERROR_HANDLE] {
                let handle = GetStdHandle(std);
                let mut mode = 0u32;
                if GetConsoleMode(handle, &mut mode) != 0 {
                    SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
                }
            }
        }
    }
}

/// RAII guard: puts a terminal stdin into raw mode and restores it on drop
/// (also when the surrounding future is cancelled or a panic unwinds).
#[derive(Debug)]
pub struct RawGuard {
    active: bool,
}

impl RawGuard {
    /// Enter raw mode if stdin is a terminal; otherwise a no-op guard.
    pub fn enter() -> std::io::Result<Self> {
        if std::io::stdin().is_terminal() {
            crossterm::terminal::enable_raw_mode()?;
            Ok(Self { active: true })
        } else {
            Ok(Self { active: false })
        }
    }
}

impl Drop for RawGuard {
    fn drop(&mut self) {
        if self.active {
            let _ = crossterm::terminal::disable_raw_mode();
        }
    }
}

/// Restore the terminal from a panic hook (best effort).
pub fn install_panic_hook() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = crossterm::terminal::disable_raw_mode();
        default(info);
    }));
}

/// Keyboard input as an async stream of byte chunks.
///
/// A single background thread reads stdin for the whole process lifetime. It
/// only touches the terminal while a session is active, so passphrase prompts
/// and the cooked-mode backoff period are never disturbed. An empty chunk
/// signals end-of-file.
#[derive(Debug)]
pub struct InputPump {
    rx: UnboundedReceiver<Vec<u8>>,
    active: Arc<AtomicBool>,
    eof: Arc<AtomicBool>,
    is_tty: bool,
}

impl InputPump {
    /// Start the reader thread.
    pub fn start() -> Self {
        let (tx, rx) = unbounded_channel();
        let active = Arc::new(AtomicBool::new(false));
        let eof = Arc::new(AtomicBool::new(false));
        let is_tty = std::io::stdin().is_terminal();
        let (a, e) = (active.clone(), eof.clone());
        std::thread::Builder::new()
            .name("sshtether-stdin".into())
            .spawn(move || reader::run(is_tty, a, e, tx))
            .expect("spawn stdin reader thread");
        Self {
            rx,
            active,
            eof,
            is_tty,
        }
    }

    /// Begin a session: discard stale keystrokes and start delivering input.
    pub fn begin(&mut self) {
        if self.is_tty {
            while self.rx.try_recv().is_ok() {}
        }
        self.active.store(true, Ordering::SeqCst);
    }

    /// End a session: stop reading the terminal.
    pub fn end(&self) {
        self.active.store(false, Ordering::SeqCst);
    }

    /// `true` once stdin has reached end-of-file.
    pub fn at_eof(&self) -> bool {
        self.eof.load(Ordering::SeqCst)
    }

    /// Next chunk of input; `None` if the reader thread is gone.
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.rx.recv().await
    }
}

#[cfg(unix)]
mod reader {
    use super::*;
    use std::time::Duration;
    use tokio::sync::mpsc::UnboundedSender;

    pub fn run(
        _is_tty: bool,
        active: Arc<AtomicBool>,
        eof: Arc<AtomicBool>,
        tx: UnboundedSender<Vec<u8>>,
    ) {
        let mut buf = [0u8; 4096];
        loop {
            if tx.is_closed() {
                return;
            }
            if !active.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(20));
                continue;
            }
            let mut pfd = libc::pollfd {
                fd: 0,
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: `pfd` is a valid, initialised pollfd and we pass nfds = 1.
            let r = unsafe { libc::poll(&mut pfd, 1, 100) };
            if r < 0 {
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                break;
            }
            if r == 0 {
                continue;
            }
            // SAFETY: `buf` is a valid writable buffer of `buf.len()` bytes.
            let n = unsafe { libc::read(0, buf.as_mut_ptr().cast(), buf.len()) };
            match n {
                n if n > 0 => {
                    if tx.send(buf[..n as usize].to_vec()).is_err() {
                        return;
                    }
                }
                0 => break,
                _ => {
                    use std::io::ErrorKind::{Interrupted, WouldBlock};
                    if matches!(
                        std::io::Error::last_os_error().kind(),
                        Interrupted | WouldBlock
                    ) {
                        continue;
                    }
                    break;
                }
            }
        }
        eof.store(true, Ordering::SeqCst);
        let _ = tx.send(Vec::new());
    }
}

#[cfg(windows)]
mod reader {
    use super::*;
    use crossterm::event::{self, Event, KeyEventKind};
    use std::io::Read;
    use std::time::Duration;
    use tokio::sync::mpsc::UnboundedSender;

    pub fn run(
        is_tty: bool,
        active: Arc<AtomicBool>,
        eof: Arc<AtomicBool>,
        tx: UnboundedSender<Vec<u8>>,
    ) {
        if is_tty {
            loop {
                if tx.is_closed() {
                    return;
                }
                if !active.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(20));
                    continue;
                }
                match event::poll(Duration::from_millis(100)) {
                    Ok(false) => continue,
                    Ok(true) => match event::read() {
                        Ok(Event::Key(k)) if k.kind != KeyEventKind::Release => {
                            let bytes = crate::terminal::key_to_bytes(&k);
                            if !bytes.is_empty() && tx.send(bytes).is_err() {
                                return;
                            }
                        }
                        Ok(_) => {}
                        Err(_) => break,
                    },
                    Err(_) => break,
                }
            }
        } else {
            let mut stdin = std::io::stdin().lock();
            let mut buf = [0u8; 4096];
            loop {
                match stdin.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if tx.send(buf[..n].to_vec()).is_err() {
                            return;
                        }
                    }
                }
            }
        }
        eof.store(true, Ordering::SeqCst);
        let _ = tx.send(Vec::new());
    }
}

/// Translate a key event into the bytes a VT terminal would send.
///
/// Used on Windows, where the console delivers key records rather than bytes.
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
pub fn key_to_bytes(key: &crossterm::event::KeyEvent) -> Vec<u8> {
    use crossterm::event::{KeyCode, KeyModifiers};

    let m = key.modifiers;
    let ctrl = m.contains(KeyModifiers::CONTROL);
    let alt = m.contains(KeyModifiers::ALT);
    let shift = m.contains(KeyModifiers::SHIFT);
    // xterm modifier parameter: 1 + shift(1) + alt(2) + ctrl(4)
    let param = 1 + u8::from(shift) + 2 * u8::from(alt) + 4 * u8::from(ctrl);

    let csi = |final_byte: char| -> Vec<u8> {
        if param > 1 {
            format!("\x1b[1;{param}{final_byte}").into_bytes()
        } else {
            format!("\x1b[{final_byte}").into_bytes()
        }
    };
    let tilde = |n: u8| -> Vec<u8> {
        if param > 1 {
            format!("\x1b[{n};{param}~").into_bytes()
        } else {
            format!("\x1b[{n}~").into_bytes()
        }
    };

    let mut out = match key.code {
        KeyCode::Char(c) => {
            if ctrl {
                match c {
                    'a'..='z' | 'A'..='Z' => vec![(c.to_ascii_lowercase() as u8) & 0x1f],
                    ' ' | '@' | '2' => vec![0],
                    '[' | '3' => vec![0x1b],
                    '\\' | '4' => vec![0x1c],
                    ']' | '5' => vec![0x1d],
                    '^' | '6' => vec![0x1e],
                    '_' | '7' | '/' => vec![0x1f],
                    '8' => vec![0x7f],
                    other => other.to_string().into_bytes(),
                }
            } else {
                c.to_string().into_bytes()
            }
        }
        KeyCode::Enter => vec![b'\r'],
        KeyCode::Tab => vec![b'\t'],
        KeyCode::BackTab => b"\x1b[Z".to_vec(),
        KeyCode::Backspace => vec![0x7f],
        KeyCode::Esc => vec![0x1b],
        KeyCode::Up => csi('A'),
        KeyCode::Down => csi('B'),
        KeyCode::Right => csi('C'),
        KeyCode::Left => csi('D'),
        KeyCode::Home => csi('H'),
        KeyCode::End => csi('F'),
        KeyCode::Insert => tilde(2),
        KeyCode::Delete => tilde(3),
        KeyCode::PageUp => tilde(5),
        KeyCode::PageDown => tilde(6),
        KeyCode::F(n @ 1..=4) => {
            let f = (b'P' + (n - 1)) as char;
            if param > 1 {
                format!("\x1b[1;{param}{f}").into_bytes()
            } else {
                format!("\x1bO{f}").into_bytes()
            }
        }
        KeyCode::F(n @ 5..=12) => {
            const CODES: [u8; 8] = [15, 17, 18, 19, 20, 21, 23, 24];
            tilde(CODES[usize::from(n - 5)])
        }
        _ => return Vec::new(),
    };

    // Alt+<printable/control> is ESC-prefixed (sequences already encode Alt).
    if alt
        && matches!(
            key.code,
            KeyCode::Char(_) | KeyCode::Enter | KeyCode::Backspace | KeyCode::Tab
        )
    {
        out.insert(0, 0x1b);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    fn k(code: KeyCode, m: KeyModifiers) -> Vec<u8> {
        key_to_bytes(&KeyEvent::new(code, m))
    }

    #[test]
    fn printable_and_control_keys() {
        assert_eq!(k(KeyCode::Char('a'), KeyModifiers::NONE), b"a");
        assert_eq!(k(KeyCode::Char('é'), KeyModifiers::NONE), "é".as_bytes());
        assert_eq!(k(KeyCode::Char('c'), KeyModifiers::CONTROL), [3]);
        assert_eq!(k(KeyCode::Char('d'), KeyModifiers::CONTROL), [4]);
        assert_eq!(k(KeyCode::Char('x'), KeyModifiers::ALT), b"\x1bx");
        assert_eq!(k(KeyCode::Enter, KeyModifiers::NONE), b"\r");
        assert_eq!(k(KeyCode::Backspace, KeyModifiers::NONE), [0x7f]);
    }

    #[test]
    fn navigation_keys() {
        assert_eq!(k(KeyCode::Up, KeyModifiers::NONE), b"\x1b[A");
        assert_eq!(k(KeyCode::Left, KeyModifiers::CONTROL), b"\x1b[1;5D");
        assert_eq!(k(KeyCode::Delete, KeyModifiers::NONE), b"\x1b[3~");
        assert_eq!(k(KeyCode::PageDown, KeyModifiers::NONE), b"\x1b[6~");
        assert_eq!(k(KeyCode::BackTab, KeyModifiers::SHIFT), b"\x1b[Z");
    }

    #[test]
    fn function_keys() {
        assert_eq!(k(KeyCode::F(1), KeyModifiers::NONE), b"\x1bOP");
        assert_eq!(k(KeyCode::F(5), KeyModifiers::NONE), b"\x1b[15~");
        assert_eq!(k(KeyCode::F(12), KeyModifiers::NONE), b"\x1b[24~");
        assert_eq!(k(KeyCode::F(5), KeyModifiers::SHIFT), b"\x1b[15;2~");
    }

    #[test]
    fn unsupported_keys_yield_nothing() {
        assert!(k(KeyCode::CapsLock, KeyModifiers::NONE).is_empty());
    }
}
