//! OpenSSH-style escape sequences, recognised only at the start of a line.

/// What the user asked for with an escape sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscapeAction {
    /// `~.` – disconnect and quit without reconnecting.
    Quit,
    /// `~?` – print the help text.
    Help,
}

/// Help text shown for `~?` (uses CRLF because the terminal is in raw mode).
pub const HELP: &[u8] = b"\r\nsshtether escape sequences:\r\n  ~.  disconnect and quit (no reconnect)\r\n  ~~  send a literal ~\r\n  ~?  this help\r\n";

/// Stateful filter sitting between the keyboard and the remote PTY.
#[derive(Debug)]
pub struct EscapeFilter {
    bol: bool,
    pending: bool,
}

impl Default for EscapeFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl EscapeFilter {
    /// A filter positioned at the beginning of a line.
    pub fn new() -> Self {
        Self {
            bol: true,
            pending: false,
        }
    }

    /// Process a chunk of keyboard input.
    ///
    /// Returns the bytes to forward to the server and, if an escape sequence
    /// completed, the requested action. On [`EscapeAction::Quit`] the returned
    /// bytes are only those preceding the escape.
    pub fn feed(&mut self, data: &[u8]) -> (Vec<u8>, Option<EscapeAction>) {
        let mut out = Vec::with_capacity(data.len());
        let mut action = None;
        for &b in data {
            if self.pending {
                self.pending = false;
                match b {
                    b'.' => return (out, Some(EscapeAction::Quit)),
                    b'?' => {
                        action = Some(EscapeAction::Help);
                        self.bol = true;
                        continue;
                    }
                    b'~' => {
                        out.push(b'~');
                        self.bol = false;
                        continue;
                    }
                    // Not an escape: flush the held tilde, then handle `b` normally.
                    _ => out.push(b'~'),
                }
            }
            if self.bol && b == b'~' {
                self.pending = true;
                self.bol = false;
                continue;
            }
            out.push(b);
            self.bol = b == b'\r' || b == b'\n';
        }
        (out, action)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed_all(f: &mut EscapeFilter, parts: &[&[u8]]) -> (Vec<u8>, Option<EscapeAction>) {
        let mut out = Vec::new();
        let mut act = None;
        for p in parts {
            let (o, a) = f.feed(p);
            out.extend(o);
            act = act.or(a);
        }
        (out, act)
    }

    #[test]
    fn plain_text_passes_through() {
        let mut f = EscapeFilter::new();
        assert_eq!(f.feed(b"hello\r"), (b"hello\r".to_vec(), None));
    }

    #[test]
    fn tilde_dot_at_line_start_quits() {
        let mut f = EscapeFilter::new();
        assert_eq!(f.feed(b"~."), (vec![], Some(EscapeAction::Quit)));
    }

    #[test]
    fn works_when_split_across_reads() {
        let mut f = EscapeFilter::new();
        let (out, act) = feed_all(&mut f, &[b"ls\r", b"~", b"."]);
        assert_eq!(out, b"ls\r");
        assert_eq!(act, Some(EscapeAction::Quit));
    }

    #[test]
    fn tilde_mid_line_is_literal() {
        let mut f = EscapeFilter::new();
        assert_eq!(f.feed(b"a~."), (b"a~.".to_vec(), None));
    }

    #[test]
    fn double_tilde_sends_one() {
        let mut f = EscapeFilter::new();
        assert_eq!(f.feed(b"~~x"), (b"~x".to_vec(), None));
    }

    #[test]
    fn tilde_followed_by_other_flushes_tilde() {
        let mut f = EscapeFilter::new();
        assert_eq!(f.feed(b"~a"), (b"~a".to_vec(), None));
    }

    #[test]
    fn question_mark_requests_help_and_stays_at_line_start() {
        let mut f = EscapeFilter::new();
        let (out, act) = f.feed(b"~?");
        assert!(out.is_empty());
        assert_eq!(act, Some(EscapeAction::Help));
        assert_eq!(f.feed(b"~."), (vec![], Some(EscapeAction::Quit)));
    }

    #[test]
    fn newline_rearms_the_escape() {
        let mut f = EscapeFilter::new();
        let _ = f.feed(b"x");
        assert_eq!(f.feed(b"\n~."), (b"\n".to_vec(), Some(EscapeAction::Quit)));
    }
}
