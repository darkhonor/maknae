use crate::{Password, VaultError, MAX_PASSWORD_BYTES};
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordFeed {
    More,
    Done,
    Interrupted,
    Eof,
    TooLong,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Escape {
    None,
    Started,
    Csi,
    Ss3,
}

pub struct PasswordLine {
    buf: Zeroizing<Vec<u8>>,
    escape: Escape,
    ended: Option<PasswordFeed>,
}

impl Default for PasswordLine {
    fn default() -> Self {
        Self::new()
    }
}

impl PasswordLine {
    pub fn new() -> Self {
        Self {
            buf: Zeroizing::new(Vec::with_capacity(MAX_PASSWORD_BYTES)),
            escape: Escape::None,
            ended: None,
        }
    }

    pub fn feed(&mut self, byte: u8) -> PasswordFeed {
        if let Some(end) = self.ended {
            return end;
        }
        let fed = self.step(byte);
        if fed != PasswordFeed::More {
            self.ended = Some(fed);
        }
        fed
    }

    fn step(&mut self, byte: u8) -> PasswordFeed {
        match byte {
            b'\r' | b'\n' => return PasswordFeed::Done,
            0x03 | 0x1c => return PasswordFeed::Interrupted,
            _ => {}
        }
        match self.escape {
            Escape::Started => {
                self.escape = match byte {
                    0x1b => Escape::Started,
                    b'[' => Escape::Csi,
                    b'O' => Escape::Ss3,
                    _ => Escape::None,
                };
                return PasswordFeed::More;
            }
            Escape::Csi => match byte {
                0x20..=0x3f => return PasswordFeed::More,
                0x40..=0x7e => {
                    self.escape = Escape::None;
                    return PasswordFeed::More;
                }
                _ => self.escape = Escape::None,
            },
            Escape::Ss3 => match byte {
                0x30..=0x3f => return PasswordFeed::More,
                0x40..=0x7e => {
                    self.escape = Escape::None;
                    return PasswordFeed::More;
                }
                _ => self.escape = Escape::None,
            },
            Escape::None => {}
        }
        match byte {
            0x04 if self.buf.is_empty() => PasswordFeed::Eof,
            0x1b => {
                self.escape = Escape::Started;
                PasswordFeed::More
            }
            0x7f | 0x08 => {
                self.erase_char();
                PasswordFeed::More
            }
            0x15 => {
                self.buf.zeroize();
                PasswordFeed::More
            }
            b'\t' => self.push(byte),
            0x00..=0x1f => PasswordFeed::More,
            _ => self.push(byte),
        }
    }

    fn push(&mut self, byte: u8) -> PasswordFeed {
        if self.buf.len() == MAX_PASSWORD_BYTES {
            return PasswordFeed::TooLong;
        }
        self.buf.push(byte);
        PasswordFeed::More
    }

    fn erase_char(&mut self) {
        let mut continuations = 0;
        while continuations < 3 && self.buf.last().is_some_and(|b| b & 0xc0 == 0x80) {
            self.buf.pop();
            continuations += 1;
        }
        if self
            .buf
            .last()
            .is_some_and(|&b| continuations == 0 || b >= 0xc0)
        {
            self.buf.pop();
        }
    }

    pub fn finish(mut self) -> Result<Password, VaultError> {
        if self.ended != Some(PasswordFeed::Done) {
            return Err(VaultError::InvalidSecret {
                what: "password",
                why: "line not completed",
            });
        }
        match String::from_utf8(std::mem::take(&mut *self.buf)) {
            Ok(s) => Password::new(Zeroizing::new(s)),
            Err(e) => {
                let _wiped = Zeroizing::new(e.into_bytes());
                Err(VaultError::InvalidSecret {
                    what: "password",
                    why: "not UTF-8",
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn typed(bytes: &[u8]) -> (PasswordLine, PasswordFeed) {
        let mut line = PasswordLine::new();
        let mut last = PasswordFeed::More;
        for &b in bytes {
            last = line.feed(b);
            if last != PasswordFeed::More {
                break;
            }
        }
        (line, last)
    }

    fn reads(line: PasswordLine, want: &str) -> bool {
        line.finish().is_ok_and(|p| p.expose() == want)
    }

    #[test]
    fn enter_ends_the_line_with_cr_or_lf() {
        for end in *b"\r\n" {
            let (line, fed) = typed(&[b'p', b'w', end]);
            assert_eq!(fed, PasswordFeed::Done);
            assert!(reads(line, "pw"));
        }
    }

    #[test]
    fn ctrl_c_and_ctrl_backslash_interrupt() {
        for key in [0x03, 0x1c] {
            assert_eq!(typed(&[b'a', key]).1, PasswordFeed::Interrupted);
        }
    }

    #[test]
    fn ctrl_d_ends_only_an_empty_line() {
        assert_eq!(typed(&[0x04]).1, PasswordFeed::Eof);
        let (line, fed) = typed(&[b'a', 0x04, b'\r']);
        assert_eq!(fed, PasswordFeed::Done);
        assert!(reads(line, "a"));
    }

    #[test]
    fn backspace_removes_one_whole_character() {
        for bs in [0x7f, 0x08] {
            let (line, _) = typed(&[b'a', 0xc3, 0xa9, bs, b'b', b'\r']);
            assert!(reads(line, "ab"));
        }
        let (line, _) = typed(&[b'a', 0xe2, 0x82, 0xac, 0x7f, b'\r']);
        assert!(reads(line, "a"));
        let (line, _) = typed(b"ab\x7f\r");
        assert!(reads(line, "a"));
        let (line, _) = typed(b"\x7fx\r");
        assert!(reads(line, "x"));
    }

    #[test]
    fn ctrl_u_clears_the_line() {
        let (line, _) = typed(b"abc\x15d\r");
        assert!(reads(line, "d"));
    }

    #[test]
    fn escape_sequences_are_dropped_whole() {
        let (line, _) = typed(b"a\x1b[Ab\x1b[1;5Cc\x1bOPd\x1bxe\r");
        assert!(reads(line, "abcde"));
    }

    #[test]
    fn enter_and_interrupt_still_end_a_line_inside_an_escape() {
        assert_eq!(typed(b"a\x1b[1\r").1, PasswordFeed::Done);
        assert_eq!(typed(b"a\x1b[1\x03").1, PasswordFeed::Interrupted);
        let (line, _) = typed(b"a\x1b[\rb");
        assert!(reads(line, "a"));
    }

    #[test]
    fn other_control_bytes_are_ignored_and_tab_and_space_are_kept() {
        let (line, _) = typed(b"a\x00\x1a\x1f\t b\r");
        assert!(reads(line, "a\t b"));
    }

    #[test]
    fn the_line_holds_the_maximum_and_never_grows() {
        let mut line = PasswordLine::new();
        assert_eq!(line.buf.capacity(), MAX_PASSWORD_BYTES);
        for _ in 0..MAX_PASSWORD_BYTES {
            assert_eq!(line.feed(b'a'), PasswordFeed::More);
        }
        assert_eq!(line.feed(b'a'), PasswordFeed::TooLong);
        assert_eq!(
            (line.buf.len(), line.buf.capacity()),
            (MAX_PASSWORD_BYTES, MAX_PASSWORD_BYTES)
        );
        let mut full = PasswordLine::new();
        for _ in 0..MAX_PASSWORD_BYTES {
            full.feed(b'a');
        }
        assert_eq!(full.feed(b'\r'), PasswordFeed::Done);
        assert_eq!(full.finish().unwrap().len(), MAX_PASSWORD_BYTES);
    }

    #[test]
    fn an_empty_or_non_utf8_line_is_refused() {
        let (line, fed) = typed(b"\r");
        assert_eq!(fed, PasswordFeed::Done);
        assert!(matches!(
            line.finish(),
            Err(VaultError::InvalidSecret {
                what: "password",
                why: "must be 1..=1024 bytes"
            })
        ));
        let (line, _) = typed(&[0xff, b'\r']);
        assert!(matches!(
            line.finish(),
            Err(VaultError::InvalidSecret {
                what: "password",
                why: "not UTF-8"
            })
        ));
    }

    #[test]
    fn an_ended_line_stays_ended_and_only_done_can_finish() {
        let mut line = PasswordLine::new();
        for _ in 0..=MAX_PASSWORD_BYTES {
            line.feed(b'a');
        }
        assert_eq!(line.feed(b'\r'), PasswordFeed::TooLong);
        assert_eq!(line.feed(b'x'), PasswordFeed::TooLong);
        assert!(line.finish().is_err());

        let (line, fed) = typed(b"ab\x03");
        assert_eq!(fed, PasswordFeed::Interrupted);
        assert!(line.finish().is_err());

        let (line, fed) = typed(b"ab");
        assert_eq!(fed, PasswordFeed::More);
        assert!(line.finish().is_err());

        let mut line = PasswordLine::new();
        assert_eq!(line.feed(0x04), PasswordFeed::Eof);
        assert_eq!(line.feed(b'a'), PasswordFeed::Eof);
        assert!(line.finish().is_err());

        let mut line = PasswordLine::new();
        line.feed(b'a');
        assert_eq!(line.feed(b'\r'), PasswordFeed::Done);
        assert_eq!(line.feed(0x03), PasswordFeed::Done);
        assert!(reads(line, "a"));
    }

    #[test]
    fn escape_edge_cases_are_dropped_or_aborted_per_ecma_48() {
        let rows: [(&[u8], &str); 11] = [
            (b"a\x1b\x1b[Ab\r", "ab"),
            (b"\x1b[\x1b[Ab\r", "b"),
            (b"\x1b[1\x01b\r", "b"),
            (b"\x1b[1\xc3\xa9b\r", "\u{e9}b"),
            (b"ab\x1b[1\x7fc\r", "ac"),
            (b"a\x1bO5Pb\r", "ab"),
            (b"a\x1bOPb\r", "ab"),
            (b"a\x1b\r", "a"),
            (b"a\x1bO\x1b[Ab\r", "ab"),
            (b"a\x1bO\xc3\xa9b\r", "a\u{e9}b"),
            (b"ab\xa9\x7f\r", "ab"),
        ];
        for (i, (bytes, want)) in rows.into_iter().enumerate() {
            let (line, fed) = typed(bytes);
            assert_eq!(fed, PasswordFeed::Done);
            assert!(reads(line, want), "row {i}");
        }
    }

    #[test]
    fn backspace_over_invalid_bytes_never_erases_past_one_character() {
        let (line, _) = typed(&[b'a', 0x80, 0x80, 0x80, 0x80, 0x80, 0x7f, b'\r']);
        assert_eq!(line.buf.len(), 3);
    }

    #[test]
    fn typing_after_ctrl_u_keeps_the_capacity() {
        let mut line = PasswordLine::new();
        for &b in b"abc\x15de" {
            line.feed(b);
        }
        assert_eq!(line.buf.capacity(), MAX_PASSWORD_BYTES);
        assert_eq!(line.feed(b'\r'), PasswordFeed::Done);
        assert!(reads(line, "de"));
    }
}
