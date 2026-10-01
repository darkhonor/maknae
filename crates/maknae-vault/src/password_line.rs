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
        }
    }

    pub fn feed(&mut self, byte: u8) -> PasswordFeed {
        match byte {
            b'\r' | b'\n' => return PasswordFeed::Done,
            0x03 | 0x1c => return PasswordFeed::Interrupted,
            _ => {}
        }
        match self.escape {
            Escape::Started => {
                self.escape = match byte {
                    b'[' => Escape::Csi,
                    b'O' => Escape::Ss3,
                    _ => Escape::None,
                };
                return PasswordFeed::More;
            }
            Escape::Csi => {
                if (0x40..=0x7e).contains(&byte) {
                    self.escape = Escape::None;
                }
                return PasswordFeed::More;
            }
            Escape::Ss3 => {
                self.escape = Escape::None;
                return PasswordFeed::More;
            }
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
        while let Some(b) = self.buf.pop() {
            if b & 0xc0 != 0x80 {
                break;
            }
        }
    }

    pub fn finish(mut self) -> Result<Password, VaultError> {
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

    fn text(line: PasswordLine) -> String {
        line.finish().unwrap().expose().to_string()
    }

    #[test]
    fn enter_ends_the_line_with_cr_or_lf() {
        for end in *b"\r\n" {
            let (line, fed) = typed(&[b'p', b'w', end]);
            assert_eq!(fed, PasswordFeed::Done);
            assert_eq!(text(line), "pw");
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
        assert_eq!(text(line), "a");
    }

    #[test]
    fn backspace_removes_one_whole_character() {
        for bs in [0x7f, 0x08] {
            let (line, _) = typed(&[b'a', 0xc3, 0xa9, bs, b'b', b'\r']);
            assert_eq!(text(line), "ab");
        }
        let (line, _) = typed(&[b'a', 0xe2, 0x82, 0xac, 0x7f, b'\r']);
        assert_eq!(text(line), "a");
        let (line, _) = typed(b"ab\x7f\r");
        assert_eq!(text(line), "a");
        let (line, _) = typed(b"\x7fx\r");
        assert_eq!(text(line), "x");
    }

    #[test]
    fn ctrl_u_clears_the_line() {
        let (line, _) = typed(b"abc\x15d\r");
        assert_eq!(text(line), "d");
    }

    #[test]
    fn escape_sequences_are_dropped_whole() {
        let (line, _) = typed(b"a\x1b[Ab\x1b[1;5Cc\x1bOPd\x1bxe\r");
        assert_eq!(text(line), "abcde");
    }

    #[test]
    fn enter_and_interrupt_still_end_a_line_inside_an_escape() {
        assert_eq!(typed(b"a\x1b[1\r").1, PasswordFeed::Done);
        assert_eq!(typed(b"a\x1b[1\x03").1, PasswordFeed::Interrupted);
        let (line, _) = typed(b"a\x1b[\rb");
        assert_eq!(text(line), "a");
    }

    #[test]
    fn other_control_bytes_are_ignored_and_tab_and_space_are_kept() {
        let (line, _) = typed(b"a\x00\x1a\x1f\t b\r");
        assert_eq!(text(line), "a\t b");
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
        assert_eq!(line.finish().unwrap().len(), MAX_PASSWORD_BYTES);
    }

    #[test]
    fn an_empty_or_non_utf8_line_is_refused() {
        assert!(matches!(
            PasswordLine::default().finish(),
            Err(VaultError::InvalidSecret {
                what: "password",
                ..
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
}
