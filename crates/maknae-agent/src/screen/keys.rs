#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Key {
    Char(char),
    Enter,
    CtrlJ,
    Backspace,
    Delete,
    Left,
    Right,
    Up,
    Down,
    PageUp,
    PageDown,
    Home,
    End,
    Ctrl(char),
    Alt(char),
    PasteStart,
    PasteEnd,
    Resize,
    Unknown,
}

const ESC: u8 = 0x1b;
const PASTE_END: &[u8] = b"\x1b[201~";
const CSI_MAX: usize = 32;

/// Decodes one key per call from the front of `input`. `(None, 0)` means the
/// front is an incomplete sequence: call again with more bytes appended.
#[derive(Default, Debug)]
pub struct Decoder {
    in_paste: bool,
    skip_lf: bool,
}

impl Decoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn in_paste(&self) -> bool {
        self.in_paste
    }

    pub fn next(&mut self, input: &[u8]) -> (Option<Key>, usize) {
        let Some(&first) = input.first() else {
            return (None, 0);
        };
        let skip_lf = std::mem::take(&mut self.skip_lf);
        if self.in_paste {
            return self.paste(input, first, skip_lf);
        }
        match first {
            ESC => self.escape(input),
            b'\r' => (Some(Key::Enter), 1),
            b'\n' => (Some(Key::CtrlJ), 1),
            0x7f | 0x08 => (Some(Key::Backspace), 1),
            0x01..=0x1a => (Some(Key::Ctrl(char::from(b'a' + first - 1))), 1),
            0x00 | 0x1c..=0x1f => (Some(Key::Unknown), 1),
            _ => match utf8(input) {
                Utf8::Char(c, n) => (Some(Key::Char(c)), n),
                Utf8::Incomplete => (None, 0),
                Utf8::Invalid => (Some(Key::Unknown), 1),
            },
        }
    }

    /// For the driver once no more bytes follow in time: an incomplete front
    /// (a lone ESC, a cut sequence) is one `Unknown`.
    pub fn flush(&mut self, input: &[u8]) -> (Option<Key>, usize) {
        match self.next(input) {
            (None, 0) if input.is_empty() => (None, 0),
            (None, 0) if self.in_paste && input[0] == ESC => (Some(Key::Char('\x1b')), 1),
            (None, 0) => (Some(Key::Unknown), input.len()),
            done => done,
        }
    }

    fn paste(&mut self, input: &[u8], first: u8, skip_lf: bool) -> (Option<Key>, usize) {
        match first {
            b'\n' if skip_lf => (None, 1),
            b'\r' => {
                self.skip_lf = true;
                (Some(Key::CtrlJ), 1)
            }
            b'\n' => (Some(Key::CtrlJ), 1),
            ESC if input.starts_with(PASTE_END) => {
                self.in_paste = false;
                (Some(Key::PasteEnd), PASTE_END.len())
            }
            ESC if PASTE_END.starts_with(input) => (None, 0),
            _ => match utf8(input) {
                Utf8::Char(c, n) => (Some(Key::Char(c)), n),
                Utf8::Incomplete => (None, 0),
                Utf8::Invalid => (Some(Key::Unknown), 1),
            },
        }
    }

    fn escape(&mut self, input: &[u8]) -> (Option<Key>, usize) {
        match input.get(1) {
            None => (None, 0),
            Some(b'[') => self.csi(input),
            Some(b'O') => match input.get(2) {
                None => (None, 0),
                Some(b'A') => (Some(Key::Up), 3),
                Some(b'B') => (Some(Key::Down), 3),
                Some(b'C') => (Some(Key::Right), 3),
                Some(b'D') => (Some(Key::Left), 3),
                Some(b'H') => (Some(Key::Home), 3),
                Some(b'F') => (Some(Key::End), 3),
                Some(_) => (Some(Key::Unknown), 3),
            },
            Some(&ESC) => (Some(Key::Unknown), 1),
            Some(_) => match utf8(&input[1..]) {
                Utf8::Char(c, n) if !c.is_control() => (Some(Key::Alt(c)), 1 + n),
                Utf8::Incomplete => (None, 0),
                _ => (Some(Key::Unknown), 2),
            },
        }
    }

    fn csi(&mut self, input: &[u8]) -> (Option<Key>, usize) {
        let window = &input[2..input.len().min(CSI_MAX)];
        let Some(at) = window.iter().position(|b| !(0x20..=0x3f).contains(b)) else {
            return if input.len() >= CSI_MAX {
                (Some(Key::Unknown), CSI_MAX)
            } else {
                (None, 0)
            };
        };
        let at = at + 2;
        let fin = input[at];
        if !(0x40..=0x7e).contains(&fin) {
            return (Some(Key::Unknown), at);
        }
        let used = at + 1;
        let param = input[2..at]
            .split(|&b| b == b';')
            .next()
            .and_then(|p| std::str::from_utf8(p).ok())
            .and_then(|p| p.parse::<u16>().ok());
        let key = match (fin, param) {
            (b'A', _) => Key::Up,
            (b'B', _) => Key::Down,
            (b'C', _) => Key::Right,
            (b'D', _) => Key::Left,
            (b'H', _) => Key::Home,
            (b'F', _) => Key::End,
            (b'~', Some(1 | 7)) => Key::Home,
            (b'~', Some(4 | 8)) => Key::End,
            (b'~', Some(3)) => Key::Delete,
            (b'~', Some(5)) => Key::PageUp,
            (b'~', Some(6)) => Key::PageDown,
            (b'~', Some(200)) => {
                self.in_paste = true;
                Key::PasteStart
            }
            (b'~', Some(201)) => Key::PasteEnd,
            _ => Key::Unknown,
        };
        (Some(key), used)
    }
}

enum Utf8 {
    Char(char, usize),
    Incomplete,
    Invalid,
}

fn utf8(input: &[u8]) -> Utf8 {
    let want = match input[0] {
        0x00..=0x7f => 1,
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => return Utf8::Invalid,
    };
    let have = input.len().min(want);
    match std::str::from_utf8(&input[..have]) {
        Ok(s) => s
            .chars()
            .next()
            .map_or(Utf8::Invalid, |c| Utf8::Char(c, want)),
        Err(e) if e.error_len().is_none() => Utf8::Incomplete,
        Err(_) => Utf8::Invalid,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_all(d: &mut Decoder, input: &[u8]) -> (Vec<Key>, usize) {
        let mut keys = Vec::new();
        let mut at = 0;
        loop {
            let (key, used) = d.next(&input[at..]);
            if used == 0 {
                assert!(key.is_none());
                return (keys, at);
            }
            at += used;
            keys.extend(key);
        }
    }

    #[test]
    fn bracketed_paste_is_one_chunked_paste_with_lf_line_ends() {
        let mut d = Decoder::new();
        let mut keys = Vec::new();
        let chunks: [&[u8]; 4] = [b"\x1b[200~a\r", b"\nb\rc", b"\nd\x1b[2", b"01~"];
        let mut pending: Vec<u8> = Vec::new();
        for chunk in chunks {
            pending.extend_from_slice(chunk);
            let (got, used) = decode_all(&mut d, &pending);
            keys.extend(got);
            pending.drain(..used);
        }
        assert!(pending.is_empty());
        use Key::*;
        assert_eq!(
            keys,
            [
                PasteStart,
                Char('a'),
                CtrlJ,
                Char('b'),
                CtrlJ,
                Char('c'),
                CtrlJ,
                Char('d'),
                PasteEnd
            ]
        );
        assert!(!d.in_paste());
    }

    #[test]
    fn a_paste_carries_enter_escape_and_controls_as_text() {
        let mut d = Decoder::new();
        let (keys, used) = decode_all(&mut d, b"\x1b[200~\x1b[A\x7f\t\x1b[201~\r");
        assert_eq!(used, 18);
        use Key::*;
        assert_eq!(
            keys,
            [
                PasteStart,
                Char('\x1b'),
                Char('['),
                Char('A'),
                Char('\x7f'),
                Char('\t'),
                PasteEnd,
                Enter
            ]
        );
    }

    #[test]
    fn alt_and_arrow_sequences_decode() {
        let mut d = Decoder::new();
        let input = b"\x1bb\x1bf\x1b[A\x1b[B\x1b[C\x1b[D\x1bOA\x1b[1;5C\x1b[H\x1b[F\x1b[1~\x1b[4~\x1b[3~\x1b[5~\x1b[6~\x1b[7~\x1b[8~\x1bOH\x1bOF\x1b\xed\x95\x9c";
        let (keys, used) = decode_all(&mut d, input);
        assert_eq!(used, input.len());
        use Key::*;
        assert_eq!(
            keys,
            [
                Alt('b'),
                Alt('f'),
                Up,
                Down,
                Right,
                Left,
                Up,
                Right,
                Home,
                End,
                Home,
                End,
                Delete,
                PageUp,
                PageDown,
                Home,
                End,
                Home,
                End,
                Alt('한')
            ]
        );
    }

    #[test]
    fn control_bytes_and_text_decode() {
        let mut d = Decoder::new();
        let input = "\r\n\x7f\x08\x01\x05\x17\x03\x04aé한😀".as_bytes();
        let (keys, used) = decode_all(&mut d, input);
        assert_eq!(used, input.len());
        use Key::*;
        assert_eq!(
            keys,
            [
                Enter,
                CtrlJ,
                Backspace,
                Backspace,
                Ctrl('a'),
                Ctrl('e'),
                Ctrl('w'),
                Ctrl('c'),
                Ctrl('d'),
                Char('a'),
                Char('é'),
                Char('한'),
                Char('😀')
            ]
        );
    }

    #[test]
    fn a_split_escape_sequence_across_feeds_decodes() {
        let mut d = Decoder::new();
        assert_eq!(d.next(b"\x1b"), (None, 0));
        assert_eq!(d.next(b"\x1b["), (None, 0));
        assert_eq!(d.next(b"\x1b[5"), (None, 0));
        assert_eq!(d.next(b"\x1b[5~"), (Some(Key::PageUp), 4));
        assert_eq!(d.next(b"\x1bO"), (None, 0));
        assert_eq!(d.next(b"\x1bOB"), (Some(Key::Down), 3));
        assert_eq!(d.next(b"\xed\x95"), (None, 0));
        assert_eq!(d.next(b"\xed\x95\x9c"), (Some(Key::Char('한')), 3));
        assert_eq!(d.next(b"\x1b\xed\x95"), (None, 0));
        assert_eq!(d.next(b""), (None, 0));
    }

    #[test]
    fn malformed_input_is_unknown_and_consumed() {
        let mut d = Decoder::new();
        assert_eq!(d.next(b"\xff"), (Some(Key::Unknown), 1));
        assert_eq!(d.next(b"\x9b31m"), (Some(Key::Unknown), 1));
        assert_eq!(d.next(b"\x9d0;t\x07"), (Some(Key::Unknown), 1));
        let mut p = Decoder::new();
        p.next(b"\x1b[200~");
        assert_eq!(p.next(b"\x9b2J"), (Some(Key::Unknown), 1));
        assert_eq!(d.next(b"\xed\x41"), (Some(Key::Unknown), 1));
        assert_eq!(d.next(b"\x1b[9~"), (Some(Key::Unknown), 4));
        assert_eq!(d.next(b"\x1b[Z"), (Some(Key::Unknown), 3));
        assert_eq!(d.next(b"\x1b[201~"), (Some(Key::PasteEnd), 6));
        assert!(!d.in_paste());
        assert_eq!(d.next(b"\x1bOZ"), (Some(Key::Unknown), 3));
        assert_eq!(d.next(b"\x1b\x1b"), (Some(Key::Unknown), 1));
        assert_eq!(d.next(b"\x1b\x7f"), (Some(Key::Unknown), 2));
        assert_eq!(d.next(b"\x1b[\x01"), (Some(Key::Unknown), 2));
        assert_eq!(d.next(b"\x00"), (Some(Key::Unknown), 1));
        assert_eq!(d.next(b"\x1c"), (Some(Key::Unknown), 1));
        let long = [b"\x1b[".as_slice(), &[b'1'; CSI_MAX], b"~"].concat();
        assert_eq!(d.next(&long), (Some(Key::Unknown), CSI_MAX));
        let cut = [b"\x1b[".as_slice(), &[b'1'; CSI_MAX - 2]].concat();
        assert_eq!(d.next(&cut), (Some(Key::Unknown), CSI_MAX));
        let short = [b"\x1b[".as_slice(), &[b'1'; CSI_MAX - 3]].concat();
        assert_eq!(d.next(&short), (None, 0));
    }

    #[test]
    fn flush_turns_an_incomplete_front_into_one_unknown() {
        let mut d = Decoder::new();
        assert_eq!(d.flush(b"\x1b"), (Some(Key::Unknown), 1));
        assert_eq!(d.flush(b"\x1b[1"), (Some(Key::Unknown), 3));
        assert_eq!(d.flush(b"\x1b[A"), (Some(Key::Up), 3));
        assert_eq!(d.flush(b""), (None, 0));
        let mut p = Decoder::new();
        assert_eq!(p.next(b"\x1b[200~"), (Some(Key::PasteStart), 6));
        assert!(p.in_paste());
        assert_eq!(p.next(b"\x1b[20"), (None, 0));
        assert_eq!(p.flush(b"\x1b[20"), (Some(Key::Char('\x1b')), 1));
    }

    #[test]
    fn a_lone_lf_after_a_paste_cr_is_dropped_only_inside_the_paste() {
        let mut d = Decoder::new();
        let (keys, _) = decode_all(&mut d, b"\x1b[200~\r\x1b[201~\n");
        assert_eq!(
            keys,
            [Key::PasteStart, Key::CtrlJ, Key::PasteEnd, Key::CtrlJ]
        );
        let (keys, _) = decode_all(&mut d, b"\x1b[200~\n\n\x1b[201~");
        assert_eq!(
            keys,
            [Key::PasteStart, Key::CtrlJ, Key::CtrlJ, Key::PasteEnd]
        );
    }
}
