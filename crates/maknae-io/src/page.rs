use std::io::{ErrorKind, Read};
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageWindow {
    pub offset_line: u64,
    pub limit_lines: u32,
    pub column: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageNext {
    pub line: u64,
    pub column: u64,
}

pub struct Page {
    pub content: Zeroizing<Vec<u8>>,
    pub start: u64,
    pub lines: Option<(u64, u64)>,
    pub complete_last: bool,
    pub next: Option<PageNext>,
    pub eof: bool,
    pub version: crate::FileVersion,
}

impl std::fmt::Debug for Page {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Page")
            .field("content", &format_args!("<{} bytes>", self.content.len()))
            .field("start", &self.start)
            .field("lines", &self.lines)
            .field("complete_last", &self.complete_last)
            .field("next", &self.next)
            .field("eof", &self.eof)
            .finish()
    }
}

struct Scan<'r, R> {
    r: &'r mut R,
    buf: Zeroizing<Vec<u8>>,
    at: usize,
    len: usize,
    pos: u64,
}

impl<R: Read> Scan<'_, R> {
    fn peek(&mut self) -> std::io::Result<Option<u8>> {
        if self.at == self.len {
            self.len = loop {
                match self.r.read(&mut self.buf) {
                    Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                    other => break other?,
                }
            };
            self.at = 0;
        }
        Ok((self.at < self.len).then_some(self.buf[self.at]))
    }
    fn take(&mut self) {
        self.at += 1;
        self.pos += 1;
    }
}

fn incomplete_tail(bytes: &[u8]) -> usize {
    for back in 1..=bytes.len().min(4) {
        let b = bytes[bytes.len() - back];
        if b & 0xC0 != 0x80 {
            let need = match b {
                0xC0..=0xDF => 2,
                0xE0..=0xEF => 3,
                0xF0..=0xF7 => 4,
                _ => 1,
            };
            return if need > back { back } else { 0 };
        }
    }
    0
}

pub fn read_page<R: Read>(r: &mut R, w: PageWindow, cap: usize) -> std::io::Result<Page> {
    let mut s = Scan {
        r,
        buf: Zeroizing::new(vec![0; 8192]),
        at: 0,
        len: 0,
        pos: 0,
    };
    let mut line = 1u64;
    while line < w.offset_line {
        match s.peek()? {
            None => break,
            Some(b) => {
                s.take();
                if b == b'\n' {
                    line += 1;
                }
            }
        }
    }
    let mut col = 0u64;
    while line == w.offset_line && col < w.column {
        match s.peek()? {
            Some(b) if b != b'\n' => {
                s.take();
                col += 1;
            }
            _ => break,
        }
    }
    let start = s.pos;
    let mut content = Zeroizing::new(Vec::with_capacity(cap));
    let (mut taken, mut cur) = (0u32, line);
    while line == w.offset_line && taken < w.limit_lines && content.len() < cap {
        match s.peek()? {
            None => break,
            Some(b) => {
                s.take();
                content.push(b);
                if b == b'\n' {
                    taken += 1;
                    cur += 1;
                    col = 0;
                } else {
                    col += 1;
                }
            }
        }
    }
    let mut trimmed = 0;
    if content.len() == cap && content.last() != Some(&b'\n') {
        let tail = incomplete_tail(&content);
        if tail < content.len() {
            let keep = content.len() - tail;
            content[keep..].fill(0);
            content.truncate(keep);
            col -= tail as u64;
            trimmed = tail;
        }
    }
    let eof = trimmed == 0 && s.peek()?.is_none();
    let ends_line = content.last() == Some(&b'\n');
    let lines =
        (!content.is_empty()).then(|| (w.offset_line, if ends_line { cur - 1 } else { cur }));
    let next = (!eof).then_some(PageNext {
        line: cur,
        column: if ends_line { 0 } else { col },
    });
    Ok(Page {
        complete_last: ends_line || eof,
        content,
        start,
        lines,
        next,
        eof,
        version: crate::FileVersion::default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn page(text: &[u8], w: PageWindow, cap: usize) -> Page {
        read_page(&mut Cursor::new(text), w, cap).unwrap()
    }
    fn from(line: u64, column: u64, limit: u32) -> PageWindow {
        PageWindow {
            offset_line: line,
            limit_lines: limit,
            column,
        }
    }
    fn stream(text: &[u8], limit: u32, cap: usize) -> (Vec<u8>, usize) {
        let (mut out, mut w, mut n) = (Vec::new(), from(1, 0, limit), 0);
        loop {
            let p = page(text, w, cap);
            assert_eq!(
                &text[p.start as usize..p.start as usize + p.content.len()],
                &p.content[..]
            );
            out.extend_from_slice(&p.content);
            n += 1;
            assert!(n <= text.len() + 2, "no progress at {w:?}");
            match p.next {
                None => {
                    assert!(p.eof);
                    return (out, n);
                }
                Some(next) => w = from(next.line, next.column, limit),
            }
        }
    }
    fn pseudo_random(len: usize) -> Vec<u8> {
        let mut x = 0x9E37_79B9_7F4A_7C15u64;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect()
    }

    #[test]
    fn a_multi_page_file_reassembles_byte_exactly() {
        let text: Vec<u8> = (0..500)
            .flat_map(|i| format!("line {i}\n").into_bytes())
            .collect();
        for (limit, cap) in [(7, 1 << 16), (u32::MAX, 97), (3, 20)] {
            assert_eq!(stream(&text, limit, cap).0, text);
        }
    }

    #[test]
    fn pages_reassemble_any_bytes_exactly() {
        let latin1: Vec<u8> = b"temp 21\xb0C, cost \xa35, half \xbd\n".repeat(50);
        let mut starts_continuation = vec![b'a'; 64];
        starts_continuation.extend_from_slice(&[0x80, b'b']);
        let partial_at_cap = [b"ab\xE0".to_vec(), "a🦀".as_bytes()[..3].to_vec()];
        for text in [
            pseudo_random(5000),
            latin1,
            starts_continuation,
            partial_at_cap[0].clone(),
            partial_at_cap[1].clone(),
        ] {
            for cap in [1, 2, 3, 5, 64, 1000, 65_536] {
                assert_eq!(stream(&text, u32::MAX, cap).0, text, "cap {cap}");
            }
        }
    }

    #[test]
    fn a_line_over_three_caps_continues_by_column() {
        let text = [
            b"head\n".to_vec(),
            vec![b'x'; 3 * 64 + 5],
            b"\ntail".to_vec(),
        ]
        .concat();
        let (out, pages) = stream(&text, u32::MAX, 64);
        assert_eq!(out, text);
        assert!(pages >= 4);
        let first = page(&text, from(2, 0, 1), 64);
        assert_eq!((first.lines, first.complete_last), (Some((2, 2)), false));
        assert_eq!(
            first.next,
            Some(PageNext {
                line: 2,
                column: 64
            })
        );
    }

    #[test]
    fn a_split_never_falls_inside_a_character() {
        for unit in ["é", "가", "🦀"] {
            let text = unit.repeat(60).into_bytes();
            for cap in [4, 5, 6, 7, 64] {
                let (mut w, mut out) = (from(1, 0, u32::MAX), Vec::new());
                loop {
                    let p = page(&text, w, cap);
                    assert!(std::str::from_utf8(&p.content).is_ok(), "{unit} cap {cap}");
                    out.extend_from_slice(&p.content);
                    match p.next {
                        None => break,
                        Some(n) => w = from(n.line, n.column, u32::MAX),
                    }
                }
                assert_eq!(out, text, "{unit} cap {cap}");
            }
        }
    }

    #[test]
    fn a_cap_smaller_than_a_character_still_makes_progress() {
        let text = "🦀🦀".as_bytes();
        let p = page(text, from(1, 0, 1), 2);
        assert_eq!(
            (&p.content[..], p.next),
            (&text[..2], Some(PageNext { line: 1, column: 2 }))
        );
        assert_eq!(stream(text, u32::MAX, 2).0, text);
    }

    #[test]
    fn a_file_ending_in_a_partial_character_is_released_whole_at_eof() {
        let p = page(b"ab\xE0", from(1, 0, 9), 64);
        assert_eq!(
            (&p.content[..], p.eof, p.next),
            (&b"ab\xE0"[..], true, None)
        );
    }

    #[test]
    fn a_page_request_beyond_eof_returns_eof_and_nothing() {
        let p = page(b"a\nb\n", from(9, 0, 5), 64);
        assert_eq!(
            (p.content.len(), p.lines, p.next, p.eof, p.start),
            (0, None, None, true, 4)
        );
        let empty = page(b"", from(1, 0, 5), 64);
        assert_eq!((empty.content.len(), empty.eof), (0, true));
    }

    #[test]
    fn limit_lines_ends_on_a_line_boundary() {
        let p = page(b"a\nb\nc\nd\n", from(2, 0, 2), 64);
        assert_eq!(&p.content[..], b"b\nc\n");
        assert_eq!(
            (p.start, p.lines, p.complete_last, p.eof),
            (2, Some((2, 3)), true, false)
        );
        assert_eq!(p.next, Some(PageNext { line: 4, column: 0 }));
    }

    #[test]
    fn a_column_inside_a_character_starts_there_exactly() {
        let p = page("가나\n".as_bytes(), from(1, 1, 1), 64);
        assert_eq!(&p.content[..], &"가나\n".as_bytes()[1..]);
        assert_eq!(p.start, 1);
    }

    #[test]
    fn a_column_past_the_line_end_starts_at_its_newline() {
        let p = page(b"ab\ncd\n", from(1, 99, 1), 64);
        assert_eq!(&p.content[..], b"\n");
        assert_eq!(
            (p.start, p.next),
            (2, Some(PageNext { line: 2, column: 0 }))
        );
    }

    #[test]
    fn pages_reassemble_awkward_files_byte_exactly() {
        for text in [
            &b"no newline at end"[..],
            b"crlf\r\nlines\r\n",
            b"\n\n\n",
            b"\n",
            b"x",
        ] {
            for cap in [1, 2, 64] {
                assert_eq!(stream(text, 1, cap).0, text, "{text:?} cap {cap}");
            }
        }
        let p = page(b"a\nlast", from(2, 0, 9), 64);
        assert_eq!(
            (p.lines, p.complete_last, p.eof, p.next),
            (Some((2, 2)), true, true, None)
        );
    }

    #[test]
    fn a_page_never_grows_its_buffer() {
        let p = page(&vec![b'z'; 1000], from(1, 0, 1), 100);
        assert_eq!((p.content.len(), p.content.capacity()), (100, 100));
    }

    #[test]
    fn a_page_debug_names_its_length_and_never_its_bytes() {
        let p = page(b"PAGE-DEBUG-SENTINEL\n", from(1, 0, 1), 64);
        let shown = format!("{p:?}");
        assert!(shown.contains("<20 bytes>"), "{shown}");
        assert!(!shown.contains("SENTINEL"), "{shown}");
    }

    #[test]
    fn an_interrupted_read_is_retried() {
        struct Flaky(bool, Cursor<&'static [u8]>);
        impl std::io::Read for Flaky {
            fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
                if std::mem::replace(&mut self.0, false) {
                    return Err(std::io::ErrorKind::Interrupted.into());
                }
                self.1.read(b)
            }
        }
        let p = read_page(&mut Flaky(true, Cursor::new(b"ok\n")), from(1, 0, 1), 64).unwrap();
        assert_eq!(&p.content[..], b"ok\n");
    }

    #[test]
    fn an_io_error_at_any_read_yields_no_page() {
        struct FailsAt(usize, usize, Cursor<&'static [u8]>);
        impl std::io::Read for FailsAt {
            fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
                self.1 += 1;
                if self.1 == self.0 {
                    return Err(std::io::ErrorKind::Other.into());
                }
                let n = self.2.read(&mut b[..1])?;
                Ok(n)
            }
        }
        for k in 1..=5 {
            let r = read_page(
                &mut FailsAt(k, 0, Cursor::new(b"a\nb\nc\n")),
                from(2, 1, 1),
                2,
            );
            assert!(r.is_err(), "k {k}");
        }
    }
}
