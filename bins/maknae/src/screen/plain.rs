use super::term::{write_all, Readable, TermError};
use maknae_agent::render::display_safe;
use maknae_agent::screen::fixed::FixedText;
use nix::errno::Errno;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use zeroize::{Zeroize, Zeroizing};

pub(crate) const OUT_BYTES: usize = 4096;

pub(crate) enum Line {
    Text(Zeroizing<String>),
    Refused,
    End,
}

impl std::fmt::Debug for Line {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Line::Text(t) => write!(f, "Text(<{} bytes>)", t.len()),
            Line::Refused => f.write_str("Refused"),
            Line::End => f.write_str("End"),
        }
    }
}

/// The session without a terminal: lines in through one fixed buffer, lines out
/// escaped for display.
pub(crate) struct Lines {
    input: OwnedFd,
    readable: Readable,
    output: OwnedFd,
    line_max: usize,
    buf: Zeroizing<Vec<u8>>,
    filled: usize,
    skipping: bool,
    ended: bool,
    out: FixedText,
}

impl Lines {
    pub(crate) fn stdio(line_max: usize) -> Result<Lines, TermError> {
        let dup = |fd: BorrowedFd<'_>| {
            fd.try_clone_to_owned()
                .map_err(|e| TermError::Read(Errno::from_raw(e.raw_os_error().unwrap_or(0))))
        };
        Self::new(
            dup(std::io::stdin().as_fd())?,
            dup(std::io::stdout().as_fd())?,
            line_max,
        )
    }

    /// `line_max` is the request bound in bytes; a longer line is refused.
    pub(crate) fn new(
        input: OwnedFd,
        output: OwnedFd,
        line_max: usize,
    ) -> Result<Lines, TermError> {
        Ok(Lines {
            readable: Readable::new(&input)?,
            input,
            output,
            line_max,
            buf: Zeroizing::new(vec![0; line_max + 2]),
            filled: 0,
            skipping: false,
            ended: false,
            out: FixedText::with_capacity(OUT_BYTES),
        })
    }

    /// The next line without its `\n` or `\r\n`. Cancel-safe: what was read
    /// stays in the buffer.
    pub(crate) async fn next_line(&mut self) -> Result<Line, TermError> {
        loop {
            if let Some(line) = self.take_line()? {
                return Ok(line);
            }
            self.readable.wait().await?;
            self.fill()?;
        }
    }

    pub(crate) fn write_line(&mut self, text: &str) -> Result<(), TermError> {
        let mut piece = [0u8; 4];
        for c in text.chars().chain(['\n']) {
            let c = c.encode_utf8(&mut piece);
            if display_safe(c, &mut self.out).is_err() {
                self.flush()?;
                if display_safe(c, &mut self.out).is_err() {
                    return Err(TermError::Write(Errno::ENOBUFS));
                }
            }
        }
        self.flush()
    }

    fn flush(&mut self) -> Result<(), TermError> {
        let written = write_all(&self.output, self.out.as_str().as_bytes());
        self.out.clear();
        written.map_err(TermError::Write)
    }

    fn fill(&mut self) -> Result<(), TermError> {
        match nix::unistd::read(&self.input, &mut self.buf[self.filled..]) {
            Ok(0) => self.ended = true,
            Ok(n) => self.filled += n,
            Err(Errno::EINTR | Errno::EAGAIN) => {}
            Err(e) => return Err(TermError::Read(e)),
        }
        Ok(())
    }

    fn take_line(&mut self) -> Result<Option<Line>, TermError> {
        loop {
            let newline = self.buf[..self.filled].iter().position(|&b| b == b'\n');
            match newline {
                Some(at) if self.skipping => {
                    self.consume(at + 1);
                    self.skipping = false;
                }
                Some(at) => {
                    let line = self.line(at)?;
                    self.consume(at + 1);
                    return Ok(Some(line));
                }
                None if self.skipping => {
                    self.consume(self.filled);
                    return Ok(self.ended.then_some(Line::End));
                }
                None if self.filled == self.buf.len() => {
                    self.consume(self.filled);
                    self.skipping = true;
                    return self.refuse(&self.too_long()).map(Some);
                }
                None if self.ended && self.filled > 0 => {
                    let line = self.line(self.filled)?;
                    self.consume(self.filled);
                    return Ok(Some(line));
                }
                None if self.ended => return Ok(Some(Line::End)),
                None => return Ok(None),
            }
        }
    }

    fn line(&mut self, end: usize) -> Result<Line, TermError> {
        let bytes = &self.buf[..end];
        let bytes = bytes.strip_suffix(b"\r").unwrap_or(bytes);
        if bytes.len() > self.line_max {
            return self.refuse(&self.too_long());
        }
        match std::str::from_utf8(bytes) {
            Ok(text) => {
                let mut line = Zeroizing::new(String::with_capacity(text.len()));
                line.push_str(text);
                Ok(Line::Text(line))
            }
            Err(_) => self.refuse("maknae: that line is not UTF-8 text and was not sent"),
        }
    }

    fn too_long(&self) -> String {
        format!(
            "maknae: that line is longer than {} bytes and was not sent",
            self.line_max
        )
    }

    fn refuse(&mut self, why: &str) -> Result<Line, TermError> {
        self.write_line(why)?;
        Ok(Line::Refused)
    }

    fn consume(&mut self, n: usize) {
        self.buf.copy_within(n..self.filled, 0);
        self.buf[self.filled - n..self.filled].zeroize();
        self.filled -= n;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(line_max: usize) -> (Lines, OwnedFd, OwnedFd) {
        let (in_r, in_w) = nix::unistd::pipe().unwrap();
        let (out_r, out_w) = nix::unistd::pipe().unwrap();
        (Lines::new(in_r, out_w, line_max).unwrap(), in_w, out_r)
    }

    fn written(out_r: &OwnedFd) -> String {
        let mut got = vec![0u8; 64 * 1024];
        let n = nix::unistd::read(out_r, &mut got).unwrap();
        String::from_utf8(got[..n].to_vec()).unwrap()
    }

    fn text(line: Line) -> String {
        match line {
            Line::Text(t) => t.to_string(),
            other => panic!("expected a line, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn an_over_long_line_is_refused_visibly_and_the_next_line_is_read() {
        let (mut lines, in_w, out_r) = lines(8);
        write_all(&in_w, b"123456789abcdef\nshort\r\n").unwrap();
        drop(in_w);
        assert!(matches!(lines.next_line().await.unwrap(), Line::Refused));
        assert_eq!(
            written(&out_r),
            "maknae: that line is longer than 8 bytes and was not sent\n"
        );
        assert_eq!(text(lines.next_line().await.unwrap()), "short");
        assert!(matches!(lines.next_line().await.unwrap(), Line::End));
    }

    #[tokio::test]
    async fn a_line_of_exactly_the_limit_is_read_and_one_byte_more_is_refused() {
        let (mut lines, in_w, _out_r) = lines(4);
        write_all(&in_w, b"abcd\nabcde\nlast").unwrap();
        drop(in_w);
        assert_eq!(text(lines.next_line().await.unwrap()), "abcd");
        assert!(matches!(lines.next_line().await.unwrap(), Line::Refused));
        assert_eq!(text(lines.next_line().await.unwrap()), "last");
        assert!(matches!(lines.next_line().await.unwrap(), Line::End));
    }

    #[tokio::test]
    async fn a_line_that_is_not_utf8_is_refused_visibly() {
        let (mut lines, in_w, out_r) = lines(16);
        write_all(&in_w, b"\xff\xfe\n").unwrap();
        drop(in_w);
        assert!(matches!(lines.next_line().await.unwrap(), Line::Refused));
        assert_eq!(
            written(&out_r),
            "maknae: that line is not UTF-8 text and was not sent\n"
        );
    }

    #[test]
    fn output_lines_are_escaped_for_display() {
        let (mut lines, _in_w, out_r) = lines(16);
        lines
            .write_line("#2 working \x1b[2J\u{202e}x\r\nnext")
            .unwrap();
        assert_eq!(
            written(&out_r),
            "#2 working \\u{001b}[2J\\u{202e}x\\u{000d}\nnext\n"
        );
    }

    #[tokio::test]
    async fn the_line_and_output_buffers_never_move_or_grow() {
        let (mut lines, in_w, out_r) = lines(64);
        let (ptr, cap) = (lines.buf.as_ptr(), lines.buf.capacity());
        let out_ptr = lines.out.as_str().as_ptr();
        let writer = std::thread::spawn(move || {
            for _ in 0..200 {
                write_all(&in_w, &[b'y'; 100]).unwrap();
                write_all(&in_w, b"\nok\n").unwrap();
            }
        });
        let drain = std::thread::spawn(move || {
            let mut chunk = [0u8; 4096];
            while let Ok(1..) = nix::unistd::read(&out_r, &mut chunk) {}
        });
        let mut ok = 0;
        loop {
            match lines.next_line().await.unwrap() {
                Line::Text(_) => ok += 1,
                Line::Refused => {}
                Line::End => break,
            }
            lines.write_line(&"z".repeat(3 * OUT_BYTES)).unwrap();
            assert_eq!((lines.buf.as_ptr(), lines.buf.capacity()), (ptr, cap));
            assert_eq!(
                (lines.out.as_str().as_ptr(), lines.out.capacity()),
                (out_ptr, OUT_BYTES)
            );
        }
        assert_eq!(ok, 200);
        writer.join().unwrap();
        drop(lines);
        drain.join().unwrap();
    }
}
