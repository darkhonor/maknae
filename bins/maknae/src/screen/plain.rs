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

#[derive(Clone, Copy)]
enum Stream {
    Output,
    Diagnostics,
}

/// The session without a terminal: lines in through one fixed buffer, lines out
/// escaped for display, and a refused line said on the diagnostics descriptor.
pub(crate) struct Lines {
    input: OwnedFd,
    readable: Readable,
    output: OwnedFd,
    diagnostics: OwnedFd,
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
            dup(std::io::stderr().as_fd())?,
            line_max,
        )
    }

    /// `line_max` is the request bound in bytes; a longer line is refused.
    pub(crate) fn new(
        input: OwnedFd,
        output: OwnedFd,
        diagnostics: OwnedFd,
        line_max: usize,
    ) -> Result<Lines, TermError> {
        Ok(Lines {
            readable: Readable::new(&input)?,
            input,
            output,
            diagnostics,
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
        self.put(Stream::Output, text)
    }

    fn put(&mut self, to: Stream, text: &str) -> Result<(), TermError> {
        let mut piece = [0u8; 4];
        for c in text.chars().chain(['\n']) {
            let c = c.encode_utf8(&mut piece);
            if display_safe(c, &mut self.out).is_err() {
                self.flush(to)?;
                if display_safe(c, &mut self.out).is_err() {
                    return Err(TermError::Write(Errno::ENOBUFS));
                }
            }
        }
        self.flush(to)
    }

    fn flush(&mut self, to: Stream) -> Result<(), TermError> {
        let fd = match to {
            Stream::Output => &self.output,
            Stream::Diagnostics => &self.diagnostics,
        };
        let written = write_all(fd, self.out.as_str().as_bytes());
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
        self.put(Stream::Diagnostics, why)?;
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
    use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
    use std::time::Duration;

    struct Pipes {
        lines: Lines,
        input: OwnedFd,
        output: OwnedFd,
        diagnostics: OwnedFd,
    }

    fn lines(line_max: usize) -> Pipes {
        let (in_r, in_w) = nix::unistd::pipe().unwrap();
        let (out_r, out_w) = nix::unistd::pipe().unwrap();
        let (diag_r, diag_w) = nix::unistd::pipe().unwrap();
        Pipes {
            lines: Lines::new(in_r, out_w, diag_w, line_max).unwrap(),
            input: in_w,
            output: out_r,
            diagnostics: diag_r,
        }
    }

    /// What is waiting on `from`, after at most 10 s.
    fn written(from: &OwnedFd) -> String {
        let mut fds = [PollFd::new(from.as_fd(), PollFlags::POLLIN)];
        let ready = poll(&mut fds, PollTimeout::from(10_000u16)).unwrap();
        assert!(ready > 0, "nothing was written within 10 s");
        let mut got = vec![0u8; 64 * 1024];
        let n = nix::unistd::read(from, &mut got).unwrap();
        String::from_utf8(got[..n].to_vec()).unwrap()
    }

    fn nothing_written(from: &OwnedFd) -> bool {
        let mut fds = [PollFd::new(from.as_fd(), PollFlags::POLLIN)];
        poll(&mut fds, PollTimeout::ZERO).unwrap() == 0
    }

    async fn next(lines: &mut Lines) -> Line {
        tokio::time::timeout(Duration::from_secs(10), lines.next_line())
            .await
            .expect("no line within 10 s")
            .unwrap()
    }

    fn text(line: Line) -> String {
        match line {
            Line::Text(t) => t.to_string(),
            other => panic!("expected a line, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn an_over_long_line_is_refused_on_the_diagnostics_and_the_next_line_is_read() {
        let mut p = lines(8);
        write_all(&p.input, b"123456789abcdef\nshort\r\n").unwrap();
        drop(p.input);
        assert!(matches!(next(&mut p.lines).await, Line::Refused));
        assert_eq!(
            written(&p.diagnostics),
            "maknae: that line is longer than 8 bytes and was not sent\n"
        );
        assert!(nothing_written(&p.output), "the refusal reached the output");
        assert_eq!(text(next(&mut p.lines).await), "short");
        assert!(matches!(next(&mut p.lines).await, Line::End));
    }

    #[tokio::test]
    async fn a_line_of_exactly_the_limit_is_read_and_one_byte_more_is_refused() {
        let mut p = lines(4);
        write_all(&p.input, b"abcd\nabcde\nlast").unwrap();
        drop(p.input);
        assert_eq!(text(next(&mut p.lines).await), "abcd");
        assert!(matches!(next(&mut p.lines).await, Line::Refused));
        assert_eq!(text(next(&mut p.lines).await), "last");
        assert!(matches!(next(&mut p.lines).await, Line::End));
    }

    #[tokio::test]
    async fn a_line_that_is_not_utf8_is_refused_on_the_diagnostics() {
        let mut p = lines(16);
        write_all(&p.input, b"\xff\xfe\n").unwrap();
        drop(p.input);
        assert!(matches!(next(&mut p.lines).await, Line::Refused));
        assert_eq!(
            written(&p.diagnostics),
            "maknae: that line is not UTF-8 text and was not sent\n"
        );
        assert!(nothing_written(&p.output), "the refusal reached the output");
    }

    #[test]
    fn output_lines_are_escaped_for_display() {
        let mut p = lines(16);
        p.lines
            .write_line("#2 working \x1b[2J\u{202e}x\r\nnext")
            .unwrap();
        assert_eq!(
            written(&p.output),
            "#2 working \\u{001b}[2J\\u{202e}x\\u{000d}\nnext\n"
        );
    }

    #[tokio::test]
    async fn the_line_and_output_buffers_never_move_or_grow() {
        let Pipes {
            mut lines,
            input,
            output,
            diagnostics,
        } = lines(64);
        let (ptr, cap) = (lines.buf.as_ptr(), lines.buf.capacity());
        let out_ptr = lines.out.as_str().as_ptr();
        let writer = std::thread::spawn(move || {
            for _ in 0..200 {
                write_all(&input, &[b'y'; 100]).unwrap();
                write_all(&input, b"\nok\n").unwrap();
            }
        });
        let drains = [output, diagnostics].map(|from| {
            std::thread::spawn(move || {
                let mut chunk = [0u8; 4096];
                while let Ok(1..) = nix::unistd::read(&from, &mut chunk) {}
            })
        });
        let mut ok = 0;
        loop {
            match next(&mut lines).await {
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
        for drain in drains {
            drain.join().unwrap();
        }
    }
}
