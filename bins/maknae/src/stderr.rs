//! Best-effort stderr writes. A closed or full stderr must not abort the
//! process: `eprintln!` panics on a write error, and the exit code is the
//! CLI's verdict.

pub(crate) fn line(err: &mut impl std::io::Write, args: std::fmt::Arguments<'_>) {
    let _ = err.write_all(format!("{args}\n").as_bytes());
}

pub(crate) fn raw(err: &mut impl std::io::Write, bytes: &[u8]) {
    let _ = err.write_all(bytes);
}

macro_rules! errln {
    ($($t:tt)*) => {
        $crate::stderr::line(&mut std::io::stderr(), format_args!($($t)*))
    };
}
pub(crate) use errln;

#[cfg(test)]
mod tests {
    use super::*;

    struct Failing;
    impl std::io::Write for Failing {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_line_write_to_a_failing_writer_does_not_panic() {
        line(&mut Failing, format_args!("x {}", 1));
    }

    #[test]
    fn a_raw_write_to_a_failing_writer_does_not_panic() {
        raw(&mut Failing, b"x");
    }

    #[test]
    fn a_line_write_ends_with_one_newline() {
        let mut out = vec![];
        line(&mut out, format_args!("a {}", 1));
        assert_eq!(out, b"a 1\n");
    }

    #[derive(Default)]
    struct Counting {
        writes: usize,
        bytes: Vec<u8>,
    }
    impl std::io::Write for Counting {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.writes += 1;
            self.bytes.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_line_is_one_write() {
        let mut out = Counting::default();
        line(&mut out, format_args!("a {} b {}", 1, "c"));
        assert_eq!((out.writes, out.bytes.as_slice()), (1, &b"a 1 b c\n"[..]));
    }

    #[test]
    fn a_raw_write_adds_no_newline() {
        let mut out = vec![];
        raw(&mut out, b"a\xffb");
        assert_eq!(out, b"a\xffb");
    }
}
