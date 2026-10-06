//! Backward line scan over a positioned reader: the rollback-anchor lookup of
//! ADR-0029 (#488). Newest line first, no total cap; `scanned_bytes` reports
//! what the lookup cost.
use std::io;
use std::num::NonZeroUsize;

pub const SCAN_WINDOW: usize = 1 << 20;

#[derive(Debug, PartialEq, Eq)]
pub struct ScanResult {
    pub line: Option<Vec<u8>>,
    pub scanned_bytes: u64,
}

pub fn scan_back(
    len: u64,
    read_at: impl FnMut(u64, &mut [u8]) -> io::Result<usize>,
    find: impl FnMut(&[u8]) -> bool,
) -> io::Result<ScanResult> {
    const WINDOW: NonZeroUsize = NonZeroUsize::new(SCAN_WINDOW).unwrap();
    scan_back_with_window(WINDOW, len, read_at, find)
}

pub(crate) fn scan_back_with_window(
    window: NonZeroUsize,
    len: u64,
    mut read_at: impl FnMut(u64, &mut [u8]) -> io::Result<usize>,
    mut find: impl FnMut(&[u8]) -> bool,
) -> io::Result<ScanResult> {
    let window = window.get() as u64;
    // The bytes from the current window's end up to the oldest newline already
    // seen: a line whose start lies in an older window.
    let mut carry: Vec<u8> = Vec::new();
    let mut scanned_bytes = 0u64;
    for k in 0..len.div_ceil(window) {
        let end = len - k * window;
        let start = end.saturating_sub(window);
        let mut buf = vec![0u8; (end - start) as usize];
        read_exact_at(&mut read_at, start, &mut buf)?;
        scanned_bytes += end - start;
        buf.extend_from_slice(&carry);
        let mut hi = buf.len();
        while let Some(nl) = buf[..hi].iter().rposition(|b| *b == b'\n') {
            let line = &buf[nl + 1..hi];
            if !line.is_empty() && find(line) {
                return Ok(ScanResult {
                    line: Some(line.to_vec()),
                    scanned_bytes,
                });
            }
            hi = nl;
        }
        buf.truncate(hi);
        carry = buf;
    }
    let line = (!carry.is_empty() && find(&carry)).then_some(carry);
    Ok(ScanResult {
        line,
        scanned_bytes,
    })
}

fn read_exact_at(
    read_at: &mut impl FnMut(u64, &mut [u8]) -> io::Result<usize>,
    mut offset: u64,
    mut rest: &mut [u8],
) -> io::Result<()> {
    while !rest.is_empty() {
        let n = read_at(offset, rest)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "audit file shorter than its length during backward scan",
            ));
        }
        rest = &mut rest[n..];
        offset += n as u64;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &[u8] =
        b"first\nsecond-line\n\nthird is a longer line than most\nx\nfifth\nsixth-and-final-line\n";

    fn w(n: usize) -> NonZeroUsize {
        NonZeroUsize::new(n).unwrap()
    }

    // The call budget turns a non-advancing read loop into a failure, not a hang.
    fn reader(data: &[u8], max: usize) -> impl FnMut(u64, &mut [u8]) -> io::Result<usize> + '_ {
        let mut budget = 2 * data.len() + 8;
        move |off, buf| {
            budget = budget.checked_sub(1).expect("read loop does not advance");
            let off = off as usize;
            let n = buf.len().min(max).min(data.len().saturating_sub(off));
            buf[..n].copy_from_slice(&data[off..off + n]);
            Ok(n)
        }
    }

    fn lines_with_offsets(data: &[u8]) -> Vec<(usize, &[u8])> {
        let mut out = Vec::new();
        let mut start = 0;
        for (i, b) in data.iter().enumerate() {
            if *b == b'\n' {
                if i > start {
                    out.push((start, &data[start..i]));
                }
                start = i + 1;
            }
        }
        if start < data.len() {
            out.push((start, &data[start..]));
        }
        out
    }

    fn expected_scanned(len: usize, line_start: usize, window: usize) -> u64 {
        if line_start == 0 {
            return len as u64;
        }
        let need = len - (line_start - 1);
        (need.div_ceil(window) * window).min(len) as u64
    }

    fn sweep(data: &[u8]) {
        let lines = lines_with_offsets(data);
        for window in 1..=64 {
            for max in [usize::MAX, 3] {
                let mut seen = Vec::new();
                let none =
                    scan_back_with_window(w(window), data.len() as u64, reader(data, max), |l| {
                        seen.push(l.to_vec());
                        false
                    })
                    .unwrap();
                assert_eq!(none.line, None, "window {window}");
                assert_eq!(none.scanned_bytes, data.len() as u64, "window {window}");
                let expected: Vec<Vec<u8>> = lines.iter().rev().map(|(_, l)| l.to_vec()).collect();
                assert_eq!(seen, expected, "window {window} max {max}");

                for (start, target) in &lines {
                    let got = scan_back_with_window(
                        w(window),
                        data.len() as u64,
                        reader(data, max),
                        |l| l == *target,
                    )
                    .unwrap();
                    assert_eq!(got.line.as_deref(), Some(*target), "window {window}");
                    assert_eq!(
                        got.scanned_bytes,
                        expected_scanned(data.len(), *start, window),
                        "window {window} line at {start}"
                    );
                }
            }
        }
    }

    #[test]
    fn every_window_size_finds_every_line_across_boundaries() {
        sweep(FIXTURE);
    }

    #[test]
    fn a_torn_terminal_line_is_offered_first() {
        sweep(b"alpha\nbeta\ntorn-tail");
    }

    #[test]
    fn a_leading_blank_line_is_never_offered() {
        sweep(b"\nleading-blank\n\n");
    }

    #[test]
    fn a_file_without_any_newline_is_one_line() {
        sweep(b"only-one-line");
    }

    #[test]
    fn the_newest_of_two_equal_lines_is_returned_first() {
        let data = b"match\nmid\nmatch\nend\n";
        let mut calls = 0;
        let got = scan_back_with_window(w(4), data.len() as u64, reader(data, usize::MAX), |l| {
            calls += 1;
            l == b"match"
        })
        .unwrap();
        assert_eq!(got.line.as_deref(), Some(&b"match"[..]));
        assert_eq!(calls, 2);
        assert_eq!(got.scanned_bytes, 12);
    }

    #[test]
    fn an_empty_file_reads_nothing() {
        let got =
            scan_back_with_window(w(8), 0, |_, _| panic!("no read expected"), |_| true).unwrap();
        assert_eq!(
            got,
            ScanResult {
                line: None,
                scanned_bytes: 0
            }
        );
    }

    #[test]
    fn a_zero_read_before_the_known_length_is_an_error() {
        let data = b"abc\ndef\n";
        let err = scan_back_with_window(w(64), 12, reader(data, usize::MAX), |_| false);
        let err = match err {
            Err(e) => e,
            Ok(r) => panic!("{r:?}"),
        };
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn a_read_error_propagates() {
        let err = scan_back_with_window(
            w(64),
            8,
            |_, _| Err(io::Error::from(io::ErrorKind::PermissionDenied)),
            |_| true,
        )
        .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn scan_back_uses_the_one_mebibyte_window() {
        assert_eq!(SCAN_WINDOW, 1 << 20);
        let mut data = vec![b'a'; SCAN_WINDOW];
        data.extend_from_slice(b"\nb\n");
        let mut reads = Vec::new();
        let got = scan_back(
            data.len() as u64,
            |off, buf: &mut [u8]| {
                reads.push((off, buf.len()));
                reader(&data, usize::MAX)(off, buf)
            },
            |l| l == b"b",
        )
        .unwrap();
        assert_eq!(got.line.as_deref(), Some(&b"b"[..]));
        assert_eq!(reads, vec![(3, SCAN_WINDOW)]);
        assert_eq!(got.scanned_bytes, SCAN_WINDOW as u64);
    }
}
