use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::engine::GeneralPurpose;
use base64::Engine;
use std::cmp::Ordering;
use std::fmt;
use std::ops::{ControlFlow, Range};
use zeroize::Zeroizing;

use crate::credential::CredentialSlot;
use crate::secret::{MaknaeSecret, SecretBuf, MAX_SECRET_BYTES};

pub(crate) const MIN_VALUE: usize = 8;
pub(crate) const WHOLE_BELOW: usize = 16;
pub(crate) const MAX_ENCODED_VALUE: usize = 4096;

pub(crate) const RAW_WINDOW: usize = 16;
pub(crate) const PERCENT_WINDOW: usize = 16;
pub(crate) const BASE64_WINDOW: usize = 24;
pub(crate) const HEX_WINDOW: usize = 32;
pub(crate) const WINDOWS: [usize; 3] = [RAW_WINDOW, BASE64_WINDOW, HEX_WINDOW];

const MAX_FORMS: usize = 11;
const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";
const UPPER_HEX: &[u8; 16] = b"0123456789ABCDEF";

pub(crate) struct Form {
    pub(crate) bytes: Zeroizing<Vec<u8>>,
    pub(crate) window: usize,
}

pub(crate) fn forms(value: &[u8]) -> Vec<Form> {
    if value.len() < MIN_VALUE {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(MAX_FORMS);
    push(&mut out, Zeroizing::new(value.to_vec()), RAW_WINDOW);
    if value.len() < WHOLE_BELOW || value.len() > MAX_ENCODED_VALUE {
        return out;
    }
    for digits in [LOWER_HEX, UPPER_HEX] {
        push(&mut out, hex(value, digits), HEX_WINDOW);
    }
    for digits in [UPPER_HEX, LOWER_HEX] {
        push(&mut out, percent(value, digits), PERCENT_WINDOW);
    }
    for engine in [&STANDARD_NO_PAD, &URL_SAFE_NO_PAD] {
        for align in 0..3 {
            if let Some(b) = base64_at(value, engine, align) {
                push(&mut out, b, BASE64_WINDOW);
            }
        }
    }
    out
}

fn push(out: &mut Vec<Form>, bytes: Zeroizing<Vec<u8>>, window: usize) {
    if out.iter().any(|f| f.bytes == bytes) {
        return;
    }
    let window = if bytes.len() < window { 0 } else { window };
    out.push(Form { bytes, window });
}

fn hex(value: &[u8], digits: &[u8; 16]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(vec![0u8; value.len() * 2]);
    for (pair, &b) in out.as_chunks_mut::<2>().0.iter_mut().zip(value) {
        pair[0] = digits[usize::from(b >> 4)];
        pair[1] = digits[usize::from(b & 0x0f)];
    }
    out
}

fn unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'-')
}

fn percent(value: &[u8], digits: &[u8; 16]) -> Zeroizing<Vec<u8>> {
    let len = value
        .iter()
        .map(|&b| if unreserved(b) { 1 } else { 3 })
        .sum();
    let mut out = Zeroizing::new(vec![0u8; len]);
    let mut i = 0;
    for &b in value {
        if unreserved(b) {
            out[i] = b;
            i += 1;
        } else {
            out[i] = b'%';
            out[i + 1] = digits[usize::from(b >> 4)];
            out[i + 2] = digits[usize::from(b & 0x0f)];
            i += 3;
        }
    }
    out
}

fn base64_at(value: &[u8], engine: &GeneralPurpose, align: usize) -> Option<Zeroizing<Vec<u8>>> {
    let total = align + value.len();
    let mut input = Zeroizing::new(vec![0u8; total]);
    input[align..].copy_from_slice(value);
    let mut full = Zeroizing::new(vec![0u8; (4 * total).div_ceil(3)]);
    engine
        .encode_slice(input.as_slice(), full.as_mut_slice())
        .ok()?;
    let lead = (4 * align).div_ceil(3);
    let end = if total.is_multiple_of(3) {
        full.len()
    } else {
        full.len() - 1
    };
    Some(Zeroizing::new(full[lead..end].to_vec()))
}

pub(crate) struct Index {
    pub(crate) forms: Vec<Form>,
    pub(crate) sources: Vec<u32>,
    pub(crate) tables: [Zeroizing<Vec<(u32, u32)>>; 3],
}

pub(crate) fn build_index(values: &[&[u8]]) -> Index {
    let per_value: Vec<Vec<Form>> = values.iter().map(|v| forms(v)).collect();
    let total = per_value.iter().map(Vec::len).sum();
    let mut forms = Vec::with_capacity(total);
    let mut sources = Vec::with_capacity(total);
    for (source, value_forms) in per_value.into_iter().enumerate() {
        for form in value_forms {
            forms.push(form);
            sources.push(source as u32);
        }
    }
    let tables = WINDOWS.map(|w| table(&forms, &sources, w));
    Index {
        forms,
        sources,
        tables,
    }
}

fn window(forms: &[Form], (form, offset): (u32, u32), w: usize) -> &[u8] {
    let offset = offset as usize;
    &forms[form as usize].bytes[offset..offset + w]
}

fn table(forms: &[Form], sources: &[u32], w: usize) -> Zeroizing<Vec<(u32, u32)>> {
    let count = forms
        .iter()
        .filter(|f| f.window == w)
        .map(|f| f.bytes.len() - w + 1)
        .sum();
    let mut entries = Zeroizing::new(Vec::with_capacity(count));
    for (i, f) in forms.iter().enumerate() {
        if f.window == w {
            for offset in 0..=f.bytes.len() - w {
                entries.push((i as u32, offset as u32));
            }
        }
    }
    let source = |e: (u32, u32)| sources[e.0 as usize];
    entries.sort_unstable_by(|&a, &b| {
        window(forms, a, w)
            .cmp(window(forms, b, w))
            .then(source(a).cmp(&source(b)))
    });
    entries
        .dedup_by(|a, b| source(*a) == source(*b) && window(forms, *a, w) == window(forms, *b, w));
    entries
}

pub(crate) const MAX_VALUES: usize = 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Source {
    Slot(CredentialSlot),
    Label(&'static str),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FilterError {
    TooManyValues,
    ValueTooLong,
}

impl fmt::Display for FilterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FilterError::TooManyValues => write!(f, "more than {MAX_VALUES} values"),
            FilterError::ValueTooLong => write!(f, "a value longer than {MAX_SECRET_BYTES} bytes"),
        }
    }
}

impl std::error::Error for FilterError {}

pub struct ValueFilterBuilder<'a> {
    entries: Vec<(Source, &'a [u8])>,
}

pub struct ValueFilter {
    index: Index,
    sources: Vec<Source>,
    raw: Vec<usize>,
    whole: Vec<usize>,
    max_raw: usize,
    values: usize,
    skipped: usize,
}

struct Found {
    seen: Vec<bool>,
    order: Vec<u32>,
}

impl Found {
    fn new(sources: usize) -> Self {
        Found {
            seen: vec![false; sources],
            order: Vec::new(),
        }
    }

    fn add(&mut self, source: u32) {
        let seen = &mut self.seen[source as usize];
        if !*seen {
            *seen = true;
            self.order.push(source);
        }
    }
}

fn compare(a: &[u8], b: &[u8], work: &mut u64) -> Ordering {
    for (x, y) in a.iter().zip(b) {
        *work += 1;
        match x.cmp(y) {
            Ordering::Equal => {}
            other => return other,
        }
    }
    a.len().cmp(&b.len())
}

fn runs(coverage: &[bool]) -> Vec<(bool, Range<usize>)> {
    let mut at = 0;
    coverage
        .chunk_by(|a, b| a == b)
        .map(|run| {
            let range = at..at + run.len();
            at = range.end;
            (run[0], range)
        })
        .collect()
}

fn widen(s: &str, coverage: &mut [bool]) {
    for (covered, r) in runs(coverage) {
        if covered {
            coverage[s.floor_char_boundary(r.start)..s.ceil_char_boundary(r.end)].fill(true);
        }
    }
}

fn fall_back(pattern: &[u8], pi: &[u32], mut k: usize, c: u8, work: &mut u64) -> usize {
    for _ in 0..pattern.len() {
        if k == 0 || pattern[k] == c {
            break;
        }
        *work += 1;
        k = pi[k - 1] as usize;
    }
    k
}

fn prefix_function(pattern: &[u8], pi: &mut [u32], work: &mut u64) {
    let mut k = 0;
    for q in 1..pattern.len() {
        k = fall_back(pattern, pi, k, pattern[q], work);
        *work += 1;
        if pattern[k] == pattern[q] {
            k += 1;
        }
        pi[q] = k as u32;
    }
}

fn longest_prefix_suffix(pattern: &[u8], pi: &[u32], text: &[u8], work: &mut u64) -> usize {
    let mut k = 0;
    for &c in text {
        k = fall_back(pattern, pi, k, c, work);
        *work += 1;
        if pattern[k] == c {
            k += 1;
        }
    }
    k
}

impl ValueFilter {
    pub fn builder<'a>() -> ValueFilterBuilder<'a> {
        ValueFilterBuilder {
            entries: Vec::new(),
        }
    }

    pub fn mask_in_place(&self, buf: &mut [u8]) -> Vec<Source> {
        self.mask(buf, &mut 0)
    }

    #[cfg(test)]
    fn mask_in_place_with_work(&self, buf: &mut [u8]) -> (Vec<Source>, u64) {
        let mut work = 0;
        let found = self.mask(buf, &mut work);
        (found, work)
    }

    fn mask(&self, buf: &mut [u8], work: &mut u64) -> Vec<Source> {
        let mut coverage = vec![false; buf.len()];
        let mut found = Found::new(self.sources.len());
        let _ = self.scan(buf, work, |at, n, source| {
            coverage[at..at + n].fill(true);
            found.add(source);
            ControlFlow::Continue(())
        });
        self.tail(buf, work, |n, source| {
            let len = coverage.len();
            coverage[len - n..].fill(true);
            found.add(source);
        });
        for (b, &c) in buf.iter_mut().zip(&coverage) {
            if c {
                *b = b'*';
            }
        }
        found
            .order
            .iter()
            .map(|&s| self.sources[s as usize].clone())
            .collect()
    }

    pub fn matches(&self, bytes: &[u8]) -> bool {
        self.scan(bytes, &mut 0, |_, _, _| ControlFlow::Break(()))
            .is_break()
    }

    pub fn redact_text(&self, s: &str) -> String {
        let len = s.len();
        let mut coverage = vec![false; len];
        let _ = self.scan(s.as_bytes(), &mut 0, |at, n, _| {
            coverage[at..at + n].fill(true);
            ControlFlow::Continue(())
        });
        widen(s, &mut coverage);
        let mut out = String::with_capacity(len);
        for (covered, r) in runs(&coverage) {
            if covered {
                out.push_str("<redacted>");
            } else {
                out.push_str(&s[r]);
            }
        }
        out
    }

    pub fn skipped(&self) -> usize {
        self.skipped
    }

    pub fn is_empty(&self) -> bool {
        self.index.forms.is_empty()
    }

    fn scan(
        &self,
        buf: &[u8],
        work: &mut u64,
        mut hit: impl FnMut(usize, usize, u32) -> ControlFlow<()>,
    ) -> ControlFlow<()> {
        let forms = &self.index.forms;
        for at in 0..buf.len() {
            for (table, &w) in self.index.tables.iter().zip(&WINDOWS) {
                let Some(needle) = buf.get(at..at + w) else {
                    continue;
                };
                let lo = table.partition_point(|&entry| {
                    *work += 1;
                    compare(window(forms, entry, w), needle, work).is_lt()
                });
                for &entry in &table[lo..] {
                    if compare(window(forms, entry, w), needle, work).is_ne() {
                        break;
                    }
                    hit(at, w, self.index.sources[entry.0 as usize])?;
                }
            }
            for &f in &self.whole {
                let form = &forms[f].bytes;
                if let Some(candidate) = buf.get(at..at + form.len()) {
                    if compare(form, candidate, work).is_eq() {
                        hit(at, form.len(), self.index.sources[f])?;
                    }
                }
            }
        }
        ControlFlow::Continue(())
    }

    fn tail(&self, buf: &[u8], work: &mut u64, mut hit: impl FnMut(usize, u32)) {
        if buf.is_empty() || self.raw.is_empty() {
            return;
        }
        let mut pi = Zeroizing::new(vec![0u32; self.max_raw]);
        for &r in &self.raw {
            let form = self.index.forms[r].bytes.as_slice();
            let pi = &mut pi[..form.len()];
            prefix_function(form, pi, work);
            let text = &buf[buf.len().saturating_sub(form.len())..];
            let k = longest_prefix_suffix(form, pi, text, work);
            if k > 0 {
                hit(k, self.index.sources[r]);
            }
        }
    }
}

impl fmt::Debug for ValueFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ValueFilter({} values)", self.values)
    }
}

impl<'a> ValueFilterBuilder<'a> {
    pub fn secret<B: SecretBuf>(self, label: &'static str, s: &'a MaknaeSecret<B>) -> Self {
        self.source(Source::Label(label), s.bytes())
    }

    pub(crate) fn source(mut self, source: Source, bytes: &'a [u8]) -> Self {
        self.entries.push((source, bytes));
        self
    }

    pub fn build(self) -> Result<ValueFilter, FilterError> {
        if self.entries.len() > MAX_VALUES {
            return Err(FilterError::TooManyValues);
        }
        if self.entries.iter().any(|(_, b)| b.len() > MAX_SECRET_BYTES) {
            return Err(FilterError::ValueTooLong);
        }
        let values: Vec<&[u8]> = self.entries.iter().map(|&(_, b)| b).collect();
        let kept = values.iter().filter(|v| v.len() >= MIN_VALUE).count();
        let index = build_index(&values);
        let raw: Vec<usize> = (0..index.forms.len())
            .filter(|&i| i == 0 || index.sources[i] != index.sources[i - 1])
            .collect();
        let whole = (0..index.forms.len())
            .filter(|&i| index.forms[i].window == 0)
            .collect();
        let max_raw = raw
            .iter()
            .map(|&i| index.forms[i].bytes.len())
            .max()
            .unwrap_or(0);
        Ok(ValueFilter {
            index,
            sources: self.entries.into_iter().map(|(s, _)| s).collect(),
            raw,
            whole,
            max_raw,
            values: kept,
            skipped: values.len() - kept,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    use base64::Engine;

    fn token() -> Vec<u8> {
        let mut v = b"ghp_A1b2/C3d4+E5 f6:G7h8".to_vec();
        v.extend((0u8..16).map(|i| i.wrapping_mul(37).wrapping_add(200)));
        v
    }

    fn contains(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }

    fn hex(v: &[u8], upper: bool) -> Vec<u8> {
        v.iter()
            .flat_map(|b| {
                if upper {
                    format!("{b:02X}")
                } else {
                    format!("{b:02x}")
                }
                .into_bytes()
            })
            .collect()
    }

    fn percent(v: &[u8], upper: bool) -> Vec<u8> {
        v.iter()
            .flat_map(|&b| {
                if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'-') {
                    vec![b]
                } else if upper {
                    format!("%{b:02X}").into_bytes()
                } else {
                    format!("%{b:02x}").into_bytes()
                }
            })
            .collect()
    }

    fn trimmed_base64(v: &[u8], url: bool, a: usize) -> Vec<u8> {
        let mut input = vec![0u8; a];
        input.extend_from_slice(v);
        let full = if url {
            URL_SAFE_NO_PAD.encode(&input)
        } else {
            STANDARD_NO_PAD.encode(&input)
        }
        .into_bytes();
        let lead = (4 * a).div_ceil(3);
        let end = if (a + v.len()).is_multiple_of(3) {
            full.len()
        } else {
            full.len() - 1
        };
        full[lead..end].to_vec()
    }

    fn expected(v: &[u8]) -> Vec<(Vec<u8>, usize)> {
        let whole = |b: Vec<u8>, w: usize| {
            let win = if b.len() < w { 0 } else { w };
            (b, win)
        };
        let mut out = vec![whole(v.to_vec(), RAW_WINDOW)];
        out.push(whole(hex(v, false), HEX_WINDOW));
        out.push(whole(hex(v, true), HEX_WINDOW));
        for upper in [true, false] {
            let p = percent(v, upper);
            if p != v {
                out.push(whole(p, PERCENT_WINDOW));
            }
        }
        for url in [false, true] {
            for a in 0..3 {
                out.push(whole(trimmed_base64(v, url, a), BASE64_WINDOW));
            }
        }
        out.sort();
        out.dedup();
        out
    }

    fn actual(v: &[u8]) -> Vec<(Vec<u8>, usize)> {
        let mut out: Vec<_> = forms(v)
            .iter()
            .map(|f| (f.bytes.to_vec(), f.window))
            .collect();
        out.sort();
        out
    }

    fn window_count(idx: &Index, w: usize) -> usize {
        idx.forms
            .iter()
            .filter(|f| f.window == w)
            .map(|f| f.bytes.len() - w + 1)
            .sum()
    }

    fn entries(idx: &Index, t: usize) -> Vec<(&[u8], u32)> {
        let w = WINDOWS[t];
        idx.tables[t]
            .iter()
            .map(|&(f, o)| {
                let (f, o) = (f as usize, o as usize);
                (&idx.forms[f].bytes[o..o + w], idx.sources[f])
            })
            .collect()
    }

    #[test]
    fn forms_of_a_token_include_raw_hex_percent_and_base64() {
        let v = token();
        let got = actual(&v);
        let has = |b: &[u8]| got.iter().any(|(f, _)| f == b);
        assert!(has(&v));
        assert!(has(&hex(&v, false)));
        assert!(has(&hex(&v, true)));
        assert!(has(&percent(&v, true)));
        assert!(has(&percent(&v, false)));
        for url in [false, true] {
            for a in 0..3 {
                assert!(has(&trimmed_base64(&v, url, a)), "url={url} a={a}");
            }
        }
        assert_eq!(got, expected(&v));
        let mut distinct: Vec<_> = got.iter().map(|(f, _)| f.clone()).collect();
        distinct.dedup();
        assert_eq!(distinct.len(), got.len());
    }

    #[test]
    fn a_token_of_unreserved_bytes_has_no_percent_form() {
        let v = b"ghp_0123456789abcdefXYZ.~-_".to_vec();
        let got = actual(&v);
        assert_eq!(got.iter().filter(|(f, _)| f == &v).count(), 1);
        assert_eq!(got, expected(&v));
        assert!(!got.iter().any(|(f, _)| f.contains(&b'%')));
    }

    #[test]
    fn each_base64_alignment_finds_the_value_inside_a_larger_blob() {
        let v = token();
        let got = forms(&v);
        let b64: Vec<&[u8]> = got
            .iter()
            .filter(|f| f.window == BASE64_WINDOW)
            .map(|f| f.bytes.as_slice())
            .collect();
        for prefix in [&b":"[..], b"x:", b"xy:", b"user:", b"x-access-token:"] {
            for trailing in [&b""[..], b"@github.com", b"\n", b"z"] {
                let mut blob = prefix.to_vec();
                blob.extend_from_slice(&v);
                blob.extend_from_slice(trailing);
                for engine in [&STANDARD, &URL_SAFE, &STANDARD_NO_PAD, &URL_SAFE_NO_PAD] {
                    let enc = engine.encode(&blob).into_bytes();
                    assert!(
                        b64.iter().any(|f| contains(&enc, f)),
                        "prefix={prefix:?} trailing={trailing:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn a_value_under_eight_bytes_has_no_forms() {
        for n in [0usize, 1, 2, 3, 7] {
            assert!(forms(&vec![b'k'; n]).is_empty(), "{n}");
        }
        let short = vec![b'k'; 7];
        let idx = build_index(&[&short]);
        assert!(idx.forms.is_empty());
        assert!(idx.tables.iter().all(|t| t.is_empty()));
    }

    #[test]
    fn an_eight_to_fifteen_byte_value_has_only_its_raw_form() {
        for n in [8usize, 11, 15] {
            let v: Vec<u8> = (0..n).map(|i| b"a:/+ %"[i % 6]).collect();
            let got = forms(&v);
            assert_eq!(got.len(), 1, "{n}");
            assert_eq!(*got[0].bytes, v);
            assert_eq!(got[0].window, 0);
            let idx = build_index(&[&v]);
            assert_eq!(idx.forms.len(), 1);
            assert!(idx.tables.iter().all(|t| t.is_empty()), "{n}");
        }
    }

    #[test]
    fn every_form_has_its_window_length() {
        for v in [token(), vec![0xffu8; 40], b"0123456789abcdef".to_vec()] {
            let got = actual(&v);
            assert_eq!(got, expected(&v));
            assert!(got.iter().all(|(f, w)| !f.is_empty() && f.len() >= *w));
            assert!(got.iter().any(|(_, w)| *w == RAW_WINDOW));
            assert!(got.iter().any(|(_, w)| *w == HEX_WINDOW));
        }
        let v = token();
        let got = actual(&v);
        assert!(got.iter().all(|(_, w)| WINDOWS.contains(w)));
        assert_eq!(got.iter().filter(|(_, w)| *w == HEX_WINDOW).count(), 2);
        let mut b64: Vec<Vec<u8>> = [false, true]
            .iter()
            .flat_map(|&url| (0..3).map(move |a| (url, a)))
            .map(|(url, a)| trimmed_base64(&v, url, a))
            .collect();
        b64.sort();
        b64.dedup();
        assert!(b64.len() >= 3);
        assert_eq!(
            got.iter().filter(|(_, w)| *w == BASE64_WINDOW).count(),
            b64.len()
        );
        assert_eq!(got.iter().filter(|(_, w)| *w == RAW_WINDOW).count(), 3);
    }

    #[test]
    fn every_form_and_the_index_are_sized_exactly() {
        let a = token();
        let b = vec![b'q'; MAX_ENCODED_VALUE];
        let c = vec![b'w'; 11];
        for f in forms(&a).iter().chain(forms(&b).iter()) {
            assert_eq!(f.bytes.capacity(), f.bytes.len());
        }
        let idx = build_index(&[&a, &b, &c]);
        assert_eq!(idx.forms.capacity(), idx.forms.len());
        assert_eq!(idx.sources.capacity(), idx.sources.len());
        assert_eq!(idx.sources.len(), idx.forms.len());
        assert_eq!(
            idx.forms.len(),
            forms(&a).len() + forms(&b).len() + forms(&c).len()
        );
        for f in &idx.forms {
            assert_eq!(f.bytes.capacity(), f.bytes.len());
        }
        for (t, &w) in WINDOWS.iter().enumerate() {
            assert!(window_count(&idx, w) > 0);
            assert_eq!(idx.tables[t].capacity(), window_count(&idx, w), "{w}");
            assert!(idx.tables[t].len() <= idx.tables[t].capacity());
        }
    }

    #[test]
    fn a_value_over_4096_bytes_is_indexed_raw_only() {
        let big: Vec<u8> = (0..MAX_ENCODED_VALUE + 1)
            .map(|i| (i % 251) as u8)
            .collect();
        let got = forms(&big);
        assert_eq!(got.len(), 1);
        assert_eq!(*got[0].bytes, big);
        assert_eq!(got[0].window, RAW_WINDOW);
        let edge = &big[..MAX_ENCODED_VALUE];
        assert!(forms(edge).len() > 1);
        assert_eq!(actual(edge), expected(edge));
    }

    #[test]
    fn base64_of_sixteen_and_seventeen_byte_values_is_matched_whole_at_every_alignment() {
        for n in [16usize, 17] {
            let v: Vec<u8> = token()[..n].to_vec();
            let got = forms(&v);
            assert!(!got.iter().any(|f| f.window == BASE64_WINDOW), "{n}");
            for url in [false, true] {
                for a in 0..3 {
                    let t = trimmed_base64(&v, url, a);
                    assert!(t.len() < BASE64_WINDOW);
                    assert!(
                        got.iter().any(|f| f.window == 0 && *f.bytes == t),
                        "n={n} url={url} a={a}"
                    );
                }
            }
            for prefix in [&b":"[..], b"x:", b"xy:"] {
                for trailing in [&b""[..], b"@h"] {
                    let mut blob = prefix.to_vec();
                    blob.extend_from_slice(&v);
                    blob.extend_from_slice(trailing);
                    for engine in [&STANDARD, &URL_SAFE] {
                        let enc = engine.encode(&blob).into_bytes();
                        assert!(got
                            .iter()
                            .any(|f| f.window == 0 && contains(&enc, &f.bytes)));
                    }
                }
            }
        }
        let v18 = token()[..18].to_vec();
        assert!(forms(&v18).iter().any(|f| f.window == BASE64_WINDOW));
    }

    #[test]
    fn every_offset_of_every_windowed_form_is_indexed() {
        let lettered: Vec<u8> = (0xau8..=0xf)
            .flat_map(|hi| (0xau8..=0xf).map(move |lo| hi << 4 | lo))
            .collect();
        let twenty = lettered[..20].to_vec();
        for v in [lettered, twenty] {
            let idx = build_index(&[&v]);
            for (t, &w) in WINDOWS.iter().enumerate() {
                let mut all: Vec<&[u8]> = idx
                    .forms
                    .iter()
                    .filter(|f| f.window == w)
                    .flat_map(|f| f.bytes.windows(w))
                    .collect();
                all.sort();
                all.dedup();
                let mut held: Vec<&[u8]> = entries(&idx, t).into_iter().map(|(b, _)| b).collect();
                held.sort();
                assert_eq!(held, all, "w={w}");
                let mut checked = 0;
                for (i, f) in idx.forms.iter().enumerate() {
                    if f.window != w {
                        continue;
                    }
                    let shared = f.bytes.windows(w).any(|x| {
                        idx.forms.iter().enumerate().any(|(j, g)| {
                            j != i && g.window == w && g.bytes.windows(w).any(|y| y == x)
                        })
                    });
                    if shared {
                        continue;
                    }
                    checked += 1;
                    let mut offsets: Vec<u32> = idx.tables[t]
                        .iter()
                        .filter(|e| e.0 as usize == i)
                        .map(|e| e.1)
                        .collect();
                    offsets.sort_unstable();
                    let want: Vec<u32> = (0..=(f.bytes.len() - w) as u32).collect();
                    assert_eq!(offsets, want, "form {i} w={w}");
                }
                assert!(checked > 0, "w={w}");
            }
        }
    }

    #[test]
    fn the_index_holds_one_entry_per_distinct_window_and_source() {
        let a64 = vec![b'a'; 64];
        let idx = build_index(&[&a64]);
        assert_eq!(idx.tables[0].len(), 1);
        assert_eq!(idx.tables[2].len(), 2);
        assert!(!idx.tables[1].is_empty() && idx.tables[1].len() <= 4);

        let shared = b"0123456789abcdef";
        let mut x = shared.to_vec();
        x.extend_from_slice(b":XXXXXXXX");
        let mut y = shared.to_vec();
        y.extend_from_slice(b"YYYYYYYY");
        let idx = build_index(&[&x, &y, &x]);
        let hits: Vec<u32> = entries(&idx, 0)
            .into_iter()
            .filter(|(w, _)| *w == shared)
            .map(|(_, s)| s)
            .collect();
        assert_eq!(hits, vec![0, 1, 2]);

        for t in 0..3 {
            let e = entries(&idx, t);
            assert!(e.windows(2).all(|p| p[0] < p[1]), "table {t}");
        }
    }

    const TOKEN: &[u8; 64] = b"sk-ant-api03-Zq7/Lp+Xw:9Rt2Ks!Vb4Nm8Hc0Jd6Fg1Yh3Ue5Wi7Oa2Pl4Mn6B";
    const LABELS: [&str; 8] = ["v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7"];

    fn filter_of(values: &[&[u8]]) -> ValueFilter {
        let mut b = ValueFilter::builder();
        for (i, v) in values.iter().enumerate() {
            b = b.source(Source::Label(LABELS[i]), v);
        }
        b.build().unwrap()
    }

    fn masked(f: &ValueFilter, buf: &[u8]) -> (Vec<u8>, Vec<Source>) {
        let mut out = buf.to_vec();
        let found = f.mask_in_place(&mut out);
        assert_eq!(out.len(), buf.len());
        (out, found)
    }

    fn embed(form: &[u8]) -> Vec<u8> {
        [&b"<<"[..], form, b">>\n"].concat()
    }

    fn stars(n: usize) -> Vec<u8> {
        vec![b'*'; n]
    }

    fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
        hay.windows(needle.len()).position(|w| w == needle)
    }

    fn spoil(form: &[u8], step: usize) -> Vec<u8> {
        form.iter()
            .enumerate()
            .map(|(i, &b)| if i % step == step / 2 { b'#' } else { b })
            .collect()
    }

    fn v0() -> Vec<Source> {
        vec![Source::Label("v0")]
    }

    fn base64_blobs(v: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut out = Vec::new();
        for prefix in [&b":"[..], b"x:", b"xy:"] {
            for trailing in [&b""[..], b"@github.com"] {
                let plain = [prefix, v, trailing].concat();
                for (engine, url) in [(&STANDARD, false), (&URL_SAFE, true)] {
                    let blob = engine.encode(&plain).into_bytes();
                    out.push((blob, trimmed_base64(v, url, prefix.len() % 3)));
                }
            }
        }
        out
    }

    fn sample_buffers() -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for form in [
            TOKEN.to_vec(),
            hex(TOKEN, false),
            hex(TOKEN, true),
            percent(TOKEN, true),
            percent(TOKEN, false),
        ] {
            out.push(embed(&form));
            out.push(embed(&spoil(&form, 8)));
            out.push(embed(&form[20..36]));
            out.push(embed(&form[20..35]));
        }
        for (blob, _) in base64_blobs(TOKEN) {
            out.push(embed(&blob));
            out.push(embed(&spoil(&blob, 12)));
        }
        out.push(b"key=sk-ant-api03-\n".to_vec());
        out.push(embed(b"ghp_Qw3rTy8UiOpAsDfGhJkLzXcVbNm1234"));
        out
    }

    #[test]
    fn raw_and_every_encoding_is_masked_inside_a_larger_buffer() {
        for v in [&TOKEN[..], &TOKEN[..16], &TOKEN[..17]] {
            let f = filter_of(&[v]);
            for form in [
                v.to_vec(),
                hex(v, false),
                hex(v, true),
                percent(v, true),
                percent(v, false),
            ] {
                let (out, found) = masked(&f, &embed(&form));
                assert_eq!(out, embed(&stars(form.len())), "n={} {form:?}", v.len());
                assert_eq!(found, v0());
            }
            for (blob, trimmed) in base64_blobs(v) {
                let buf = embed(&blob);
                let (out, found) = masked(&f, &buf);
                let at = find(&buf, &trimmed).unwrap();
                assert_eq!(&out[at..at + trimmed.len()], &stars(trimmed.len())[..]);
                assert!(out.starts_with(b"<<") && out.ends_with(b">>\n"));
                assert_eq!(found, v0(), "n={} {blob:?}", v.len());
            }
        }
    }

    #[test]
    fn a_near_miss_of_each_encoding_is_untouched() {
        let f = filter_of(&[TOKEN]);
        for (form, step) in [
            (TOKEN.to_vec(), 8),
            (hex(TOKEN, false), 16),
            (hex(TOKEN, true), 16),
            (percent(TOKEN, true), 8),
            (percent(TOKEN, false), 8),
        ] {
            let buf = embed(&spoil(&form, step));
            assert_eq!(masked(&f, &buf), (buf.clone(), vec![]));
            assert!(!f.matches(&buf));
        }
        for (blob, _) in base64_blobs(TOKEN) {
            let buf = embed(&spoil(&blob, 12));
            assert_eq!(masked(&f, &buf), (buf.clone(), vec![]));
        }
        let short = filter_of(&[&TOKEN[..16]]);
        for (blob, _) in base64_blobs(&TOKEN[..16]) {
            let buf = embed(&spoil(&blob, blob.len()));
            assert_eq!(masked(&short, &buf), (buf.clone(), vec![]), "{blob:?}");
        }
    }

    #[test]
    fn a_window_from_the_middle_is_masked_and_one_byte_less_is_not() {
        let f = filter_of(&[TOKEN]);
        for (form, w) in [
            (TOKEN.to_vec(), 16),
            (hex(TOKEN, false), 32),
            (hex(TOKEN, true), 32),
            (trimmed_base64(TOKEN, false, 0), 24),
            (trimmed_base64(TOKEN, true, 1), 24),
        ] {
            let mid = form.len() / 2 - w / 2;
            let (out, found) = masked(&f, &embed(&form[mid..mid + w]));
            assert_eq!(out, embed(&stars(w)), "w={w}");
            assert_eq!(found, v0());
            let short = embed(&form[mid..mid + w - 1]);
            assert_eq!(masked(&f, &short), (short.clone(), vec![]), "w={w}");
            assert!(!f.matches(&short));
        }
    }

    #[test]
    fn a_public_prefix_alone_is_not_masked() {
        let f = filter_of(&[TOKEN]);
        let prefix = b"sk-ant-api03-";
        for buf in [
            b"key=sk-ant-api03-\n".to_vec(),
            embed(&hex(prefix, false)),
            embed(&hex(prefix, true)),
        ] {
            assert_eq!(masked(&f, &buf), (buf.clone(), vec![]));
            assert!(!f.matches(&buf));
        }
    }

    #[test]
    fn a_truncated_tail_is_masked() {
        let f = filter_of(&[TOKEN]);
        for n in [1, 32, 63, 64] {
            let buf = [&b"out: "[..], &TOKEN[..n]].concat();
            let (out, found) = masked(&f, &buf);
            assert_eq!(out, [&b"out: "[..], &stars(n)].concat(), "n={n}");
            assert_eq!(found, v0());
            assert_eq!(f.matches(&buf), n >= 16, "n={n}");
        }
        let v = b"abcabcabcabcabcabcabQQQQ";
        let f = filter_of(&[v]);
        let (out, _) = masked(&f, b"zzabcabca");
        assert_eq!(out, b"zz*******");
        let (out, _) = masked(&f, b"abcabcabcabcabcabcabQQQQ");
        assert_eq!(out, stars(v.len()));
        let (out, _) = masked(&f, b"abcabcabcabcabcabcabQQQQabcabcab");
        assert_eq!(out, stars(32));
        let f = filter_of(&[b"aaabXXXXXXXXXXXXXXXX"]);
        let (out, found) = masked(&f, b"zzaaaab");
        assert_eq!(out, b"zza****");
        assert_eq!(found, v0());
    }

    #[test]
    fn overlapping_and_adjacent_echoes_are_all_masked() {
        let x: &[u8] = TOKEN;
        let y = [&TOKEN[40..], b"-the-second-value-continues"].concat();
        let f = filter_of(&[x, &y]);
        let buf = [&b"<<"[..], x, &y[24..], x, x, b">>\n"].concat();
        let (out, found) = masked(&f, &buf);
        assert_eq!(out, embed(&stars(buf.len() - 5)));
        assert_eq!(found, vec![Source::Label("v0"), Source::Label("v1")]);

        let buf = [&b"<<"[..], &y[24..], x, b">>\n"].concat();
        let (out, found) = masked(&f, &buf);
        assert_eq!(out, embed(&stars(buf.len() - 5)));
        assert_eq!(found, vec![Source::Label("v1"), Source::Label("v0")]);
    }

    #[test]
    fn a_value_never_given_is_untouched() {
        let f = filter_of(&[TOKEN]);
        let other = b"ghp_Qw3rTy8UiOpAsDfGhJkLzXcVbNm1234567890abcdefghijklmnopqrstuvw";
        for buf in [
            embed(other),
            embed(&hex(other, false)),
            embed(&spoil(TOKEN, 8)),
        ] {
            assert_eq!(masked(&f, &buf), (buf.clone(), vec![]));
            assert!(!f.matches(&buf));
        }
    }

    #[test]
    fn masking_never_changes_the_length() {
        let f = filter_of(&[TOKEN, &TOKEN[..12]]);
        for buf in sample_buffers() {
            let mut b = buf.clone();
            f.mask_in_place(&mut b);
            assert_eq!(b.len(), buf.len());
            assert!(b.iter().zip(&buf).all(|(m, o)| m == o || *m == b'*'));
        }
        let mut empty: [u8; 0] = [];
        assert!(f.mask_in_place(&mut empty).is_empty());
    }

    #[test]
    fn matches_agrees_with_mask_in_place_without_a_tail() {
        let f = filter_of(&[TOKEN]);
        let mut hits = 0;
        for buf in sample_buffers() {
            let (out, found) = masked(&f, &buf);
            assert_eq!(f.matches(&buf), !found.is_empty(), "{buf:?}");
            assert_eq!(found.is_empty(), out == buf);
            hits += usize::from(!found.is_empty());
        }
        assert!(hits > 5);
    }

    #[test]
    fn redact_text_widens_a_straddling_fragment_to_whole_characters() {
        let secret = "é0123456789abcdeéfghijklmnopqrstuvwxyz";
        let f = filter_of(&[secret.as_bytes()]);
        let start = format!("pre ĩ{}", &secret[2..]);
        assert_eq!(f.redact_text(&start), "pre <redacted>");
        let end = format!("{}èpost", &secret[..17]);
        assert_eq!(f.redact_text(&end), "<redacted>post");
        let both = format!("a {secret} b {secret}{secret} c");
        assert_eq!(f.redact_text(&both), "a <redacted> b <redacted> c");
        assert_eq!(f.redact_text("nothing here"), "nothing here");
    }

    #[test]
    fn redact_text_output_holds_no_indexed_window_of_any_form() {
        let short = "0123456789:abcd";
        let f = filter_of(&[TOKEN, &TOKEN[..17], short.as_bytes()]);
        let mut text = String::from("start ");
        for v in [&TOKEN[..], &TOKEN[..17], short.as_bytes()] {
            for form in [v.to_vec(), hex(v, false), hex(v, true), percent(v, true)] {
                text.push_str(std::str::from_utf8(&form).unwrap());
                text.push_str(" | ");
            }
            for (blob, _) in base64_blobs(v) {
                text.push_str(std::str::from_utf8(&blob).unwrap());
                text.push(' ');
            }
        }
        text.push_str("end");
        let out = f.redact_text(&text);
        assert!(out.starts_with("start ") && out.ends_with("end"));
        assert!(out.contains("<redacted>"));
        for form in &f.index.forms {
            let w = if form.window == 0 {
                form.bytes.len()
            } else {
                form.window
            };
            for win in form.bytes.windows(w) {
                assert!(find(out.as_bytes(), win).is_none(), "{win:?}");
            }
        }
    }

    #[test]
    fn a_value_under_eight_bytes_is_skipped_and_counted() {
        let tiny: [&[u8]; 4] = [b"k", b"ke", b"key", b"keyword"];
        let f = filter_of(&tiny);
        assert_eq!(f.skipped(), 4);
        assert!(f.is_empty());
        assert_eq!(format!("{f:?}"), "ValueFilter(0 values)");
        let buf = b"k ke key keyword\n".to_vec();
        assert_eq!(masked(&f, &buf), (buf.clone(), vec![]));
        assert!(!f.matches(&buf));
        assert_eq!(f.redact_text("k ke key keyword"), "k ke key keyword");

        let eight = b"Pa55w0rd";
        let fifteen = &b"Fifteen:bytes!!"[..];
        let f = filter_of(&[b"k", eight, fifteen]);
        assert_eq!(f.skipped(), 1);
        assert!(!f.is_empty());
        for (v, label) in [(&eight[..], "v1"), (fifteen, "v2")] {
            let (out, found) = masked(&f, &embed(v));
            assert_eq!(out, embed(&stars(v.len())));
            assert_eq!(found, vec![Source::Label(label)]);
            let near = embed(&v[..v.len() - 1]);
            assert_eq!(masked(&f, &near), (near.clone(), vec![]));
            assert!(!f.matches(&near));
        }
    }

    #[test]
    fn exactly_max_values_builds_and_one_more_is_refused() {
        let values: Vec<Vec<u8>> = (0..=MAX_VALUES)
            .map(|i| format!("val{i:05}").into_bytes())
            .collect();
        let build = |n: usize| {
            let mut b = ValueFilter::builder();
            for v in &values[..n] {
                b = b.source(Source::Label("bulk"), v);
            }
            b.build()
        };
        let f = build(MAX_VALUES).unwrap();
        assert_eq!(f.skipped(), 0);
        assert_eq!(
            format!("{f:?}"),
            format!("ValueFilter({MAX_VALUES} values)")
        );
        assert!(f.matches(&embed(&values[0])));
        assert!(f.matches(&embed(&values[MAX_VALUES - 1])));
        assert_eq!(
            build(MAX_VALUES + 1).unwrap_err(),
            FilterError::TooManyValues
        );
    }

    #[test]
    fn a_value_of_max_secret_bytes_builds_and_one_byte_more_is_refused() {
        let v: Vec<u8> = (0..=MAX_SECRET_BYTES).map(|i| (i % 251) as u8).collect();
        let f = ValueFilter::builder()
            .source(Source::Label("big"), &v[..MAX_SECRET_BYTES])
            .build()
            .unwrap();
        assert_eq!(f.skipped(), 0);
        assert!(f.matches(&v[MAX_SECRET_BYTES - 16..MAX_SECRET_BYTES]));
        let refused = ValueFilter::builder()
            .source(Source::Label("small"), TOKEN)
            .source(Source::Label("big"), &v)
            .build();
        assert_eq!(refused.unwrap_err(), FilterError::ValueTooLong);
    }

    #[test]
    fn a_filter_error_names_the_bound_and_never_a_value() {
        assert_eq!(
            FilterError::TooManyValues.to_string(),
            "more than 1024 values"
        );
        assert_eq!(
            FilterError::ValueTooLong.to_string(),
            "a value longer than 65536 bytes"
        );
    }

    #[test]
    fn a_secret_is_read_through_the_builder() {
        let s = MaknaeSecret::new(Zeroizing::new(String::from("hunter2-but-longer"))).unwrap();
        let b = MaknaeSecret::new(Zeroizing::new(TOKEN.to_vec())).unwrap();
        let t = MaknaeSecret::new(Zeroizing::new(String::from("abc"))).unwrap();
        let f = ValueFilter::builder()
            .secret("pw", &s)
            .secret("tok", &b)
            .secret("tiny", &t)
            .build()
            .unwrap();
        assert_eq!(f.skipped(), 1);
        let (out, found) = masked(&f, &embed(b"hunter2-but-longer"));
        assert_eq!(out, embed(&stars(18)));
        assert_eq!(found, vec![Source::Label("pw")]);
        assert_eq!(masked(&f, &embed(TOKEN)).1, vec![Source::Label("tok")]);
    }

    #[test]
    fn debug_shows_only_the_count() {
        let f = filter_of(&[TOKEN, b"Pa55w0rd", b"k"]);
        let shown = format!("{f:?}");
        assert_eq!(shown, "ValueFilter(2 values)");
        assert_eq!(format!("{f:#?}"), shown);
    }

    const WORK_C: u64 = 16;
    const MIB: usize = 1 << 20;

    fn work_bound(f: &ValueFilter, n: usize) -> u64 {
        let m: usize = f.index.tables.iter().map(|t| t.len()).sum::<usize>() + f.index.forms.len();
        let log_m = u64::from(m.max(2).next_power_of_two().ilog2());
        WORK_C * n as u64 * log_m
    }

    fn repeat_to(unit: &[u8], n: usize) -> Vec<u8> {
        unit.iter().copied().cycle().take(n).collect()
    }

    #[test]
    fn a_value_repeated_to_a_mebibyte_costs_linear_work() {
        let f = filter_of(&[TOKEN]);
        let mut buf = repeat_to(TOKEN, MIB);
        let (found, work) = f.mask_in_place_with_work(&mut buf);
        assert_eq!(found, v0());
        assert!(buf.iter().all(|&b| b == b'*'));
        let bound = work_bound(&f, MIB);
        eprintln!("repeated token: work={work} bound={bound}");
        assert!(work > MIB as u64);
        assert!(work <= bound, "work={work} bound={bound}");
    }

    #[test]
    fn a_run_of_one_byte_against_a_run_value_costs_linear_work() {
        let v = vec![b'a'; MAX_ENCODED_VALUE];
        let f = filter_of(&[&v]);
        let mut buf = vec![b'a'; MIB];
        let (found, work) = f.mask_in_place_with_work(&mut buf);
        assert_eq!(found, v0());
        assert!(buf.iter().all(|&b| b == b'*'));
        let bound = work_bound(&f, MIB);
        eprintln!("run of a: work={work} bound={bound}");
        assert!(work > MIB as u64);
        assert!(work <= bound, "work={work} bound={bound}");
    }

    #[test]
    fn a_near_whole_short_value_repeated_costs_linear_work() {
        let v = b"Fifteen:bytes!!";
        assert_eq!(v.len(), 15);
        let f = filter_of(&[v]);
        let mut buf = repeat_to(&v[..14], MIB);
        let (_, work) = f.mask_in_place_with_work(&mut buf);
        assert!(buf[..MIB - v.len()].iter().all(|&b| b != b'*'));
        let bound = work_bound(&f, MIB);
        eprintln!("near-whole short: work={work} bound={bound}");
        assert!(work > MIB as u64);
        assert!(work <= bound, "work={work} bound={bound}");
    }

    #[test]
    fn runs_group_equal_neighbours_with_their_ranges() {
        assert!(runs(&[]).is_empty());
        assert_eq!(runs(&[false]), vec![(false, 0..1)]);
        assert_eq!(
            runs(&[true, true, false, true]),
            vec![(true, 0..2), (false, 2..3), (true, 3..4)]
        );
        assert_eq!(
            runs(&[false, false, false, true, true, false]),
            vec![(false, 0..3), (true, 3..5), (false, 5..6)]
        );
    }

    #[test]
    fn widen_reaches_the_boundaries_of_every_straddled_character() {
        let s = "a😀bé€c";
        assert_eq!(s.len(), 12);
        let widened = |covered: &[usize]| {
            let mut coverage = vec![false; s.len()];
            for &i in covered {
                coverage[i] = true;
            }
            widen(s, &mut coverage);
            runs(&coverage)
                .into_iter()
                .filter(|(c, _)| *c)
                .map(|(_, r)| r)
                .collect::<Vec<_>>()
        };
        for i in 1..5 {
            assert_eq!(widened(&[i]), vec![1..5], "4-byte at {i}");
        }
        for i in 6..8 {
            assert_eq!(widened(&[i]), vec![6..8], "2-byte at {i}");
        }
        for i in 8..11 {
            assert_eq!(widened(&[i]), vec![8..11], "3-byte at {i}");
        }
        assert_eq!(widened(&[0]), vec![0..1]);
        assert_eq!(widened(&[5]), vec![5..6]);
        assert_eq!(widened(&[11]), vec![11..12]);
        assert_eq!(widened(&[4, 5, 6]), vec![1..8]);
        assert_eq!(widened(&[2, 9]), vec![1..5, 8..11]);
        assert_eq!(widened(&[]), Vec::<Range<usize>>::new());
    }

    fn pi_of(pattern: &[u8]) -> Vec<u32> {
        let mut pi = vec![0u32; pattern.len()];
        prefix_function(pattern, &mut pi, &mut 0);
        pi
    }

    #[test]
    fn prefix_function_matches_the_textbook_tables() {
        assert_eq!(pi_of(b"aabaaab"), vec![0, 1, 0, 1, 2, 2, 3]);
        assert_eq!(pi_of(b"abcabcab"), vec![0, 0, 0, 1, 2, 3, 4, 5]);
        assert_eq!(pi_of(b"abacabab"), vec![0, 0, 1, 0, 1, 2, 3, 2]);
        assert_eq!(pi_of(b"aaaa"), vec![0, 1, 2, 3]);
        assert_eq!(pi_of(b"abcd"), vec![0, 0, 0, 0]);
        assert_eq!(pi_of(b"x"), vec![0]);
    }

    #[test]
    fn fall_back_follows_the_prefix_chain_to_a_continuable_state() {
        let p = b"abacabab";
        let pi = pi_of(p);
        assert_eq!(fall_back(p, &pi, 0, b'z', &mut 0), 0);
        assert_eq!(fall_back(p, &pi, 7, b'b', &mut 0), 7);
        assert_eq!(fall_back(p, &pi, 7, b'c', &mut 0), 3);
        assert_eq!(fall_back(p, &pi, 7, b'a', &mut 0), 0);
        let q = b"aabaaab";
        let pi = pi_of(q);
        assert_eq!(fall_back(q, &pi, 5, b'b', &mut 0), 2);
        assert_eq!(fall_back(q, &pi, 6, b'a', &mut 0), 1);
        assert_eq!(fall_back(q, &pi, 6, b'z', &mut 0), 0);
    }

    #[test]
    fn longest_prefix_suffix_finds_the_longest_overlap() {
        let lps = |p: &[u8], t: &[u8]| longest_prefix_suffix(p, &pi_of(p), t, &mut 0);
        assert_eq!(lps(b"aaabXXXX", b"zaaab"), 4);
        assert_eq!(lps(b"aaabXXXX", b"aaaa"), 3);
        assert_eq!(lps(b"abcabd", b"cabcab"), 5);
        assert_eq!(lps(b"abacabab", b"abacaba"), 7);
        assert_eq!(lps(b"abacabab", b"xabacab"), 6);
        assert_eq!(lps(b"abacabab", b"abacabab"), 8);
        assert_eq!(lps(b"abcd", b"xyzw"), 0);
        assert_eq!(lps(b"abcd", b""), 0);
    }

    #[test]
    fn the_tail_counts_each_compare_and_each_fallback_step() {
        let count_pi = |p: &[u8]| {
            let mut pi = vec![0u32; p.len()];
            let mut work = 0;
            prefix_function(p, &mut pi, &mut work);
            work
        };
        assert_eq!(count_pi(b"aabaaab"), 8);
        assert_eq!(count_pi(b"abacabab"), 9);
        assert_eq!(count_pi(b"aaaa"), 3);
        let count_lps = |p: &[u8], t: &[u8]| {
            let mut work = 0;
            let k = longest_prefix_suffix(p, &pi_of(p), t, &mut work);
            (k, work)
        };
        assert_eq!(count_lps(b"aaabXXXX", b"aaaa"), (3, 5));
        assert_eq!(count_lps(b"aaabXXXX", b"zaaab"), (4, 5));
        assert_eq!(count_lps(b"abacabab", b"xabacab"), (6, 7));
        let q = b"aabaaab";
        let mut work = 0;
        assert_eq!(fall_back(q, &pi_of(q), 6, b'a', &mut work), 1);
        assert_eq!(work, 2);
    }
}
