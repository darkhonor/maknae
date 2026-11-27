use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::engine::GeneralPurpose;
use base64::Engine;
use zeroize::Zeroizing;

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
}
