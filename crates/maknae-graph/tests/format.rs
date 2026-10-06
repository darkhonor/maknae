mod common;

use common::*;
use maknae_graph::format::*;
use maknae_graph::graph::{GraphBuilder, GraphError};
use maknae_graph::kernel::*;
use maknae_graph::record::*;

fn valid() -> Vec<u8> {
    encode(&builder().build(&SCHEMA, &compiled()).unwrap())
}

fn dec(b: &[u8]) -> Result<maknae_graph::graph::Graph, FormatError> {
    decode(b, &SCHEMA, &compiled())
}

fn put_u16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}
fn put_u32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
fn put_u64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}
fn get_u64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}
fn section(b: &[u8], i: usize) -> (usize, usize) {
    let at = HEADER_LEN + i * 16;
    (get_u64(b, at) as usize, get_u64(b, at + 8) as usize)
}
/// Inserts `extra` at the end of section `i`, fixing up every later offset and this section's length.
fn grow_section(b: &[u8], i: usize, extra: &[u8]) -> Vec<u8> {
    let (off, len) = section(b, i);
    let mut out = b[..off + len].to_vec();
    out.extend_from_slice(extra);
    out.extend_from_slice(&b[off + len..]);
    put_u64(
        &mut out,
        HEADER_LEN + i * 16 + 8,
        (len + extra.len()) as u64,
    );
    for j in i + 1..SECTION_COUNT {
        let at = HEADER_LEN + j * 16;
        let o = get_u64(&out, at);
        put_u64(&mut out, at, o + extra.len() as u64);
    }
    out
}
fn first_node(b: &[u8]) -> usize {
    section(b, 1).0 + 4
}
fn first_edge(b: &[u8]) -> usize {
    section(b, 2).0 + 4
}
fn first_attr(b: &[u8]) -> usize {
    section(b, 6).0 + 4
}

#[test]
fn layout_constants_are_pinned() {
    assert_eq!((HEADER_LEN, SECTION_COUNT, SECTIONS_START), (40, 7, 152));
    assert_eq!((NODE_LEN, EDGE_LEN, KEY_LEN, ATTR_LEN), (56, 72, 12, 16));
    assert_eq!(MAGIC, *b"MKNG");
    assert_eq!(FORMAT_VERSION, 1);
    let b = valid();
    assert_eq!(&b[..4], b"MKNG");
    assert_eq!(section(&b, 0).0, SECTIONS_START);
    let nodes = section(&b, 1);
    assert_eq!(nodes.1, 4 + 12 * NODE_LEN);
    assert_eq!(section(&b, 2).1, 4 + 8 * EDGE_LEN);
    assert_eq!(section(&b, 3).1, 13 * 4);
    assert_eq!(section(&b, 4).1, 13 * 4 + 8 * 4);
    assert_eq!(section(&b, 5).1, 12 * KEY_LEN);
    assert_eq!(section(&b, 6).1, 4 + 4 * ATTR_LEN);
    let (last_off, last_len) = section(&b, 6);
    assert_eq!(last_off + last_len, b.len());
}

#[test]
fn round_trip_is_identity() {
    let g = builder().build(&SCHEMA, &compiled()).unwrap();
    let bytes = encode(&g);
    let back = dec(&bytes).unwrap();
    assert_eq!(back, g);
    assert_eq!(encode(&back), bytes);
}

#[test]
fn every_space_round_trips() {
    for space in [
        GraphSpace::Shared,
        GraphSpace::User(SubjectId(1000)),
        GraphSpace::Kernel,
    ] {
        let mut b = GraphBuilder::new(space, 3);
        for n in builder().build(&SCHEMA, &compiled()).unwrap().nodes() {
            let mut n = n.clone();
            n.space = space;
            b = b.node(n);
        }
        let g = b.build(&SCHEMA, &compiled()).unwrap();
        assert_eq!(dec(&encode(&g)).unwrap(), g);
    }
}

#[test]
fn encode_is_order_independent() {
    let g = builder().build(&SCHEMA, &compiled()).unwrap();
    let mut b = GraphBuilder::new(GraphSpace::Kernel, 7);
    for n in g.nodes().iter().rev() {
        b = b.node(n.clone());
    }
    for e in g.edges().iter().rev() {
        b = b.edge(e.clone());
    }
    assert_eq!(encode(&b.build(&SCHEMA, &compiled()).unwrap()), encode(&g));
}

#[test]
fn header_refusals() {
    let b = valid();
    assert_eq!(dec(&b[..39]).unwrap_err(), FormatError::Truncated);
    assert_eq!(dec(&b[..50]).unwrap_err(), FormatError::Truncated);
    assert_eq!(dec(&b[..151]).unwrap_err(), FormatError::BadSectionLayout);
    assert_eq!(dec(&[]).unwrap_err(), FormatError::Truncated);

    let mut m = b.clone();
    m[0] = b'X';
    assert_eq!(dec(&m).unwrap_err(), FormatError::BadMagic);

    let mut m = b.clone();
    put_u16(&mut m, 4, 2);
    assert_eq!(
        dec(&m).unwrap_err(),
        FormatError::UnsupportedFormatVersion(2)
    );

    let mut m = b.clone();
    put_u16(&mut m, 6, 9);
    assert_eq!(
        dec(&m).unwrap_err(),
        FormatError::UnsupportedSchemaVersion {
            found: 9,
            expected: 1
        }
    );

    let mut m = b.clone();
    m[8] = 3;
    assert_eq!(dec(&m).unwrap_err(), FormatError::UnknownSpaceTag(3));

    let mut m = b.clone();
    m[9] = 1;
    assert_eq!(dec(&m).unwrap_err(), FormatError::NonZeroReserved);

    let mut m = b.clone();
    put_u16(&mut m, 10, 1);
    assert_eq!(dec(&m).unwrap_err(), FormatError::UnknownFlags(1));

    let mut m = b.clone();
    put_u32(&mut m, 28, 6);
    assert_eq!(dec(&m).unwrap_err(), FormatError::BadSectionCount(6));

    let mut m = b.clone();
    put_u64(&mut m, 32, 1);
    assert_eq!(dec(&m).unwrap_err(), FormatError::NonZeroReserved);

    let mut m = b.clone();
    put_u64(&mut m, 12, 5);
    assert_eq!(dec(&m).unwrap_err(), FormatError::NonCanonical);
}

#[test]
fn section_table_refusals() {
    let b = valid();
    let mut m = b.clone();
    put_u64(&mut m, HEADER_LEN, SECTIONS_START as u64 + 1);
    assert_eq!(dec(&m).unwrap_err(), FormatError::BadSectionLayout);

    let mut m = b.clone();
    put_u64(&mut m, HEADER_LEN + 8, u64::MAX);
    assert_eq!(dec(&m).unwrap_err(), FormatError::BadSectionLayout);

    let mut m = b.clone();
    let (off, len) = section(&b, 6);
    put_u64(&mut m, HEADER_LEN + 6 * 16 + 8, (len + 1) as u64);
    assert_eq!(off + len, b.len());
    assert_eq!(dec(&m).unwrap_err(), FormatError::BadSectionLayout);

    let mut m = b.clone();
    m.push(0);
    assert_eq!(dec(&m).unwrap_err(), FormatError::TrailingBytes);
}

#[test]
fn trailing_bytes_inside_each_parsed_section_refuse() {
    let b = valid();
    for i in [0usize, 1, 2, 6] {
        assert_eq!(
            dec(&grow_section(&b, i, &[0])).unwrap_err(),
            FormatError::TrailingBytes,
            "section {i}"
        );
    }
    for i in [3usize, 4, 5] {
        assert_eq!(
            dec(&grow_section(&b, i, &[0])).unwrap_err(),
            FormatError::NonCanonical,
            "section {i}"
        );
    }
}

#[test]
fn record_field_refusals() {
    let b = valid();
    let s0 = section(&b, 0).0;
    let mut m = b.clone();
    m[s0 + 8] = 0xff;
    assert_eq!(dec(&m).unwrap_err(), FormatError::BadUtf8);

    let n = first_node(&b);
    let mut m = b.clone();
    put_u32(&mut m, n + 24, u32::MAX);
    assert_eq!(
        dec(&m).unwrap_err(),
        FormatError::BadStrRef(u64::from(u32::MAX))
    );

    let mut m = b.clone();
    put_u16(&mut m, n + 10, 9);
    assert_eq!(dec(&m).unwrap_err(), FormatError::UnknownProvenance(9));

    let mut m = b.clone();
    m[n + 13] = 1;
    assert_eq!(dec(&m).unwrap_err(), FormatError::NonZeroReserved);

    let mut m = b.clone();
    m[n + 12] = 7;
    assert_eq!(dec(&m).unwrap_err(), FormatError::UnknownSpaceTag(7));

    let mut m = b.clone();
    put_u32(&mut m, n + 52, u32::MAX);
    assert_eq!(dec(&m).unwrap_err(), FormatError::BadAttrRange);

    let e = first_edge(&b);
    let mut m = b.clone();
    put_u32(&mut m, e + 44, 1);
    assert_eq!(dec(&m).unwrap_err(), FormatError::NonZeroReserved);

    let mut m = b.clone();
    put_u16(&mut m, e + 26, 9);
    assert_eq!(dec(&m).unwrap_err(), FormatError::UnknownProvenance(9));

    let mut m = b.clone();
    m[e + 29] = 1;
    assert_eq!(dec(&m).unwrap_err(), FormatError::NonZeroReserved);

    let a = first_attr(&b);
    let mut m = b.clone();
    m[a + 4] = 9;
    assert_eq!(dec(&m).unwrap_err(), FormatError::UnknownAttrTag(9));

    let mut m = b.clone();
    m[a + 5] = 1;
    assert_eq!(dec(&m).unwrap_err(), FormatError::NonZeroReserved);

    let mut m = b.clone();
    put_u64(&mut m, a + 8, u64::MAX);
    assert_eq!(dec(&m).unwrap_err(), FormatError::BadStrRef(u64::MAX));
}

#[test]
fn graph_errors_surface_through_decode() {
    let b = valid();
    let e = first_edge(&b);
    let mut m = b.clone();
    put_u16(&mut m, e + 24, 99);
    assert_eq!(
        dec(&m).unwrap_err(),
        FormatError::Graph(GraphError::UnknownEdgeKind(EdgeKind(99)))
    );
}

#[test]
fn huge_count_refuses_at_the_section_end() {
    let b = valid();
    for i in [0usize, 1, 2, 6] {
        let mut m = b.clone();
        put_u32(&mut m, section(&b, i).0, u32::MAX);
        assert_eq!(dec(&m).unwrap_err(), FormatError::Truncated, "section {i}");
    }
}

/// Keeps only the first `keep` bytes of section `i`, fixing up its length and every later offset.
fn cut_section(b: &[u8], i: usize, keep: usize) -> Vec<u8> {
    let (off, len) = section(b, i);
    let mut out = b[..off + keep].to_vec();
    out.extend_from_slice(&b[off + len..]);
    put_u64(&mut out, HEADER_LEN + i * 16 + 8, keep as u64);
    for j in i + 1..SECTION_COUNT {
        let at = HEADER_LEN + j * 16;
        let o = get_u64(&out, at);
        put_u64(&mut out, at, o - (len - keep) as u64);
    }
    out
}

#[test]
fn every_cut_inside_a_parsed_section_refuses_as_truncated() {
    let b = valid();
    for i in [0usize, 1, 2, 6] {
        let len = section(&b, i).1;
        for keep in 0..len {
            assert_eq!(
                dec(&cut_section(&b, i, keep)).unwrap_err(),
                FormatError::Truncated,
                "section {i} cut to {keep} of {len}"
            );
        }
    }
}

/// Offset of the attr-start field of the node at `index` in id order
/// (ids 1,2,3,4,5,6,10,11,20,21,30,40: node 11 is index 7, node 20 is 8, node 40 is 11).
fn attr_range_at(b: &[u8], index: usize) -> usize {
    first_node(b) + index * NODE_LEN + 48
}

#[test]
fn duplicate_attr_keys_refuse_as_non_canonical() {
    let b = valid();
    let a = first_attr(&b);
    let mut m = b.clone();
    let hash_key: [u8; 4] = m[a..a + 4].try_into().unwrap();
    m[a + ATTR_LEN..a + ATTR_LEN + 4].copy_from_slice(&hash_key);
    put_u32(&mut m, attr_range_at(&b, 7) + 4, 2);
    put_u32(&mut m, attr_range_at(&b, 8), 2);
    put_u32(&mut m, attr_range_at(&b, 8) + 4, 0);
    assert_eq!(dec(&m).unwrap_err(), FormatError::NonCanonical);
}

#[test]
fn overlapping_or_unconsumed_attr_ranges_refuse() {
    let b = valid();
    let mut m = b.clone();
    put_u32(&mut m, attr_range_at(&b, 8), 0);
    assert_eq!(dec(&m).unwrap_err(), FormatError::BadAttrRange);
    let mut m = b.clone();
    put_u32(&mut m, attr_range_at(&b, 11) + 4, 0);
    assert_eq!(dec(&m).unwrap_err(), FormatError::BadAttrRange);
}

fn shared_label_graph(subjects: u64, label_len: usize) -> GraphBuilder {
    let long = "x".repeat(label_len);
    let mut bld = GraphBuilder::new(GraphSpace::Kernel, 1);
    for k in builder().build(&SCHEMA, &compiled()).unwrap().nodes() {
        bld = bld.node(k.clone());
    }
    for i in 0..subjects {
        let mut n = node(
            1_000 + i,
            SUBJECT,
            &format!("{}", 10_000 + i),
            ProvenanceKind::Seed,
        );
        n.label = long.clone();
        bld = bld.node(n);
    }
    bld
}

fn reference_bytes(g: &maknae_graph::graph::Graph) -> usize {
    let attrs = |a: &Attrs| {
        a.iter()
            .map(|(k, v)| {
                k.len()
                    + if let AttrValue::Str(s) = v {
                        s.len()
                    } else {
                        0
                    }
            })
            .sum::<usize>()
    };
    g.nodes()
        .iter()
        .map(|n| n.key.len() + n.label.len() + attrs(&n.attrs))
        .sum::<usize>()
        + g.edges()
            .iter()
            .map(|e| e.label.len() + attrs(&e.attrs))
            .sum::<usize>()
}

#[test]
fn build_refuses_a_graph_its_store_could_not_be_decoded_from() {
    let err = shared_label_graph(2_000, 10_000)
        .build(&SCHEMA, &compiled())
        .unwrap_err();
    assert_eq!(err, GraphError::ExpansionLimit);
}

#[test]
fn moderately_shared_strings_round_trip() {
    let g = shared_label_graph(200, 150)
        .build(&SCHEMA, &compiled())
        .unwrap();
    let bytes = encode(&g);
    let ratio = reference_bytes(&g) as f64 / bytes.len() as f64;
    assert!(
        ratio > 1.5 && ratio < 3.5,
        "fixture must sit between 1x and 4x, got {ratio}"
    );
    assert_eq!(dec(&bytes).unwrap(), g);
}

/// Index of `wanted` in the store's sorted string table.
fn string_index(b: &[u8], wanted: &str) -> u32 {
    let (off, _) = section(b, 0);
    let count = u32::from_le_bytes(b[off..off + 4].try_into().unwrap());
    let mut at = off + 4;
    for i in 0..count {
        let len = u32::from_le_bytes(b[at..at + 4].try_into().unwrap()) as usize;
        if &b[at + 4..at + 4 + len] == wanted.as_bytes() {
            return i;
        }
        at += 4 + len;
    }
    panic!("{wanted:?} is not in the string table");
}

#[test]
fn crafted_references_refuse_past_the_expansion_limit_before_build() {
    let b = encode(
        &shared_label_graph(300, 250)
            .build(&SCHEMA, &compiled())
            .unwrap(),
    );
    assert!(dec(&b).is_ok());
    let long = string_index(&b, &"x".repeat(250));
    let n = first_node(&b);
    let nodes = u32::from_le_bytes(b[n - 4..n].try_into().unwrap()) as usize;
    let mut m = b.clone();
    for k in 0..nodes {
        put_u32(&mut m, n + k * NODE_LEN + 24, long);
    }
    assert_eq!(dec(&m).unwrap_err(), FormatError::ExpansionLimit);
}

#[test]
fn unconsumed_attrs_refuse_on_an_edgeless_store() {
    let mut bld = GraphBuilder::new(GraphSpace::Kernel, 7);
    for n in builder().build(&SCHEMA, &compiled()).unwrap().nodes() {
        bld = bld.node(n.clone());
    }
    let b = encode(&bld.build(&SCHEMA, &compiled()).unwrap());
    assert_eq!(section(&b, 2).1, 4);
    let mut m = b.clone();
    put_u32(&mut m, attr_range_at(&b, 11) + 4, 0);
    assert_eq!(dec(&m).unwrap_err(), FormatError::BadAttrRange);
}

#[test]
fn record_space_mismatch_in_bytes_refuses() {
    let b = valid();
    let n = first_node(&b);
    let mut m = b.clone();
    m[n + 12] = 1;
    put_u64(&mut m, n + 16, 1000);
    assert_eq!(
        dec(&m).unwrap_err(),
        FormatError::Graph(GraphError::SpaceMismatch)
    );
}

#[test]
fn format_error_messages_name_the_cause() {
    let cases = [
        (FormatError::Truncated, "store is truncated"),
        (
            FormatError::BadMagic,
            "store does not begin with the MKNG magic",
        ),
        (
            FormatError::UnsupportedFormatVersion(2),
            "unsupported store format version 2",
        ),
        (
            FormatError::UnsupportedSchemaVersion {
                found: 9,
                expected: 1,
            },
            "store schema version 9 differs from the binary's 1",
        ),
        (
            FormatError::NonZeroReserved,
            "a reserved store field is not zero",
        ),
        (FormatError::UnknownFlags(4), "unknown store flags 0x0004"),
        (FormatError::UnknownSpaceTag(3), "unknown graph space tag 3"),
        (
            FormatError::BadSectionCount(6),
            "store declares 6 sections, expected 7",
        ),
        (
            FormatError::BadSectionLayout,
            "store sections are not contiguous and in bounds",
        ),
        (
            FormatError::TrailingBytes,
            "store has bytes past the end of a table",
        ),
        (FormatError::BadUtf8, "a stored string is not UTF-8"),
        (
            FormatError::BadStrRef(9),
            "string reference 9 is out of range",
        ),
        (
            FormatError::UnknownProvenance(9),
            "unknown provenance code 9",
        ),
        (FormatError::UnknownAttrTag(9), "unknown attribute tag 9"),
        (
            FormatError::BadAttrRange,
            "attribute range is out of bounds",
        ),
        (
            FormatError::ExpansionLimit,
            "store string references expand past the decode limit",
        ),
        (
            FormatError::NonCanonical,
            "store bytes are not the canonical encoding of their graph",
        ),
        (
            FormatError::Graph(GraphError::EmptyLabel),
            "invalid graph: record has an empty label",
        ),
    ];
    for (err, text) in cases {
        assert_eq!(err.to_string(), text);
    }
}
