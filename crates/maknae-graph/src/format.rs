use crate::bytes::{Reader, Writer};
use crate::graph::{index_u32, Graph, GraphBuilder, GraphError};
use crate::record::{
    AttrValue, Attrs, EdgeId, EdgeKind, EdgeRecord, GraphSpace, NodeId, NodeKind, NodeRecord,
    Provenance, ProvenanceKind, SubjectId,
};
use crate::schema::{CompiledNode, CompiledSet, Schema};
use std::fmt;

pub const MAGIC: [u8; 4] = *b"MKNG";
pub const FORMAT_VERSION: u16 = 1;
pub const HEADER_LEN: usize = 40;
pub const SECTION_COUNT: usize = 7;
pub const SECTIONS_START: usize = HEADER_LEN + SECTION_COUNT * 16;
pub const NODE_LEN: usize = 56;
pub const EDGE_LEN: usize = 72;
pub const KEY_LEN: usize = 12;
pub const ATTR_LEN: usize = 16;

pub const EXPANSION_LIMIT: usize = 4;

pub(crate) fn within_expansion_limit(charged: usize, encoded_len: usize) -> bool {
    charged <= EXPANSION_LIMIT * encoded_len
}

const ATTR_STR: u8 = 1;
const ATTR_U64: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormatError {
    Truncated,
    BadMagic,
    UnsupportedFormatVersion(u16),
    UnsupportedSchemaVersion { found: u16, expected: u16 },
    NonZeroReserved,
    UnknownFlags(u16),
    UnknownSpaceTag(u8),
    WrongSpace,
    BadSectionCount(u32),
    BadSectionLayout,
    TrailingBytes,
    BadUtf8,
    BadStrRef(u64),
    UnknownProvenance(u16),
    UnknownAttrTag(u8),
    BadAttrRange,
    ExpansionLimit,
    NonCanonical,
    Graph(GraphError),
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("store is truncated"),
            Self::BadMagic => f.write_str("store does not begin with the MKNG magic"),
            Self::UnsupportedFormatVersion(v) => write!(f, "unsupported store format version {v}"),
            Self::UnsupportedSchemaVersion { found, expected } => {
                write!(
                    f,
                    "store schema version {found} differs from the binary's {expected}"
                )
            }
            Self::NonZeroReserved => f.write_str("a reserved store field is not zero"),
            Self::UnknownFlags(v) => write!(f, "unknown store flags {v:#06x}"),
            Self::UnknownSpaceTag(t) => write!(f, "unknown graph space tag {t}"),
            Self::WrongSpace => f.write_str("store holds a different graph space than requested"),
            Self::BadSectionCount(n) => {
                write!(f, "store declares {n} sections, expected {SECTION_COUNT}")
            }
            Self::BadSectionLayout => {
                f.write_str("store sections are not contiguous and in bounds")
            }
            Self::TrailingBytes => f.write_str("store has bytes past the end of a table"),
            Self::BadUtf8 => f.write_str("a stored string is not UTF-8"),
            Self::BadStrRef(i) => write!(f, "string reference {i} is out of range"),
            Self::UnknownProvenance(c) => write!(f, "unknown provenance code {c}"),
            Self::UnknownAttrTag(t) => write!(f, "unknown attribute tag {t}"),
            Self::BadAttrRange => f.write_str("attribute range is out of bounds"),
            Self::ExpansionLimit => {
                f.write_str("store string references expand past the decode limit")
            }
            Self::NonCanonical => {
                f.write_str("store bytes are not the canonical encoding of their graph")
            }
            Self::Graph(e) => write!(f, "invalid graph: {e}"),
        }
    }
}

impl std::error::Error for FormatError {}

pub fn encode(g: &Graph) -> Vec<u8> {
    let strings = string_table(g);
    let sref = |s: &str| {
        index_u32(
            strings
                .binary_search(&s)
                .expect("every record string is in the table"),
        )
    };

    let mut attr_body = Writer::default();
    let mut attr_count = 0u32;

    let mut nodes = Writer::default();
    nodes.u32(index_u32(g.nodes().len()));
    for n in g.nodes() {
        let (tag, subject) = space_parts(n.space);
        let (start, count) = push_attrs(&mut attr_body, &mut attr_count, &n.attrs, &sref);
        nodes.u64(n.id.0);
        nodes.u16(n.kind.0);
        nodes.u16(n.provenance.kind.code());
        nodes.u8(tag);
        nodes.bytes(&[0; 3]);
        nodes.u64(subject);
        nodes.u32(sref(&n.key));
        nodes.u32(sref(&n.label));
        nodes.u64(n.revision);
        nodes.u64(n.provenance.transition);
        nodes.u32(start);
        nodes.u32(count);
    }

    let mut edges = Writer::default();
    edges.u32(index_u32(g.edges().len()));
    for e in g.edges() {
        let (tag, subject) = space_parts(e.space);
        let (start, count) = push_attrs(&mut attr_body, &mut attr_count, &e.attrs, &sref);
        edges.u64(e.id.0);
        edges.u64(e.from.0);
        edges.u64(e.to.0);
        edges.u16(e.kind.0);
        edges.u16(e.provenance.kind.code());
        edges.u8(tag);
        edges.bytes(&[0; 3]);
        edges.u64(subject);
        edges.u32(sref(&e.label));
        edges.u32(0);
        edges.u64(e.revision);
        edges.u64(e.provenance.transition);
        edges.u32(start);
        edges.u32(count);
    }

    let mut out_index = Writer::default();
    for &o in g.out_offsets() {
        out_index.u32(o);
    }
    let mut in_index = Writer::default();
    for &o in g.in_offsets() {
        in_index.u32(o);
    }
    for &i in g.in_edge_indices() {
        in_index.u32(i);
    }
    let mut keys = Writer::default();
    for (kind, key, node) in g.key_index() {
        keys.u16(kind.0);
        keys.u16(0);
        keys.u32(sref(key));
        keys.u32(*node);
    }
    let mut attrs = Writer::default();
    attrs.u32(attr_count);
    attrs.bytes(&attr_body.into_inner());
    let mut string_section = Writer::default();
    string_section.u32(index_u32(strings.len()));
    for s in &strings {
        string_section.u32(index_u32(s.len()));
        string_section.bytes(s.as_bytes());
    }

    let sections = [
        string_section.into_inner(),
        nodes.into_inner(),
        edges.into_inner(),
        out_index.into_inner(),
        in_index.into_inner(),
        keys.into_inner(),
        attrs.into_inner(),
    ];
    let mut w = Writer::default();
    let (tag, subject) = space_parts(g.space());
    w.bytes(&MAGIC);
    w.u16(FORMAT_VERSION);
    w.u16(g.schema_version());
    w.u8(tag);
    w.u8(0);
    w.u16(0);
    w.u64(subject);
    w.u64(g.revision());
    w.u32(index_u32(SECTION_COUNT));
    w.u64(0);
    let mut offset = SECTIONS_START as u64;
    for s in &sections {
        w.u64(offset);
        w.u64(s.len() as u64);
        offset += s.len() as u64;
    }
    for s in &sections {
        w.bytes(s);
    }
    w.into_inner()
}

pub fn decode(
    bytes: &[u8],
    expected: GraphSpace,
    schema: &Schema,
    compiled: &CompiledSet,
) -> Result<Graph, FormatError> {
    let b = parse(bytes, expected, schema)?;
    rebuild_canonical(b, bytes, schema, compiled)
}

/// Decodes trusting the store's own `Compiled` nodes as the compiled set; the caller must
/// judge that set against the binary's vocabulary digest before using the graph.
pub fn decode_stored_compiled(
    bytes: &[u8],
    expected: GraphSpace,
    schema: &Schema,
) -> Result<(Graph, CompiledSet), FormatError> {
    let b = parse(bytes, expected, schema)?;
    let stored = CompiledSet::new(
        b.nodes()
            .iter()
            .filter(|n| n.provenance.kind == ProvenanceKind::Compiled)
            .map(|n| CompiledNode {
                kind: n.kind,
                key: n.key.clone(),
                label: n.label.clone(),
                attrs: n.attrs.clone(),
            })
            .collect(),
    );
    let g = rebuild_canonical(b, bytes, schema, &stored)?;
    Ok((g, stored))
}

fn rebuild_canonical(
    b: GraphBuilder,
    bytes: &[u8],
    schema: &Schema,
    compiled: &CompiledSet,
) -> Result<Graph, FormatError> {
    let (g, encoded) = b
        .build_encoded(schema, compiled)
        .map_err(FormatError::Graph)?;
    if encoded != bytes {
        return Err(FormatError::NonCanonical);
    }
    Ok(g)
}

fn parse(bytes: &[u8], expected: GraphSpace, schema: &Schema) -> Result<GraphBuilder, FormatError> {
    let mut r = Reader::new(bytes);
    if r.take(4)? != MAGIC {
        return Err(FormatError::BadMagic);
    }
    let format = r.u16()?;
    if format != FORMAT_VERSION {
        return Err(FormatError::UnsupportedFormatVersion(format));
    }
    let schema_version = r.u16()?;
    if schema_version != schema.version {
        return Err(FormatError::UnsupportedSchemaVersion {
            found: schema_version,
            expected: schema.version,
        });
    }
    let tag = r.u8()?;
    let reserved = r.u8()?;
    let flags = r.u16()?;
    let subject = r.u64()?;
    let revision = r.u64()?;
    let count = r.u32()?;
    let reserved_tail = r.u64()?;
    if flags != 0 {
        return Err(FormatError::UnknownFlags(flags));
    }
    if reserved != 0 || reserved_tail != 0 {
        return Err(FormatError::NonZeroReserved);
    }
    if count != index_u32(SECTION_COUNT) {
        return Err(FormatError::BadSectionCount(count));
    }
    let space = decode_space(tag, subject)?;
    if space != expected {
        return Err(FormatError::WrongSpace);
    }

    let mut sections: [&[u8]; SECTION_COUNT] = [&[]; SECTION_COUNT];
    let mut next = SECTIONS_START as u64;
    for slot in &mut sections {
        let offset = r.u64()?;
        let len = r.u64()?;
        if offset != next {
            return Err(FormatError::BadSectionLayout);
        }
        let end = offset
            .checked_add(len)
            .filter(|&end| end <= bytes.len() as u64)
            .ok_or(FormatError::BadSectionLayout)?;
        *slot = &bytes[offset as usize..end as usize];
        next = end;
    }
    if next != bytes.len() as u64 {
        return Err(FormatError::TrailingBytes);
    }

    let mut strings = Strings {
        table: read_strings(sections[0])?,
        budget: EXPANSION_LIMIT * bytes.len(),
    };

    let mut r = Reader::new(sections[1]);
    let mut nodes = Vec::new();
    for _ in 0..r.u32()? {
        nodes.push(read_node(&mut r, &mut strings)?);
    }
    done(&r)?;

    let mut r = Reader::new(sections[2]);
    let mut edges = Vec::new();
    for _ in 0..r.u32()? {
        edges.push(read_edge(&mut r, &mut strings)?);
    }
    done(&r)?;

    let mut r = Reader::new(sections[6]);
    let mut attrs = Vec::new();
    for _ in 0..r.u32()? {
        attrs.push(read_attr(&mut r, &mut strings)?);
    }
    done(&r)?;

    let mut b = GraphBuilder::new(space, revision);
    let mut attrs = attrs.into_iter();
    let mut cursor = 0usize;
    for (mut n, start, count) in nodes {
        n.attrs = take_attrs(&mut attrs, &mut cursor, start, count)?;
        b = b.node(n);
    }
    for (mut e, start, count) in edges {
        e.attrs = take_attrs(&mut attrs, &mut cursor, start, count)?;
        b = b.edge(e);
    }
    if attrs.len() != 0 {
        return Err(FormatError::BadAttrRange);
    }
    Ok(b)
}

fn string_table(g: &Graph) -> Vec<&str> {
    let mut out: Vec<&str> = Vec::new();
    for n in g.nodes() {
        out.push(&n.key);
        out.push(&n.label);
        attr_strings(&mut out, &n.attrs);
    }
    for e in g.edges() {
        out.push(&e.label);
        attr_strings(&mut out, &e.attrs);
    }
    out.sort_unstable();
    out.dedup();
    out
}

fn attr_strings<'a>(out: &mut Vec<&'a str>, a: &'a Attrs) {
    for (k, v) in a {
        out.push(k);
        if let AttrValue::Str(s) = v {
            out.push(s);
        }
    }
}

fn push_attrs(
    out: &mut Writer,
    count: &mut u32,
    a: &Attrs,
    sref: &impl Fn(&str) -> u32,
) -> (u32, u32) {
    let start = *count;
    for (k, v) in a {
        out.u32(sref(k));
        match v {
            AttrValue::Str(s) => {
                out.u8(ATTR_STR);
                out.bytes(&[0; 3]);
                out.u64(u64::from(sref(s)));
            }
            AttrValue::U64(x) => {
                out.u8(ATTR_U64);
                out.bytes(&[0; 3]);
                out.u64(*x);
            }
        }
        *count += 1;
    }
    (start, index_u32(a.len()))
}

fn space_parts(space: GraphSpace) -> (u8, u64) {
    match space {
        GraphSpace::Shared => (0, 0),
        GraphSpace::User(SubjectId(s)) => (1, s),
        GraphSpace::Kernel => (2, 0),
    }
}

fn decode_space(tag: u8, subject: u64) -> Result<GraphSpace, FormatError> {
    match tag {
        0 => Ok(GraphSpace::Shared),
        1 => Ok(GraphSpace::User(SubjectId(subject))),
        2 => Ok(GraphSpace::Kernel),
        t => Err(FormatError::UnknownSpaceTag(t)),
    }
}

fn provenance(code: u16, transition: u64) -> Result<Provenance, FormatError> {
    let kind = ProvenanceKind::from_code(code).ok_or(FormatError::UnknownProvenance(code))?;
    Ok(Provenance { kind, transition })
}

fn reserved(r: &mut Reader<'_>, n: usize) -> Result<(), FormatError> {
    if r.take(n)?.iter().any(|&b| b != 0) {
        return Err(FormatError::NonZeroReserved);
    }
    Ok(())
}

fn done(r: &Reader<'_>) -> Result<(), FormatError> {
    if r.is_empty() {
        Ok(())
    } else {
        Err(FormatError::TrailingBytes)
    }
}

struct Strings {
    table: Vec<String>,
    budget: usize,
}

impl Strings {
    fn get(&mut self, i: u64) -> Result<String, FormatError> {
        let s = usize::try_from(i)
            .ok()
            .and_then(|i| self.table.get(i))
            .ok_or(FormatError::BadStrRef(i))?;
        self.budget = self
            .budget
            .checked_sub(s.len())
            .ok_or(FormatError::ExpansionLimit)?;
        Ok(s.clone())
    }
}

fn read_strings(section: &[u8]) -> Result<Vec<String>, FormatError> {
    let mut r = Reader::new(section);
    let mut out = Vec::new();
    for _ in 0..r.u32()? {
        let len = r.u32()? as usize;
        let s = std::str::from_utf8(r.take(len)?).map_err(|_| FormatError::BadUtf8)?;
        out.push(s.to_owned());
    }
    done(&r)?;
    Ok(out)
}

fn read_node(
    r: &mut Reader<'_>,
    strings: &mut Strings,
) -> Result<(NodeRecord, u32, u32), FormatError> {
    let id = NodeId(r.u64()?);
    let kind = NodeKind(r.u16()?);
    let code = r.u16()?;
    let tag = r.u8()?;
    reserved(r, 3)?;
    let subject = r.u64()?;
    let key = strings.get(u64::from(r.u32()?))?;
    let label = strings.get(u64::from(r.u32()?))?;
    let revision = r.u64()?;
    let transition = r.u64()?;
    let start = r.u32()?;
    let count = r.u32()?;
    let node = NodeRecord {
        id,
        space: decode_space(tag, subject)?,
        kind,
        key,
        label,
        provenance: provenance(code, transition)?,
        revision,
        attrs: Attrs::new(),
    };
    Ok((node, start, count))
}

fn read_edge(
    r: &mut Reader<'_>,
    strings: &mut Strings,
) -> Result<(EdgeRecord, u32, u32), FormatError> {
    let id = EdgeId(r.u64()?);
    let from = NodeId(r.u64()?);
    let to = NodeId(r.u64()?);
    let kind = EdgeKind(r.u16()?);
    let code = r.u16()?;
    let tag = r.u8()?;
    reserved(r, 3)?;
    let subject = r.u64()?;
    let label = strings.get(u64::from(r.u32()?))?;
    reserved(r, 4)?;
    let revision = r.u64()?;
    let transition = r.u64()?;
    let start = r.u32()?;
    let count = r.u32()?;
    let edge = EdgeRecord {
        id,
        space: decode_space(tag, subject)?,
        from,
        to,
        kind,
        label,
        provenance: provenance(code, transition)?,
        revision,
        attrs: Attrs::new(),
    };
    Ok((edge, start, count))
}

fn read_attr(
    r: &mut Reader<'_>,
    strings: &mut Strings,
) -> Result<(String, AttrValue), FormatError> {
    let key = strings.get(u64::from(r.u32()?))?;
    let tag = r.u8()?;
    reserved(r, 3)?;
    let raw = r.u64()?;
    let value = match tag {
        ATTR_STR => AttrValue::Str(strings.get(raw)?),
        ATTR_U64 => AttrValue::U64(raw),
        other => return Err(FormatError::UnknownAttrTag(other)),
    };
    Ok((key, value))
}

fn take_attrs(
    rest: &mut std::vec::IntoIter<(String, AttrValue)>,
    cursor: &mut usize,
    start: u32,
    count: u32,
) -> Result<Attrs, FormatError> {
    let count = count as usize;
    if start as usize != *cursor || count > rest.len() {
        return Err(FormatError::BadAttrRange);
    }
    *cursor += count;
    Ok(rest.by_ref().take(count).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{build, IdentityLayer, SubjectEntry};
    use crate::kernel::{persisted_compiled_set, SCHEMA};

    fn edge_at(bytes: &[u8], i: usize) -> usize {
        let at = HEADER_LEN + 2 * 16;
        let off = u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap()) as usize;
        off + 4 + i * EDGE_LEN
    }

    #[test]
    fn decode_stored_compiled_reads_a_store_from_another_vocabulary_and_reports_its_set() {
        let roles = persisted_compiled_set("UNCLASSIFIED");
        let g = build(
            &IdentityLayer {
                aliases: Default::default(),
                source: "p".into(),
                label: "UNCLASSIFIED".into(),
                bindings_sha256: None,
                subjects: vec![],
            },
            None,
            &roles,
            [1; 32],
            3,
            ProvenanceKind::Seed,
        )
        .unwrap();
        let bytes = encode(&g);
        assert!(matches!(
            decode(&bytes, GraphSpace::Kernel, &SCHEMA, &CompiledSet::default()),
            Err(FormatError::Graph(GraphError::CompiledMismatch { .. }))
        ));
        let (g2, stored) = decode_stored_compiled(&bytes, GraphSpace::Kernel, &SCHEMA).unwrap();
        assert_eq!(g2, g);
        assert_eq!(stored.canonical_bytes(), roles.canonical_bytes());
        assert!(stored.canonical_bytes().is_ok());
        let empty = encode(
            &GraphBuilder::new(GraphSpace::Kernel, 1)
                .build(&SCHEMA, &CompiledSet::default())
                .unwrap(),
        );
        let (_, s) = decode_stored_compiled(&empty, GraphSpace::Kernel, &SCHEMA).unwrap();
        assert!(s.is_empty());
    }

    #[test]
    fn decode_stored_compiled_still_judges_compiled_revision_and_transition() {
        let roles = persisted_compiled_set("UNCLASSIFIED");
        let layer = IdentityLayer {
            aliases: Default::default(),
            source: "p".into(),
            label: "UNCLASSIFIED".into(),
            bindings_sha256: None,
            subjects: vec![],
        };
        let g = build(&layer, None, &roles, [1; 32], 3, ProvenanceKind::Seed).unwrap();
        let admin = g.lookup(crate::kernel::ROLE, "admin").unwrap().id;
        let bytes = encode(&g);
        let at = {
            let at = HEADER_LEN + 16;
            let off = u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap()) as usize;
            off + 4 + (admin.0 as usize - 1) * NODE_LEN
        };
        for field in [32usize, 40] {
            let mut m = bytes.clone();
            m[at + field] = 1;
            assert_eq!(
                decode_stored_compiled(&m, GraphSpace::Kernel, &SCHEMA).unwrap_err(),
                FormatError::Graph(GraphError::CompiledMismatch {
                    kind: crate::kernel::ROLE,
                    key: "admin".into()
                }),
                "field {field}"
            );
        }
    }

    #[test]
    fn decode_stored_compiled_still_refuses_every_non_compiled_defect() {
        let roles = persisted_compiled_set("UNCLASSIFIED");
        let g = build(
            &IdentityLayer {
                aliases: Default::default(),
                source: "p".into(),
                label: "UNCLASSIFIED".into(),
                bindings_sha256: Some([3; 32]),
                subjects: vec![SubjectEntry {
                    uid: 7,
                    name: "a".into(),
                    role: "user".into(),
                }],
            },
            None,
            &roles,
            [1; 32],
            3,
            ProvenanceKind::Seed,
        )
        .unwrap();
        let good = encode(&g);
        let kernel = GraphSpace::Kernel;
        let both = |bytes: &[u8]| {
            (
                decode(bytes, kernel, &SCHEMA, &roles).unwrap_err(),
                decode_stored_compiled(bytes, kernel, &SCHEMA).unwrap_err(),
            )
        };
        for n in 0..good.len() {
            let (a, b) = both(&good[..n]);
            assert_eq!(a, b, "truncated at {n}");
        }
        let mut m = good.clone();
        m[0] = b'X';
        assert_eq!(both(&m), (FormatError::BadMagic, FormatError::BadMagic));
        assert_eq!(
            decode_stored_compiled(&good, GraphSpace::Shared, &SCHEMA).unwrap_err(),
            decode(&good, GraphSpace::Shared, &SCHEMA, &roles).unwrap_err()
        );

        assert_eq!(g.edges().len(), 3);
        let (e0, e1) = (edge_at(&good, 0), edge_at(&good, 1));
        let mut m = good.clone();
        let first = good[e0..e0 + EDGE_LEN].to_vec();
        m.copy_within(e1..e1 + EDGE_LEN, e0);
        m[e1..e1 + EDGE_LEN].copy_from_slice(&first);
        assert_eq!(
            both(&m),
            (FormatError::NonCanonical, FormatError::NonCanonical)
        );

        let mut m = good.clone();
        m[e0 + 16..e0 + 24].copy_from_slice(&999u64.to_le_bytes());
        let dangling = FormatError::Graph(GraphError::DanglingEdge(g.edges()[0].id));
        assert_eq!(both(&m), (dangling.clone(), dangling));

        let subject = g.lookup(crate::kernel::SUBJECT, "uid:7").unwrap().id;
        let mut m = good.clone();
        m[e0 + 16..e0 + 24].copy_from_slice(&subject.0.to_le_bytes());
        let forbidden = FormatError::Graph(GraphError::ForbiddenTriple {
            from: g.node(g.edges()[0].from).unwrap().kind,
            edge: g.edges()[0].kind,
            to: crate::kernel::SUBJECT,
        });
        assert_eq!(both(&m), (forbidden.clone(), forbidden));

        for i in 0..SECTIONS_START {
            let mut f = good.clone();
            f[i] ^= 1;
            let a = decode(&f, kernel, &SCHEMA, &roles);
            let b = decode_stored_compiled(&f, kernel, &SCHEMA);
            assert_eq!(a.is_ok(), b.is_ok(), "byte {i}");
            if let (Err(a), Err(b)) = (a, b) {
                assert_eq!(a, b, "byte {i}");
            }
        }
    }

    #[test]
    fn expansion_limit_allows_equality_and_refuses_one_past() {
        assert!(within_expansion_limit(8, 2));
        assert!(!within_expansion_limit(9, 2));
        assert!(within_expansion_limit(0, 0));
        assert!(!within_expansion_limit(1, 0));
    }
}
