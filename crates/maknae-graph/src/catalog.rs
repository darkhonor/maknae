use crate::format::FormatError;
use crate::graph::{Graph, GraphBuilder, GraphError};
use crate::record::{
    AttrValue, Attrs, EdgeId, EdgeKind, EdgeRecord, GraphSpace, NodeId, NodeKind, NodeRecord,
    Provenance, ProvenanceKind,
};
use crate::schema::{CompiledSet, Schema};
use std::collections::{BTreeMap, BTreeSet};

pub const SCHEMA_VERSION: u16 = 1;

pub const ENTRY: NodeKind = NodeKind(1);
pub const PROGRAM: NodeKind = NodeKind(2);
pub const PATTERN: NodeKind = NodeKind(3);
pub const BINDING_KIND: NodeKind = NodeKind(4);
pub const FORGE: NodeKind = NodeKind(5);
pub const SHAPE: NodeKind = NodeKind(6);

pub const RUNS: EdgeKind = EdgeKind(1);
pub const GRANTED: EdgeKind = EdgeKind(2);
pub const BINDS: EdgeKind = EdgeKind(3);
pub const SERVED_BY: EdgeKind = EdgeKind(4);

pub const ATTR_DESCRIPTION: &str = "description";
pub const ATTR_EXECUTES_WORKSPACE: &str = "executes_workspace";
pub const ATTR_OUTPUT: &str = "output";
pub const ATTR_TEXT: &str = "text";
pub const ATTR_HOST: &str = "host";
pub const ATTR_PROVIDER: &str = "provider";

pub const SPACE: GraphSpace = GraphSpace::Shared;
pub const REVISION: u64 = 0;
pub const PROVENANCE: Provenance = Provenance {
    kind: ProvenanceKind::RootFile,
    transition: 0,
};

pub static SCHEMA: Schema = Schema {
    version: SCHEMA_VERSION,
    node_kinds: &[
        (ENTRY, "Entry"),
        (PROGRAM, "Program"),
        (PATTERN, "Pattern"),
        (BINDING_KIND, "BindingKind"),
        (FORGE, "Forge"),
        (SHAPE, "Shape"),
    ],
    edge_kinds: &[
        (RUNS, "runs"),
        (GRANTED, "granted"),
        (BINDS, "binds"),
        (SERVED_BY, "served_by"),
    ],
    triples: &[
        (ENTRY, RUNS, PROGRAM),
        (PROGRAM, GRANTED, PATTERN),
        (ENTRY, BINDS, BINDING_KIND),
        (BINDING_KIND, SERVED_BY, FORGE),
    ],
    compiled_kinds: &[],
    forbidden_targets: &[],
};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CatalogInput {
    pub entries: Vec<CatalogEntry>,
    pub forges: Vec<CatalogForge>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogEntry {
    pub name: String,
    pub description: Option<String>,
    pub executes_workspace: bool,
    pub output: CatalogOutput,
    pub binds: Vec<String>,
    pub programs: Vec<(String, Vec<String>)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogOutput {
    Redacted,
    StatusOnly,
}

impl CatalogOutput {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Redacted => "redacted",
            Self::StatusOnly => "status_only",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        [Self::Redacted, Self::StatusOnly]
            .into_iter()
            .find(|o| o.as_str() == s)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogForge {
    pub name: String,
    pub kind: String,
    pub host: String,
    pub provider: String,
}

type Key = (NodeKind, String);

#[derive(Default)]
struct Records {
    nodes: BTreeMap<Key, (Vec<String>, Attrs)>,
    edges: BTreeSet<(Key, EdgeKind, Key)>,
}

impl Records {
    fn node(&mut self, kind: NodeKind, origin: &[&str], attrs: Attrs) -> Result<Key, GraphError> {
        let key = (kind, origin.join("/"));
        let record = (origin.iter().map(|s| (*s).to_owned()).collect(), attrs);
        match self.nodes.get(&key) {
            Some(existing) if *existing != record => {
                Err(GraphError::DuplicateKey { kind, key: key.1 })
            }
            Some(_) => Ok(key),
            None => {
                self.nodes.insert(key.clone(), record);
                Ok(key)
            }
        }
    }

    fn builder(self) -> GraphBuilder {
        let mut b = GraphBuilder::new(SPACE, REVISION);
        let mut ids: BTreeMap<&Key, NodeId> = BTreeMap::new();
        for (i, (key, (_, attrs))) in self.nodes.iter().enumerate() {
            let id = NodeId(i as u64 + 1);
            ids.insert(key, id);
            b = b.node(NodeRecord {
                id,
                space: SPACE,
                kind: key.0,
                key: key.1.clone(),
                label: kind_label(SCHEMA.node_kind_name(key.0)),
                provenance: PROVENANCE,
                revision: REVISION,
                attrs: attrs.clone(),
            });
        }
        for (i, (from, kind, to)) in self.edges.iter().enumerate() {
            b = b.edge(EdgeRecord {
                id: EdgeId(i as u64 + 1),
                space: SPACE,
                from: ids[from],
                to: ids[to],
                kind: *kind,
                label: kind_label(SCHEMA.edge_kind_name(*kind)),
                provenance: PROVENANCE,
                revision: REVISION,
                attrs: Attrs::new(),
            });
        }
        b
    }
}

fn kind_label(name: Option<&'static str>) -> String {
    name.expect("the catalog emits only kinds its schema names")
        .to_owned()
}

fn records(input: &CatalogInput) -> Result<Records, GraphError> {
    let mut r = Records::default();
    for e in &input.entries {
        let mut attrs = Attrs::new();
        if let Some(d) = &e.description {
            attrs.insert(ATTR_DESCRIPTION.into(), AttrValue::Str(d.clone()));
        }
        attrs.insert(
            ATTR_EXECUTES_WORKSPACE.into(),
            AttrValue::U64(u64::from(e.executes_workspace)),
        );
        attrs.insert(ATTR_OUTPUT.into(), AttrValue::Str(e.output.as_str().into()));
        let entry = r.node(ENTRY, &[&e.name], attrs)?;
        for kind in &e.binds {
            let binding = r.node(BINDING_KIND, &[kind], Attrs::new())?;
            r.edges.insert((entry.clone(), BINDS, binding));
        }
        for (program, pats) in &e.programs {
            let prog = r.node(PROGRAM, &[&e.name, program], Attrs::new())?;
            r.edges.insert((entry.clone(), RUNS, prog.clone()));
            for text in pats {
                let attrs = Attrs::from([(ATTR_TEXT.into(), AttrValue::Str(text.clone()))]);
                let pat = r.node(PATTERN, &[&e.name, program, text], attrs)?;
                r.edges.insert((prog.clone(), GRANTED, pat));
            }
        }
    }
    for f in &input.forges {
        let attrs = Attrs::from([
            (ATTR_HOST.into(), AttrValue::Str(f.host.clone())),
            (ATTR_PROVIDER.into(), AttrValue::Str(f.provider.clone())),
        ]);
        let forge = r.node(FORGE, &[&f.name], attrs)?;
        let binding = r.node(BINDING_KIND, &[&f.kind], Attrs::new())?;
        r.edges.insert((binding, SERVED_BY, forge));
    }
    Ok(r)
}

pub fn build(input: &CatalogInput) -> Result<Graph, GraphError> {
    records(input)?
        .builder()
        .build(&SCHEMA, &CompiledSet::default())
}

pub fn encode(input: &CatalogInput) -> Result<Vec<u8>, GraphError> {
    records(input)?
        .builder()
        .build_encoded(&SCHEMA, &CompiledSet::default())
        .map(|(_, bytes)| bytes)
}

/// Accepts exactly the bytes `encode` produces for some input: the graph is read back into
/// a `CatalogInput` and re-encoded, so a graph built against another schema is refused.
pub fn decode(bytes: &[u8]) -> Result<Graph, FormatError> {
    let g = crate::format::decode(bytes, SPACE, &SCHEMA, &CompiledSet::default())?;
    let canonical = input_of(&g)
        .and_then(|input| encode(&input).ok())
        .is_some_and(|again| again == bytes);
    if canonical {
        Ok(g)
    } else {
        Err(FormatError::NonCanonical)
    }
}

fn input_of(g: &Graph) -> Option<CatalogInput> {
    let mut input = CatalogInput::default();
    for n in g.nodes().iter().filter(|n| n.kind == ENTRY) {
        let description = match n.attrs.get(ATTR_DESCRIPTION) {
            None => None,
            Some(v) => Some(str_of(Some(v))?.to_owned()),
        };
        let executes_workspace = match n.attrs.get(ATTR_EXECUTES_WORKSPACE) {
            Some(AttrValue::U64(0)) => false,
            Some(AttrValue::U64(1)) => true,
            _ => return None,
        };
        let output = CatalogOutput::parse(str_of(n.attrs.get(ATTR_OUTPUT))?)?;
        let binds = g
            .out_edges(n.id, BINDS)
            .map(|e| g.node(e.to).map(|t| t.key.clone()))
            .collect::<Option<Vec<_>>>()?;
        let prefix = format!("{}/", n.key);
        let mut programs = Vec::new();
        for e in g.out_edges(n.id, RUNS) {
            let prog = g.node(e.to)?;
            let pats = g
                .out_edges(prog.id, GRANTED)
                .map(|p| g.node(p.to).and_then(|t| str_of(t.attrs.get(ATTR_TEXT))))
                .map(|t| t.map(str::to_owned))
                .collect::<Option<Vec<_>>>()?;
            programs.push((prog.key.strip_prefix(&prefix)?.to_owned(), pats));
        }
        input.entries.push(CatalogEntry {
            name: n.key.clone(),
            description,
            executes_workspace,
            output,
            binds,
            programs,
        });
    }
    for n in g.nodes().iter().filter(|n| n.kind == FORGE) {
        for e in g.in_edges(n.id, SERVED_BY) {
            input.forges.push(CatalogForge {
                name: n.key.clone(),
                kind: g.node(e.from)?.key.clone(),
                host: str_of(n.attrs.get(ATTR_HOST))?.to_owned(),
                provider: str_of(n.attrs.get(ATTR_PROVIDER))?.to_owned(),
            });
        }
    }
    Some(input)
}

fn str_of(v: Option<&AttrValue>) -> Option<&str> {
    match v {
        Some(AttrValue::Str(s)) => Some(s),
        _ => None,
    }
}

pub fn entries(g: &Graph) -> Vec<&str> {
    g.nodes()
        .iter()
        .filter(|n| n.kind == ENTRY)
        .map(|n| n.key.as_str())
        .collect()
}

pub fn entries_for_binding<'g>(g: &'g Graph, kind: &str) -> Vec<&'g str> {
    let Some(b) = g.lookup(BINDING_KIND, kind) else {
        return Vec::new();
    };
    g.in_edges(b.id, BINDS)
        .filter_map(|e| g.node(e.from))
        .map(|n| n.key.as_str())
        .collect()
}

pub fn forges<'g>(g: &'g Graph, kind: &str) -> Vec<(&'g str, &'g str)> {
    let Some(b) = g.lookup(BINDING_KIND, kind) else {
        return Vec::new();
    };
    g.out_edges(b.id, SERVED_BY)
        .filter_map(|e| g.node(e.to))
        .filter_map(|n| {
            Some((
                str_of(n.attrs.get(ATTR_HOST))?,
                str_of(n.attrs.get(ATTR_PROVIDER))?,
            ))
        })
        .collect()
}

pub fn patterns<'g>(g: &'g Graph, entry: &str, program: &str) -> Vec<&'g str> {
    let Some(p) = g.lookup(PROGRAM, &format!("{entry}/{program}")) else {
        return Vec::new();
    };
    g.out_edges(p.id, GRANTED)
        .filter_map(|e| g.node(e.to))
        .filter_map(|n| str_of(n.attrs.get(ATTR_TEXT)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::GraphBuilder;
    use crate::record::{
        AttrValue, Attrs, EdgeId, EdgeRecord, GraphSpace, NodeId, NodeRecord, Provenance,
        ProvenanceKind,
    };
    use crate::schema::CompiledSet;

    fn entry(name: &str, binds: &[&str], programs: &[(&str, &[&str])]) -> CatalogEntry {
        CatalogEntry {
            name: name.into(),
            description: Some(format!("{name} tool")),
            executes_workspace: false,
            output: CatalogOutput::Redacted,
            binds: binds.iter().map(|b| (*b).into()).collect(),
            programs: programs
                .iter()
                .map(|(p, pats)| ((*p).into(), pats.iter().map(|s| (*s).into()).collect()))
                .collect(),
        }
    }

    fn forge(name: &str, host: &str, provider: &str) -> CatalogForge {
        CatalogForge {
            name: name.into(),
            kind: "git".into(),
            host: host.into(),
            provider: provider.into(),
        }
    }

    fn sample() -> CatalogInput {
        let mut cargo = entry(
            "cargo",
            &[],
            &[("cargo", &["build *", "test *"]), ("rustc", &["--version"])],
        );
        cargo.executes_workspace = true;
        cargo.description = None;
        let mut gh = entry("gh", &["git"], &[("gh", &["pr view *", "pr list"])]);
        gh.output = CatalogOutput::StatusOnly;
        CatalogInput {
            entries: vec![
                cargo,
                gh,
                entry("glab", &["git"], &[("glab", &["mr view *"])]),
            ],
            forges: vec![
                forge("github", "github.com", "github"),
                forge("lab", "gitlab.lab.local:8443", "gitlab"),
            ],
        }
    }

    fn permuted() -> CatalogInput {
        let mut i = sample();
        i.entries.reverse();
        i.forges.reverse();
        for e in &mut i.entries {
            e.binds.reverse();
            e.programs.reverse();
            for (_, p) in &mut e.programs {
                p.reverse();
            }
        }
        let dup = i.entries[0].clone();
        i.entries.push(dup);
        let again = i.entries[1].programs[0].1[0].clone();
        i.entries[1].programs[0].1.push(again);
        i.forges.push(i.forges[0].clone());
        i
    }

    #[test]
    fn schema_tables_are_pinned() {
        assert_eq!(SCHEMA.version, 1);
        assert_eq!(
            SCHEMA.node_kinds,
            &[
                (NodeKind(1), "Entry"),
                (NodeKind(2), "Program"),
                (NodeKind(3), "Pattern"),
                (NodeKind(4), "BindingKind"),
                (NodeKind(5), "Forge"),
                (NodeKind(6), "Shape"),
            ]
        );
        assert_eq!(
            SCHEMA.edge_kinds,
            &[
                (EdgeKind(1), "runs"),
                (EdgeKind(2), "granted"),
                (EdgeKind(3), "binds"),
                (EdgeKind(4), "served_by"),
            ]
        );
        assert_eq!(
            SCHEMA.triples,
            &[
                (ENTRY, RUNS, PROGRAM),
                (PROGRAM, GRANTED, PATTERN),
                (ENTRY, BINDS, BINDING_KIND),
                (BINDING_KIND, SERVED_BY, FORGE),
            ]
        );
        assert!(SCHEMA.compiled_kinds.is_empty());
        assert!(SCHEMA.forbidden_targets.is_empty());
        assert_eq!(
            [ENTRY, PROGRAM, PATTERN, BINDING_KIND, FORGE, SHAPE],
            [1, 2, 3, 4, 5, 6].map(NodeKind)
        );
        assert_eq!(
            [RUNS, GRANTED, BINDS, SERVED_BY],
            [1, 2, 3, 4].map(EdgeKind)
        );
    }

    #[test]
    fn the_vocabulary_names_no_fence_attribute() {
        let kinds: Vec<&str> = SCHEMA.node_kinds.iter().map(|(_, n)| *n).collect();
        assert_eq!(
            kinds,
            [
                "Entry",
                "Program",
                "Pattern",
                "BindingKind",
                "Forge",
                "Shape"
            ]
        );
        let allowed = [
            "description",
            "executes_workspace",
            "output",
            "text",
            "host",
            "provider",
        ];
        assert_eq!(
            [
                ATTR_DESCRIPTION,
                ATTR_EXECUTES_WORKSPACE,
                ATTR_OUTPUT,
                ATTR_TEXT,
                ATTR_HOST,
                ATTR_PROVIDER
            ],
            allowed
        );
        let g = build(&sample()).unwrap();
        let mut seen: Vec<&str> = g
            .nodes()
            .iter()
            .flat_map(|n| n.attrs.keys())
            .chain(g.edges().iter().flat_map(|e| e.attrs.keys()))
            .map(String::as_str)
            .collect();
        seen.sort_unstable();
        seen.dedup();
        let mut want = allowed.to_vec();
        want.sort_unstable();
        assert_eq!(seen, want);
        for name in kinds.iter().chain(&allowed) {
            let lower = name.to_ascii_lowercase();
            for fence in [
                "credential",
                "class",
                "app",
                "image",
                "volume",
                "network",
                "site",
                "deny",
                "resource",
                "lifetime",
                "isolation",
            ] {
                assert!(!lower.contains(fence), "{name} names {fence}");
            }
        }
    }

    #[test]
    fn build_is_deterministic() {
        let a = encode(&sample()).unwrap();
        let b = encode(&permuted()).unwrap();
        assert_eq!(a, b);
        assert_eq!(crate::format::encode(&build(&permuted()).unwrap()), a);
        let g = build(&sample()).unwrap();
        assert_eq!(g.space(), GraphSpace::Shared);
        assert_eq!(g.revision(), 0);
        let fixed = Provenance {
            kind: ProvenanceKind::RootFile,
            transition: 0,
        };
        for n in g.nodes() {
            assert_eq!((n.revision, n.provenance), (0, fixed));
            assert_eq!(Some(n.label.as_str()), SCHEMA.node_kind_name(n.kind));
        }
        for e in g.edges() {
            assert_eq!((e.revision, e.provenance), (0, fixed));
            assert_eq!(Some(e.label.as_str()), SCHEMA.edge_kind_name(e.kind));
        }
        let mut ordered: Vec<(NodeKind, &str)> =
            g.nodes().iter().map(|n| (n.kind, n.key.as_str())).collect();
        ordered.sort_unstable();
        let by_id: Vec<(NodeKind, &str)> =
            g.nodes().iter().map(|n| (n.kind, n.key.as_str())).collect();
        assert_eq!(by_id, ordered);
        let ids: Vec<u64> = g.nodes().iter().map(|n| n.id.0).collect();
        assert_eq!(ids, (1..=ids.len() as u64).collect::<Vec<_>>());
        let mut edge_ids: Vec<u64> = g.edges().iter().map(|e| e.id.0).collect();
        edge_ids.sort_unstable();
        assert_eq!(edge_ids, (1..=edge_ids.len() as u64).collect::<Vec<_>>());

        let mut changed = sample();
        changed.entries[0].programs[0].1[0] = "build --release".into();
        assert_ne!(encode(&changed).unwrap(), a);
        let mut changed = sample();
        changed.forges[1].host = "gitlab.lab.local".into();
        assert_ne!(encode(&changed).unwrap(), a);
    }

    #[test]
    fn round_trip_and_walks() {
        let bytes = encode(&sample()).unwrap();
        let g = decode(&bytes).unwrap();
        assert_eq!(g, build(&sample()).unwrap());
        assert_eq!(entries(&g), ["cargo", "gh", "glab"]);
        assert_eq!(entries_for_binding(&g, "git"), ["gh", "glab"]);
        assert!(entries_for_binding(&g, "svn").is_empty());
        assert_eq!(
            forges(&g, "git"),
            [
                ("github.com", "github"),
                ("gitlab.lab.local:8443", "gitlab")
            ]
        );
        assert!(forges(&g, "svn").is_empty());
        assert_eq!(patterns(&g, "cargo", "cargo"), ["build *", "test *"]);
        assert_eq!(patterns(&g, "cargo", "rustc"), ["--version"]);
        assert_eq!(patterns(&g, "gh", "gh"), ["pr list", "pr view *"]);
        assert!(patterns(&g, "gh", "cargo").is_empty());
        assert!(patterns(&g, "none", "none").is_empty());

        let cargo = g.lookup(ENTRY, "cargo").unwrap();
        assert_eq!(cargo.attrs.get(ATTR_DESCRIPTION), None);
        assert_eq!(
            cargo.attrs.get(ATTR_EXECUTES_WORKSPACE),
            Some(&AttrValue::U64(1))
        );
        assert_eq!(
            cargo.attrs.get(ATTR_OUTPUT),
            Some(&AttrValue::Str("redacted".into()))
        );
        let gh = g.lookup(ENTRY, "gh").unwrap();
        assert_eq!(
            gh.attrs.get(ATTR_DESCRIPTION),
            Some(&AttrValue::Str("gh tool".into()))
        );
        assert_eq!(
            gh.attrs.get(ATTR_EXECUTES_WORKSPACE),
            Some(&AttrValue::U64(0))
        );
        assert_eq!(
            gh.attrs.get(ATTR_OUTPUT),
            Some(&AttrValue::Str("status_only".into()))
        );
        assert!(g.lookup(PROGRAM, "cargo/rustc").is_some());
        assert!(g.lookup(PATTERN, "cargo/cargo/build *").is_some());
        assert!(g.lookup(BINDING_KIND, "git").is_some());
        assert!(g.lookup(FORGE, "lab").is_some());

        let empty = encode(&CatalogInput::default()).unwrap();
        let g = decode(&empty).unwrap();
        assert!(g.nodes().is_empty());
        assert!(entries(&g).is_empty());
    }

    #[test]
    fn shared_pattern_text_under_two_entries_is_two_nodes() {
        let input = CatalogInput {
            entries: vec![
                entry("a", &[], &[("git", &["status"])]),
                entry("b", &[], &[("git", &["status"])]),
            ],
            forges: vec![],
        };
        let g = decode(&encode(&input).unwrap()).unwrap();
        let pats: Vec<&str> = g
            .nodes()
            .iter()
            .filter(|n| n.kind == PATTERN)
            .map(|n| n.key.as_str())
            .collect();
        assert_eq!(pats, ["a/git/status", "b/git/status"]);
        assert_eq!(patterns(&g, "a", "git"), ["status"]);
        assert_eq!(patterns(&g, "b", "git"), ["status"]);
    }

    #[test]
    fn colliding_keys_from_distinct_content_are_refused() {
        let input = CatalogInput {
            entries: vec![
                entry("a", &[], &[("b/c", &[])]),
                entry("a/b", &[], &[("c", &[])]),
            ],
            forges: vec![],
        };
        assert_eq!(
            build(&input).unwrap_err(),
            GraphError::DuplicateKey {
                kind: PROGRAM,
                key: "a/b/c".into()
            }
        );
        let mut other = entry("a", &[], &[]);
        other.executes_workspace = true;
        let input = CatalogInput {
            entries: vec![entry("a", &[], &[]), other],
            forges: vec![],
        };
        assert_eq!(
            encode(&input).unwrap_err(),
            GraphError::DuplicateKey {
                kind: ENTRY,
                key: "a".into()
            }
        );
    }

    #[test]
    fn shape_is_reserved_and_never_emitted() {
        assert_eq!(SCHEMA.node_kind_name(SHAPE), Some("Shape"));
        assert!(!SCHEMA
            .triples
            .iter()
            .any(|&(f, _, t)| f == SHAPE || t == SHAPE));
        let g = build(&sample()).unwrap();
        assert!(g.nodes().iter().all(|n| n.kind != SHAPE));
        let kinds: Vec<NodeKind> = {
            let mut k: Vec<NodeKind> = g.nodes().iter().map(|n| n.kind).collect();
            k.dedup();
            k
        };
        assert_eq!(kinds, [ENTRY, PROGRAM, PATTERN, BINDING_KIND, FORGE]);

        let mut b = GraphBuilder::new(GraphSpace::Shared, 0);
        for n in g.nodes() {
            b = b.node(n.clone());
        }
        for e in g.edges() {
            b = b.edge(e.clone());
        }
        let with_shape = b.node(NodeRecord {
            id: NodeId(1_000),
            space: GraphSpace::Shared,
            kind: SHAPE,
            key: "s".into(),
            label: "Shape".into(),
            provenance: Provenance {
                kind: ProvenanceKind::RootFile,
                transition: 0,
            },
            revision: 0,
            attrs: Attrs::new(),
        });
        let bytes =
            crate::format::encode(&with_shape.build(&SCHEMA, &CompiledSet::default()).unwrap());
        assert_eq!(decode(&bytes).unwrap_err(), FormatError::NonCanonical);
    }

    fn shared_node(id: u64, kind: NodeKind, key: &str, label: &str, attrs: Attrs) -> NodeRecord {
        NodeRecord {
            id: NodeId(id),
            space: GraphSpace::Shared,
            kind,
            key: key.into(),
            label: label.into(),
            provenance: Provenance {
                kind: ProvenanceKind::RootFile,
                transition: 0,
            },
            revision: 0,
            attrs,
        }
    }

    fn catalog_attrs() -> Attrs {
        Attrs::from([
            (ATTR_EXECUTES_WORKSPACE.into(), AttrValue::U64(0)),
            (ATTR_OUTPUT.into(), AttrValue::Str("redacted".into())),
        ])
    }

    #[test]
    fn decode_refuses_a_shared_space_graph_built_against_another_schema() {
        use crate::kernel;
        assert_eq!(kernel::SCHEMA.version, SCHEMA.version);
        assert_eq!(kernel::CONFIG_SOURCE, ENTRY);
        let foreign = GraphBuilder::new(GraphSpace::Shared, 0)
            .node(shared_node(
                1,
                kernel::CONFIG_SOURCE,
                "tools",
                "UNCLASSIFIED",
                Attrs::new(),
            ))
            .build(&kernel::SCHEMA, &CompiledSet::default())
            .unwrap();
        let bytes = crate::format::encode(&foreign);
        assert!(crate::format::decode(
            &bytes,
            GraphSpace::Shared,
            &SCHEMA,
            &CompiledSet::default()
        )
        .is_ok());
        assert_eq!(decode(&bytes).unwrap_err(), FormatError::NonCanonical);

        static WIDER: Schema = Schema {
            version: SCHEMA_VERSION,
            node_kinds: &[(ENTRY, "Entry"), (FORGE, "Forge")],
            edge_kinds: &[(RUNS, "runs")],
            triples: &[(ENTRY, RUNS, FORGE)],
            compiled_kinds: &[],
            forbidden_targets: &[],
        };
        let mut forge_attrs = Attrs::new();
        forge_attrs.insert(ATTR_HOST.into(), AttrValue::Str("h".into()));
        forge_attrs.insert(ATTR_PROVIDER.into(), AttrValue::Str("github".into()));
        let wider = GraphBuilder::new(GraphSpace::Shared, 0)
            .node(shared_node(1, ENTRY, "e", "Entry", catalog_attrs()))
            .node(shared_node(2, FORGE, "f", "Forge", forge_attrs))
            .edge(EdgeRecord {
                id: EdgeId(1),
                space: GraphSpace::Shared,
                from: NodeId(1),
                to: NodeId(2),
                kind: RUNS,
                label: "runs".into(),
                provenance: Provenance {
                    kind: ProvenanceKind::RootFile,
                    transition: 0,
                },
                revision: 0,
                attrs: Attrs::new(),
            })
            .build(&WIDER, &CompiledSet::default())
            .unwrap();
        assert_eq!(
            decode(&crate::format::encode(&wider)).unwrap_err(),
            FormatError::Graph(GraphError::ForbiddenTriple {
                from: ENTRY,
                edge: RUNS,
                to: FORGE
            })
        );

        let mut fenced = catalog_attrs();
        fenced.insert("credential".into(), AttrValue::Str("HomeLab".into()));
        let extra = GraphBuilder::new(GraphSpace::Shared, 0)
            .node(shared_node(1, ENTRY, "e", "Entry", fenced))
            .build(&SCHEMA, &CompiledSet::default())
            .unwrap();
        assert_eq!(
            decode(&crate::format::encode(&extra)).unwrap_err(),
            FormatError::NonCanonical
        );

        let plain = GraphBuilder::new(GraphSpace::Shared, 0)
            .node(shared_node(1, ENTRY, "e", "Entry", catalog_attrs()))
            .build(&SCHEMA, &CompiledSet::default())
            .unwrap();
        let plain_bytes = crate::format::encode(&plain);
        assert_eq!(
            decode(&plain_bytes).unwrap(),
            build(&CatalogInput {
                entries: vec![CatalogEntry {
                    description: None,
                    ..entry("e", &[], &[])
                }],
                forges: vec![],
            })
            .unwrap()
        );

        let kernel_space = crate::format::encode(
            &GraphBuilder::new(GraphSpace::Kernel, 0)
                .node(NodeRecord {
                    space: GraphSpace::Kernel,
                    ..shared_node(1, ENTRY, "e", "Entry", catalog_attrs())
                })
                .build(&SCHEMA, &CompiledSet::default())
                .unwrap(),
        );
        assert_eq!(decode(&kernel_space).unwrap_err(), FormatError::WrongSpace);
    }
}
