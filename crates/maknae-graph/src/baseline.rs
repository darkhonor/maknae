use crate::graph::Graph;
use crate::identity::{unhex, IdentityError};
use crate::kernel::{
    ATTR_SHA256, ATTR_VALUE, CLASSIFICATION_SYSTEM, CONFIG_SOURCE, DECLARES, INSTANCE, LEVEL,
    LEVEL_OF, PART_OF, SECTION,
};
use crate::record::{AttrValue, NodeKind, NodeRecord};
use std::collections::BTreeMap;

pub const BASELINE_SOURCE_KEY: &str = "baseline:maknae.yaml";
pub const INSTANCE_KEY: &str = "instance";
pub const ATTR_MOVED_FROM: &str = "moved_from";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineLayer {
    /// Section name → its canonical JSON, as accepted.
    pub sections: BTreeMap<String, String>,
    pub system: String,
    pub ceiling: String,
    /// The accepted digest; the caller computes it.
    pub sha256: [u8; 32],
    /// The previously accepted audit trail path, set by an accept that moved it and
    /// cleared by the boot that performs the move.
    pub moved_from: Option<String>,
}

pub fn section_key(name: &str) -> String {
    format!("{BASELINE_SOURCE_KEY}#{name}")
}

pub fn level_key(system: &str, level: &str) -> String {
    format!("{system}:{level}")
}

fn section_name(n: &NodeRecord) -> Option<&str> {
    n.key
        .strip_prefix(BASELINE_SOURCE_KEY)
        .and_then(|k| k.strip_prefix('#'))
}

fn ambiguous(n: &NodeRecord, what: &'static str) -> IdentityError {
    IdentityError::BaselineAmbiguous { node: n.id.0, what }
}

fn bad(n: &NodeRecord, attr: &'static str) -> IdentityError {
    IdentityError::BaselineAttr { node: n.id.0, attr }
}

fn str_attr<'a>(n: &'a NodeRecord, attr: &'static str) -> Result<&'a str, IdentityError> {
    match n.attrs.get(attr) {
        Some(AttrValue::Str(s)) => Ok(s),
        _ => Err(bad(n, attr)),
    }
}

fn only<'a>(
    g: &'a Graph,
    kind: NodeKind,
    many: &'static str,
) -> Result<Option<&'a NodeRecord>, IdentityError> {
    let mut it = g.nodes().iter().filter(|n| n.kind == kind);
    let first = it.next();
    match it.next() {
        Some(second) => Err(ambiguous(second, many)),
        None => Ok(first),
    }
}

pub fn extract(g: &Graph) -> Result<Option<BaselineLayer>, IdentityError> {
    let Some(src) = g.lookup(CONFIG_SOURCE, BASELINE_SOURCE_KEY) else {
        return match g.nodes().iter().find(|n| {
            [INSTANCE, CLASSIFICATION_SYSTEM, LEVEL].contains(&n.kind)
                || (n.kind == SECTION && section_name(n).is_some())
        }) {
            Some(n) => Err(ambiguous(n, "baseline node without a baseline source")),
            None => Ok(None),
        };
    };
    let sha256 = unhex(str_attr(src, ATTR_SHA256)?).ok_or_else(|| bad(src, ATTR_SHA256))?;
    let moved_from = match src.attrs.get(ATTR_MOVED_FROM) {
        None => None,
        Some(AttrValue::Str(s)) => Some(s.clone()),
        Some(_) => return Err(bad(src, ATTR_MOVED_FROM)),
    };
    let mut sections = BTreeMap::new();
    for n in g.nodes().iter().filter(|n| n.kind == SECTION) {
        let Some(name) = section_name(n) else {
            continue;
        };
        if name.is_empty() {
            return Err(ambiguous(n, "baseline section without a name"));
        }
        let mut parts = g.out_edges(n.id, PART_OF);
        if parts.next().map(|e| e.to) != Some(src.id) || parts.next().is_some() {
            return Err(ambiguous(n, "baseline section outside the baseline source"));
        }
        sections.insert(name.to_string(), str_attr(n, ATTR_VALUE)?.to_string());
    }
    if sections.is_empty() {
        return Err(ambiguous(src, "baseline without a section"));
    }
    let inst = match only(g, INSTANCE, "more than one instance")? {
        Some(n) if n.key == INSTANCE_KEY => n,
        Some(n) => return Err(ambiguous(n, "no instance")),
        None => return Err(ambiguous(src, "no instance")),
    };
    let sys = only(
        g,
        CLASSIFICATION_SYSTEM,
        "more than one classification system",
    )?
    .ok_or_else(|| ambiguous(inst, "no classification system"))?;
    if g.out_edges(inst.id, DECLARES).count() != 1 {
        return Err(ambiguous(inst, "instance declares no single system"));
    }
    let lvl = only(g, LEVEL, "more than one level")?.ok_or_else(|| ambiguous(sys, "no level"))?;
    let ceiling = lvl
        .key
        .strip_prefix(&sys.key)
        .and_then(|k| k.strip_prefix(':'))
        .filter(|c| !c.is_empty())
        .filter(|_| g.out_edges(lvl.id, LEVEL_OF).count() == 1)
        .ok_or_else(|| ambiguous(lvl, "level outside the declared system"))?;
    Ok(Some(BaselineLayer {
        sections,
        system: sys.key.clone(),
        ceiling: ceiling.to_string(),
        sha256,
        moved_from,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::GraphBuilder;
    use crate::identity::{build, extract, IdentityLayer, SubjectEntry};
    use crate::kernel::{persisted_compiled_set, DECLARED_BY, SCHEMA};
    use crate::record::{
        Attrs, EdgeId, EdgeRecord, GraphSpace, NodeId, Provenance, ProvenanceKind,
    };

    fn layer() -> IdentityLayer {
        IdentityLayer {
            source: "/etc/maknae/bindings.yaml".into(),
            label: "UNCLASSIFIED".into(),
            bindings_sha256: Some([1; 32]),
            subjects: vec![SubjectEntry {
                uid: 0,
                name: "root".into(),
                role: "admin".into(),
            }],
            aliases: Default::default(),
        }
    }

    fn baseline() -> BaselineLayer {
        BaselineLayer {
            sections: [
                ("audit", r#"{"jsonl_path":"/var/log/maknae/audit.jsonl"}"#),
                ("core", r#"{"deployment_id":"d"}"#),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
            system: "US".into(),
            ceiling: "UNCLASSIFIED".into(),
            sha256: [7; 32],
            moved_from: None,
        }
    }

    fn graph(b: Option<&BaselineLayer>) -> Graph {
        build(
            &layer(),
            b,
            &persisted_compiled_set("UNCLASSIFIED"),
            [9; 32],
            3,
            ProvenanceKind::RootFile,
        )
        .unwrap()
    }

    #[test]
    fn a_built_baseline_extracts_unchanged_and_the_identity_layer_is_untouched() {
        let g = graph(Some(&baseline()));
        let e = extract(&g).unwrap();
        assert_eq!(e.baseline, Some(baseline()));
        assert_eq!(e.layer, layer());
        assert_eq!(e.vocabulary_sha256, Some([9; 32]));
        assert!(e.unbound.is_empty());
    }

    #[test]
    fn a_pending_move_survives_the_round_trip() {
        let mut b = baseline();
        b.moved_from = Some("/var/log/maknae/audit.jsonl".into());
        assert_eq!(extract(&graph(Some(&b))).unwrap().baseline, Some(b));
    }

    #[test]
    fn a_graph_without_a_baseline_extracts_none() {
        assert_eq!(extract(&graph(None)).unwrap().baseline, None);
    }

    #[test]
    fn the_keys_name_the_source_and_the_system() {
        assert_eq!(section_key("core"), "baseline:maknae.yaml#core");
        assert_eq!(level_key("AUS", "OFFICIAL"), "AUS:OFFICIAL");
    }

    #[test]
    fn the_classification_is_declared_by_the_core_section() {
        let g = graph(Some(&baseline()));
        let core = g.lookup(SECTION, &section_key("core")).unwrap().id;
        for (kind, key) in [
            (INSTANCE, INSTANCE_KEY.to_string()),
            (CLASSIFICATION_SYSTEM, "US".into()),
            (LEVEL, level_key("US", "UNCLASSIFIED")),
        ] {
            let n = g.lookup(kind, &key).unwrap();
            assert_eq!(
                g.out_edges(n.id, DECLARED_BY)
                    .map(|e| e.to)
                    .collect::<Vec<_>>(),
                vec![core],
                "{key}"
            );
        }
    }

    #[test]
    fn the_baseline_source_is_not_a_second_policy_source() {
        let g = graph(Some(&baseline()));
        assert!(g.lookup(CONFIG_SOURCE, BASELINE_SOURCE_KEY).is_some());
        assert_eq!(extract(&g).unwrap().layer, layer());
    }

    #[test]
    fn a_baseline_without_a_core_section_still_builds_and_extracts() {
        let mut b = baseline();
        b.sections.remove("core");
        let g = graph(Some(&b));
        assert_eq!(
            g.edges().iter().filter(|e| e.kind == DECLARED_BY).count(),
            1
        );
        assert_eq!(extract(&g).unwrap().baseline, Some(b));
    }

    fn encoded(g: &Graph) -> Vec<u8> {
        crate::format::encode(g)
    }

    fn decoded(bytes: &[u8]) -> Graph {
        crate::format::decode(
            bytes,
            GraphSpace::Kernel,
            &SCHEMA,
            &persisted_compiled_set("UNCLASSIFIED"),
        )
        .unwrap()
    }

    #[test]
    fn a_baseline_store_round_trips_canonically() {
        let mut b = baseline();
        b.moved_from = Some("/var/log/maknae/old.jsonl".into());
        let bytes = encoded(&graph(Some(&b)));
        let back = decoded(&bytes);
        assert_eq!(encoded(&back), bytes);
        assert_eq!(extract(&back).unwrap().baseline, Some(b));
    }

    fn unhex_bytes(s: &str) -> Vec<u8> {
        let s = s.trim();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn a_store_written_before_the_baseline_layer_decodes_and_extracts_unchanged() {
        let bytes = unhex_bytes(include_str!("../tests/fixtures/store-without-baseline.hex"));
        let g = decoded(&bytes);
        let e = extract(&g).unwrap();
        assert_eq!(e.baseline, None);
        assert_eq!(e.vocabulary_sha256, Some([9; 32]));
        let want = IdentityLayer {
            source: "/etc/maknae/authz.yaml".into(),
            label: "UNCLASSIFIED".into(),
            bindings_sha256: Some([1; 32]),
            subjects: vec![
                SubjectEntry {
                    uid: 0,
                    name: "root".into(),
                    role: "admin".into(),
                },
                SubjectEntry {
                    uid: 666,
                    name: "mallory".into(),
                    role: "adversary".into(),
                },
            ],
            aliases: [("eve".to_string(), 666)].into_iter().collect(),
        };
        assert_eq!(e.layer, want);
        assert_eq!(encoded(&g), bytes);
        let rebuilt = build(
            &want,
            None,
            &persisted_compiled_set("UNCLASSIFIED"),
            [9; 32],
            3,
            ProvenanceKind::RootFile,
        )
        .unwrap();
        assert_eq!(encoded(&rebuilt), bytes);
    }

    fn rebuilt(
        g: &Graph,
        keep_node: impl Fn(&NodeRecord) -> Option<NodeRecord>,
        keep_edge: impl Fn(&EdgeRecord) -> bool,
        extra: Vec<(NodeRecord, Vec<EdgeRecord>)>,
    ) -> Graph {
        let mut b = GraphBuilder::new(GraphSpace::Kernel, g.revision());
        let nodes: Vec<NodeRecord> = g.nodes().iter().filter_map(&keep_node).collect();
        let kept =
            |id: NodeId| nodes.iter().any(|n| n.id == id) || extra.iter().any(|(n, _)| n.id == id);
        for e in g
            .edges()
            .iter()
            .filter(|e| keep_edge(e) && kept(e.from) && kept(e.to))
        {
            b = b.edge(e.clone());
        }
        for n in nodes {
            b = b.node(n);
        }
        for (n, es) in extra {
            b = b.node(n);
            for e in es {
                b = b.edge(e);
            }
        }
        b.build(&SCHEMA, &persisted_compiled_set("UNCLASSIFIED"))
            .unwrap()
    }

    fn without(g: &Graph, gone: &[NodeId]) -> Graph {
        rebuilt(
            g,
            |n| (!gone.contains(&n.id)).then(|| n.clone()),
            |_| true,
            vec![],
        )
    }

    fn id(g: &Graph, kind: NodeKind, key: &str) -> NodeId {
        g.lookup(kind, key).unwrap().id
    }

    fn next_ids(g: &Graph) -> (u64, u64) {
        (
            g.nodes().iter().map(|n| n.id.0).max().unwrap() + 1,
            g.edges().iter().map(|e| e.id.0).max().unwrap() + 1,
        )
    }

    fn node(g: &Graph, id: u64, kind: NodeKind, key: &str) -> NodeRecord {
        NodeRecord {
            id: NodeId(id),
            space: GraphSpace::Kernel,
            kind,
            key: key.into(),
            label: g.nodes()[0].label.clone(),
            provenance: Provenance {
                kind: ProvenanceKind::RootFile,
                transition: g.revision(),
            },
            revision: g.revision(),
            attrs: Attrs::new(),
        }
    }

    fn edge(
        g: &Graph,
        id: u64,
        from: NodeId,
        kind: crate::record::EdgeKind,
        to: NodeId,
    ) -> EdgeRecord {
        EdgeRecord {
            id: EdgeId(id),
            space: GraphSpace::Kernel,
            from,
            to,
            kind,
            label: g.nodes()[0].label.clone(),
            provenance: Provenance {
                kind: ProvenanceKind::RootFile,
                transition: g.revision(),
            },
            revision: g.revision(),
            attrs: Attrs::new(),
        }
    }

    fn plus_edge(g: &Graph, from: NodeId, kind: crate::record::EdgeKind, to: NodeId) -> Graph {
        let (_, e) = next_ids(g);
        let mut b = GraphBuilder::new(GraphSpace::Kernel, g.revision());
        for n in g.nodes() {
            b = b.node(n.clone());
        }
        for x in g.edges() {
            b = b.edge(x.clone());
        }
        b.edge(edge(g, e, from, kind, to))
            .build(&SCHEMA, &persisted_compiled_set("UNCLASSIFIED"))
            .unwrap()
    }

    fn refusal(g: &Graph) -> (u64, &'static str) {
        match extract(g) {
            Err(IdentityError::BaselineAmbiguous { node, what }) => (node, what),
            other => panic!("expected an ambiguity, got {other:?}"),
        }
    }

    fn with_extra(
        g: &Graph,
        kind: NodeKind,
        key: &str,
        link: Option<(crate::record::EdgeKind, NodeId)>,
    ) -> (Graph, u64) {
        let (n, e) = next_ids(g);
        let edges = link
            .map(|(k, to)| vec![edge(g, e, NodeId(n), k, to)])
            .unwrap_or_default();
        (
            rebuilt(
                g,
                |x| Some(x.clone()),
                |_| true,
                vec![(node(g, n, kind, key), edges)],
            ),
            n,
        )
    }

    #[test]
    fn a_classification_node_without_a_baseline_source_is_refused() {
        let g = graph(Some(&baseline()));
        let src = id(&g, CONFIG_SOURCE, BASELINE_SOURCE_KEY);
        let sections: Vec<NodeId> = g
            .nodes()
            .iter()
            .filter(|n| n.kind == SECTION && n.key.starts_with(BASELINE_SOURCE_KEY))
            .map(|n| n.id)
            .collect();
        let mut gone = sections.clone();
        gone.push(src);
        let g2 = without(&g, &gone);
        assert_eq!(refusal(&g2).1, "baseline node without a baseline source");
        for kind in [INSTANCE, CLASSIFICATION_SYSTEM, LEVEL] {
            let others: Vec<NodeId> = [INSTANCE, CLASSIFICATION_SYSTEM, LEVEL]
                .into_iter()
                .filter(|k| *k != kind)
                .flat_map(|k| g.nodes().iter().filter(move |n| n.kind == k).map(|n| n.id))
                .chain(gone.iter().copied())
                .collect();
            let only_one = without(&g, &others);
            let n = only_one.nodes().iter().find(|n| n.kind == kind).unwrap().id;
            assert_eq!(
                refusal(&only_one),
                (n.0, "baseline node without a baseline source")
            );
        }
    }

    #[test]
    fn a_baseline_section_without_a_baseline_source_is_refused() {
        let g = graph(Some(&baseline()));
        let gone: Vec<NodeId> = g
            .nodes()
            .iter()
            .filter(|n| {
                [INSTANCE, CLASSIFICATION_SYSTEM, LEVEL].contains(&n.kind)
                    || n.key == BASELINE_SOURCE_KEY
            })
            .map(|n| n.id)
            .collect();
        let g = without(&g, &gone);
        let audit = id(&g, SECTION, &section_key("audit"));
        assert_eq!(
            refusal(&g),
            (audit.0, "baseline node without a baseline source")
        );
    }

    #[test]
    fn a_section_merely_sharing_the_prefix_is_not_a_baseline_section() {
        let g = graph(None);
        let (g, _) = with_extra(&g, SECTION, "baseline:maknae.yaml.d", None);
        assert_eq!(extract(&g).unwrap().baseline, None);
        let g = graph(Some(&baseline()));
        let (g, _) = with_extra(&g, SECTION, "baseline:maknae.yamlcore", None);
        assert_eq!(extract(&g).unwrap().baseline, Some(baseline()));
    }

    #[test]
    fn a_second_level_is_refused() {
        let g = graph(Some(&baseline()));
        let sys = id(&g, CLASSIFICATION_SYSTEM, "US");
        let (g, n) = with_extra(&g, LEVEL, &level_key("US", "SECRET"), Some((LEVEL_OF, sys)));
        assert_eq!(refusal(&g), (n, "more than one level"));
    }

    #[test]
    fn a_level_keyed_under_another_system_is_refused() {
        let g = graph(Some(&baseline()));
        let lvl = id(&g, LEVEL, &level_key("US", "UNCLASSIFIED"));
        for key in [
            level_key("AUS", "OFFICIAL"),
            "USUNCLASSIFIED".into(),
            level_key("US", ""),
        ] {
            let g = rebuilt(
                &g,
                |n| {
                    Some(if n.id == lvl {
                        NodeRecord {
                            key: key.clone(),
                            ..n.clone()
                        }
                    } else {
                        n.clone()
                    })
                },
                |_| true,
                vec![],
            );
            assert_eq!(refusal(&g), (lvl.0, "level outside the declared system"));
        }
    }

    #[test]
    fn a_level_of_no_system_is_refused() {
        let g = graph(Some(&baseline()));
        let lvl = id(&g, LEVEL, &level_key("US", "UNCLASSIFIED"));
        let g = rebuilt(&g, |n| Some(n.clone()), |e| e.kind != LEVEL_OF, vec![]);
        assert_eq!(refusal(&g), (lvl.0, "level outside the declared system"));
    }

    #[test]
    fn a_system_without_a_level_is_refused() {
        let g = graph(Some(&baseline()));
        let sys = id(&g, CLASSIFICATION_SYSTEM, "US");
        let lvl = id(&g, LEVEL, &level_key("US", "UNCLASSIFIED"));
        assert_eq!(refusal(&without(&g, &[lvl])), (sys.0, "no level"));
    }

    #[test]
    fn the_instance_must_declare_exactly_the_one_system() {
        let g = graph(Some(&baseline()));
        let inst = id(&g, INSTANCE, INSTANCE_KEY);
        let sys = id(&g, CLASSIFICATION_SYSTEM, "US");
        let undeclared = rebuilt(&g, |n| Some(n.clone()), |e| e.kind != DECLARES, vec![]);
        assert_eq!(
            refusal(&undeclared),
            (inst.0, "instance declares no single system")
        );
        assert_eq!(
            refusal(&plus_edge(&g, inst, DECLARES, sys)),
            (inst.0, "instance declares no single system")
        );
        let (two_systems, n) = with_extra(&g, CLASSIFICATION_SYSTEM, "AUS", None);
        assert_eq!(
            refusal(&two_systems),
            (n, "more than one classification system")
        );
        let lvl = id(&g, LEVEL, &level_key("US", "UNCLASSIFIED"));
        assert_eq!(
            refusal(&without(&g, &[sys, lvl])),
            (inst.0, "no classification system")
        );
    }

    #[test]
    fn exactly_one_instance_keyed_instance_is_required() {
        let g = graph(Some(&baseline()));
        let src = id(&g, CONFIG_SOURCE, BASELINE_SOURCE_KEY);
        let inst = id(&g, INSTANCE, INSTANCE_KEY);
        assert_eq!(refusal(&without(&g, &[inst])), (src.0, "no instance"));
        let renamed = rebuilt(
            &g,
            |n| {
                Some(if n.id == inst {
                    NodeRecord {
                        key: "other".into(),
                        ..n.clone()
                    }
                } else {
                    n.clone()
                })
            },
            |_| true,
            vec![],
        );
        assert_eq!(refusal(&renamed), (inst.0, "no instance"));
        let (two, n) = with_extra(&g, INSTANCE, "second", None);
        assert_eq!(refusal(&two), (n, "more than one instance"));
    }

    #[test]
    fn a_baseline_section_not_part_of_the_baseline_source_is_refused() {
        let g = graph(Some(&baseline()));
        let audit = id(&g, SECTION, &section_key("audit"));
        let policy = id(&g, CONFIG_SOURCE, "/etc/maknae/bindings.yaml");
        let detached = rebuilt(
            &g,
            |n| Some(n.clone()),
            |e| !(e.from == audit && e.kind == PART_OF),
            vec![],
        );
        assert_eq!(
            refusal(&detached),
            (audit.0, "baseline section outside the baseline source")
        );
        for g in [&detached, &g] {
            assert_eq!(
                refusal(&plus_edge(g, audit, PART_OF, policy)),
                (audit.0, "baseline section outside the baseline source")
            );
        }
    }

    fn with_attr(g: &Graph, at: NodeId, attr: &str, v: Option<AttrValue>) -> Graph {
        rebuilt(
            g,
            |n| {
                let mut n = n.clone();
                if n.id == at {
                    match &v {
                        Some(v) => n.attrs.insert(attr.into(), v.clone()),
                        None => n.attrs.remove(attr),
                    };
                }
                Some(n)
            },
            |_| true,
            vec![],
        )
    }

    #[test]
    fn a_malformed_attribute_is_refused_naming_it() {
        let g = graph(Some(&baseline()));
        let audit = id(&g, SECTION, &section_key("audit"));
        let src = id(&g, CONFIG_SOURCE, BASELINE_SOURCE_KEY);
        for (at, attr, v, want) in [
            (audit, ATTR_VALUE, None, "value"),
            (audit, ATTR_VALUE, Some(AttrValue::U64(1)), "value"),
            (src, "sha256", None, "sha256"),
            (src, "sha256", Some(AttrValue::Str("07".into())), "sha256"),
            (src, ATTR_MOVED_FROM, Some(AttrValue::U64(1)), "moved_from"),
        ] {
            assert_eq!(
                extract(&with_attr(&g, at, attr, v)),
                Err(IdentityError::BaselineAttr {
                    node: at.0,
                    attr: want
                }),
                "{attr}"
            );
        }
    }

    #[test]
    fn a_baseline_needs_a_named_section() {
        let g = graph(Some(&baseline()));
        let audit = id(&g, SECTION, &section_key("audit"));
        let core = id(&g, SECTION, &section_key("core"));
        let src = id(&g, CONFIG_SOURCE, BASELINE_SOURCE_KEY);
        assert_eq!(
            refusal(&without(&g, &[audit, core])),
            (src.0, "baseline without a section")
        );
        let unnamed = rebuilt(
            &g,
            |n| {
                let mut n = n.clone();
                if n.id == audit {
                    n.key = section_key("");
                }
                Some(n)
            },
            |_| true,
            vec![],
        );
        assert_eq!(
            refusal(&unnamed),
            (audit.0, "baseline section without a name")
        );
    }

    fn build_refusal(b: &BaselineLayer) -> &'static str {
        match build(
            &layer(),
            Some(b),
            &persisted_compiled_set("UNCLASSIFIED"),
            [9; 32],
            3,
            ProvenanceKind::RootFile,
        ) {
            Err(IdentityError::BaselineAmbiguous { what, .. }) => what,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_baseline_without_a_named_section_does_not_build() {
        let mut b = baseline();
        b.sections.clear();
        assert_eq!(build_refusal(&b), "baseline without a section");
        let mut b = baseline();
        b.sections.insert(String::new(), "{}".into());
        assert_eq!(build_refusal(&b), "baseline section without a name");
    }

    #[test]
    fn declares_and_level_of_can_only_reach_a_classification_system() {
        let triples = |kind| {
            SCHEMA
                .triples
                .iter()
                .filter(|(_, e, _)| *e == kind)
                .map(|(f, _, t)| (*f, *t))
                .collect::<Vec<_>>()
        };
        assert_eq!(triples(DECLARES), [(INSTANCE, CLASSIFICATION_SYSTEM)]);
        assert_eq!(triples(LEVEL_OF), [(LEVEL, CLASSIFICATION_SYSTEM)]);
    }
}
