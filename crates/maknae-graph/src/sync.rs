use crate::graph::Graph;
use crate::identity::{bindings_section_key, IdentityError};
use crate::kernel::{ATTR_BASE, ATTR_CONFLICTS, ATTR_LIVE, PART_OF, SECTION, SYNC_BASE};
use crate::record::{AttrValue, NodeRecord};

const ABSENT: &str = "null";
const MISSING: &str = "missing";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncBase {
    pub base: String,
    pub live: String,
    pub conflicts: String,
}

pub fn sync_key(source: &str) -> String {
    format!("{source}#sync")
}

fn explicit(token: &str) -> bool {
    token != ABSENT && token != MISSING
}

fn ambiguous(n: &NodeRecord, what: &'static str) -> IdentityError {
    IdentityError::SyncAmbiguous { node: n.id.0, what }
}

fn attr(n: &NodeRecord, attr: &'static str) -> Result<String, IdentityError> {
    match n.attrs.get(attr) {
        Some(AttrValue::Str(s)) if !s.is_empty() => Ok(s.clone()),
        _ => Err(IdentityError::SyncAttr { node: n.id.0, attr }),
    }
}

pub fn extract(g: &Graph, source: Option<&NodeRecord>) -> Result<Option<SyncBase>, IdentityError> {
    let mut it = g.nodes().iter().filter(|n| n.kind == SYNC_BASE);
    let Some(n) = it.next() else {
        return Ok(None);
    };
    if let Some(second) = it.next() {
        return Err(ambiguous(second, "more than one sync base"));
    }
    let Some(src) = source else {
        return Err(ambiguous(n, "sync base without a policy source"));
    };
    if n.key != sync_key(&src.key) {
        return Err(ambiguous(n, "sync base keyed for another source"));
    }
    let mut parts = g.out_edges(n.id, PART_OF);
    if parts.next().map(|e| e.to) != Some(src.id) || parts.next().is_some() {
        return Err(ambiguous(n, "sync base outside the policy source"));
    }
    let s = SyncBase {
        base: attr(n, ATTR_BASE)?,
        live: attr(n, ATTR_LIVE)?,
        conflicts: attr(n, ATTR_CONFLICTS)?,
    };
    if explicit(&s.base) != explicit(&s.live) {
        return Err(ambiguous(
            n,
            "sync base live and base disagree on explicit bindings",
        ));
    }
    let section = g.lookup(SECTION, &bindings_section_key(&src.key)).is_some();
    if explicit(&s.live) != section {
        return Err(ambiguous(
            n,
            "sync base and bindings section disagree on explicit bindings",
        ));
    }
    Ok(Some(s))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::baseline::BaselineLayer;
    use crate::graph::GraphBuilder;
    use crate::identity::{bindings_section_key, build, extract, IdentityLayer, SubjectEntry};
    use crate::kernel::{
        persisted_compiled_set, ATTR_BASE, ATTR_CONFLICTS, ATTR_LIVE, CONFIG_SOURCE, PART_OF,
        SCHEMA, SECTION, SUBJECT, SYNC_BASE, VOCABULARY_SOURCE_KEY,
    };
    use crate::record::{AttrValue, EdgeId, EdgeRecord, NodeId, ProvenanceKind};

    const SOURCE: &str = "/etc/maknae/bindings.yaml";

    fn layer() -> IdentityLayer {
        IdentityLayer {
            source: SOURCE.into(),
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

    fn keyless() -> IdentityLayer {
        IdentityLayer {
            bindings_sha256: None,
            ..layer()
        }
    }

    fn sync() -> SyncBase {
        SyncBase {
            base: r#"{"admin":["root"]}"#.into(),
            live: r#"{"admin":["root"],"adversary":[{"uid":7}]}"#.into(),
            conflicts: "[]".into(),
        }
    }

    fn tokens(base: &str, live: &str) -> SyncBase {
        SyncBase {
            base: base.into(),
            live: live.into(),
            conflicts: "[]".into(),
        }
    }

    fn built(l: &IdentityLayer, s: Option<&SyncBase>) -> Result<Graph, IdentityError> {
        build(
            l,
            None,
            s,
            &persisted_compiled_set("UNCLASSIFIED"),
            [9; 32],
            3,
            ProvenanceKind::RootFile,
        )
    }

    fn graph(s: Option<&SyncBase>) -> Graph {
        built(&layer(), s).unwrap()
    }

    #[test]
    fn the_sync_key_names_the_bindings_source() {
        assert_eq!(sync_key(SOURCE), "/etc/maknae/bindings.yaml#sync");
    }

    #[test]
    fn a_built_sync_base_extracts_unchanged_and_hangs_off_the_bindings_source() {
        let g = graph(Some(&sync()));
        let e = extract(&g).unwrap();
        assert_eq!(e.sync, Some(sync()));
        assert_eq!(e.layer, layer());
        let n = g.lookup(SYNC_BASE, &sync_key(SOURCE)).unwrap();
        let to: Vec<_> = g
            .out_edges(n.id, PART_OF)
            .map(|e| g.node(e.to).unwrap().key.clone())
            .collect();
        assert_eq!(to, [SOURCE]);
        assert_eq!(n.provenance.kind, ProvenanceKind::RootFile);
        assert_eq!(n.label, "UNCLASSIFIED");
        for (attr, v) in [
            (ATTR_BASE, sync().base),
            (ATTR_LIVE, sync().live),
            (ATTR_CONFLICTS, sync().conflicts),
        ] {
            assert_eq!(n.attrs.get(attr), Some(&AttrValue::Str(v)), "{attr}");
        }
        assert_eq!(n.attrs.len(), 3);
        assert!(SCHEMA.allows(SYNC_BASE, PART_OF, CONFIG_SOURCE));
    }

    #[test]
    fn build_extract_build_is_the_identity_and_none_builds_no_node() {
        let g = graph(Some(&sync()));
        let e = extract(&g).unwrap();
        assert_eq!(
            build(
                &e.layer,
                None,
                e.sync.as_ref(),
                &persisted_compiled_set("UNCLASSIFIED"),
                [9; 32],
                3,
                ProvenanceKind::RootFile
            )
            .unwrap(),
            g
        );
        assert_eq!(extract(&graph(None)).unwrap().sync, None);
        assert!(graph(None).nodes().iter().all(|n| n.kind != SYNC_BASE));
    }

    #[test]
    fn a_sync_base_beside_a_baseline_round_trips_through_the_codec() {
        let bl = BaselineLayer {
            sections: [("core".to_string(), r#"{"deployment_id":"d"}"#.to_string())]
                .into_iter()
                .collect(),
            system: "US".into(),
            ceiling: "UNCLASSIFIED".into(),
            sha256: [7; 32],
            moved_from: None,
        };
        let g = build(
            &layer(),
            Some(&bl),
            Some(&sync()),
            &persisted_compiled_set("UNCLASSIFIED"),
            [9; 32],
            3,
            ProvenanceKind::RootFile,
        )
        .unwrap();
        let bytes = crate::format::encode(&g);
        let back = crate::format::decode(
            &bytes,
            crate::record::GraphSpace::Kernel,
            &SCHEMA,
            &persisted_compiled_set("UNCLASSIFIED"),
        )
        .unwrap();
        assert_eq!(crate::format::encode(&back), bytes);
        let e = extract(&back).unwrap();
        assert_eq!((e.sync, e.baseline), (Some(sync()), Some(bl)));
    }

    #[test]
    fn absent_and_missing_tokens_are_not_explicit() {
        for (l, s) in [
            (keyless(), tokens("null", "null")),
            (keyless(), tokens("missing", "missing")),
            (keyless(), tokens("null", "missing")),
            (keyless(), tokens("missing", "null")),
            (layer(), tokens(r#"{"admin":[]}"#, r#"{"admin":["root"]}"#)),
        ] {
            let g = built(&l, Some(&s)).unwrap();
            assert_eq!(extract(&g).unwrap().sync, Some(s.clone()), "{s:?}");
        }
    }

    #[test]
    fn build_refuses_an_empty_attribute_naming_the_policy_source() {
        for (attr, s) in [
            (
                ATTR_BASE,
                SyncBase {
                    base: String::new(),
                    ..sync()
                },
            ),
            (
                ATTR_LIVE,
                SyncBase {
                    live: String::new(),
                    ..sync()
                },
            ),
            (
                ATTR_CONFLICTS,
                SyncBase {
                    conflicts: String::new(),
                    ..sync()
                },
            ),
        ] {
            assert_eq!(
                built(&layer(), Some(&s)),
                Err(IdentityError::SyncAttr { node: 1, attr }),
                "{attr}"
            );
        }
        let g = graph(Some(&sync()));
        assert_eq!(g.lookup(CONFIG_SOURCE, SOURCE).unwrap().id, NodeId(1));
    }

    #[test]
    fn extract_refuses_every_malformed_sync_base() {
        let mut absent_live = sync();
        absent_live.live = "null".into();
        assert!(matches!(
            built(&layer(), Some(&absent_live)).map(|g| extract(&g)),
            Ok(Err(IdentityError::SyncAmbiguous {
                what: "sync base live and base disagree on explicit bindings",
                ..
            }))
        ));
        let explicit_without_section = built(&keyless(), Some(&sync())).unwrap();
        assert!(matches!(
            extract(&explicit_without_section),
            Err(IdentityError::SyncAmbiguous {
                what: "sync base and bindings section disagree on explicit bindings",
                ..
            })
        ));
        for (what, g, want) in malformed(&graph(Some(&sync()))) {
            assert_eq!(extract(&g).map(|_| ()), Err(want), "{what}");
        }
        for (what, l, s, want) in inconsistent() {
            let g = built(&l, Some(&s)).unwrap();
            let node = g.lookup(SYNC_BASE, &sync_key(SOURCE)).unwrap().id.0;
            assert_eq!(
                extract(&g).map(|_| ()),
                Err(IdentityError::SyncAmbiguous { node, what: want }),
                "{what}"
            );
        }
    }

    const LIVE_BASE: &str = "sync base live and base disagree on explicit bindings";
    const SECTION_LIVE: &str = "sync base and bindings section disagree on explicit bindings";

    fn inconsistent() -> Vec<(&'static str, IdentityLayer, SyncBase, &'static str)> {
        let explicit = r#"{"admin":["root"]}"#;
        vec![
            (
                "absent base, explicit live",
                layer(),
                tokens("null", explicit),
                LIVE_BASE,
            ),
            (
                "missing base, explicit live",
                layer(),
                tokens("missing", explicit),
                LIVE_BASE,
            ),
            (
                "explicit base, absent live",
                layer(),
                tokens(explicit, "null"),
                LIVE_BASE,
            ),
            (
                "explicit base, missing live",
                layer(),
                tokens(explicit, "missing"),
                LIVE_BASE,
            ),
            (
                "explicit live, no section",
                keyless(),
                tokens(explicit, explicit),
                SECTION_LIVE,
            ),
            (
                "absent live, a section",
                layer(),
                tokens("null", "null"),
                SECTION_LIVE,
            ),
            (
                "missing live, a section",
                layer(),
                tokens("missing", "missing"),
                SECTION_LIVE,
            ),
        ]
    }

    fn regraph(
        g: &Graph,
        map_node: impl Fn(&NodeRecord) -> Option<NodeRecord>,
        keep_edge: impl Fn(&EdgeRecord) -> bool,
        extra_nodes: Vec<NodeRecord>,
        extra_edges: Vec<EdgeRecord>,
    ) -> Graph {
        let nodes: Vec<NodeRecord> = g
            .nodes()
            .iter()
            .filter_map(map_node)
            .chain(extra_nodes)
            .collect();
        let kept = |id: NodeId| nodes.iter().any(|n| n.id == id);
        let edges: Vec<EdgeRecord> = g
            .edges()
            .iter()
            .filter(|e| keep_edge(e) && kept(e.from) && kept(e.to))
            .cloned()
            .chain(extra_edges)
            .collect();
        let b = GraphBuilder::new(g.space(), g.revision());
        let b = nodes.into_iter().fold(b, |b, n| b.node(n));
        edges
            .into_iter()
            .fold(b, |b, e| b.edge(e))
            .build(&SCHEMA, &persisted_compiled_set("UNCLASSIFIED"))
            .unwrap()
    }

    fn with_attr(g: &Graph, at: NodeId, attr: &'static str, v: Option<AttrValue>) -> Graph {
        regraph(
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
            vec![],
        )
    }

    fn part_of(g: &Graph, id: u64, from: NodeId, to: NodeId) -> EdgeRecord {
        EdgeRecord {
            id: EdgeId(id),
            from,
            to,
            ..g.edges()
                .iter()
                .find(|e| e.kind == PART_OF)
                .unwrap()
                .clone()
        }
    }

    fn malformed(g: &Graph) -> Vec<(String, Graph, IdentityError)> {
        let sb = g.lookup(SYNC_BASE, &sync_key(SOURCE)).unwrap().clone();
        let src = g.lookup(CONFIG_SOURCE, SOURCE).unwrap().id;
        let vocab = g.lookup(CONFIG_SOURCE, VOCABULARY_SOURCE_KEY).unwrap().id;
        let next_node = g.nodes().iter().map(|n| n.id.0).max().unwrap() + 1;
        let next_edge = g.edges().iter().map(|e| e.id.0).max().unwrap() + 1;
        let attr = |attr| IdentityError::SyncAttr {
            node: sb.id.0,
            attr,
        };
        let amb = |node: NodeId, what| IdentityError::SyncAmbiguous { node: node.0, what };
        let mut out = Vec::new();
        for a in [ATTR_BASE, ATTR_LIVE, ATTR_CONFLICTS] {
            for (how, v) in [
                ("dropped", None),
                ("retyped", Some(AttrValue::U64(1))),
                ("emptied", Some(AttrValue::Str(String::new()))),
            ] {
                out.push((format!("{a} {how}"), with_attr(g, sb.id, a, v), attr(a)));
            }
        }
        let second = NodeRecord {
            id: NodeId(next_node),
            key: "/etc/maknae/other.yaml#sync".into(),
            ..sb.clone()
        };
        out.push((
            "a second sync base".into(),
            regraph(
                g,
                |n| Some(n.clone()),
                |_| true,
                vec![second.clone()],
                vec![part_of(g, next_edge, second.id, src)],
            ),
            amb(second.id, "more than one sync base"),
        ));
        out.push((
            "re-keyed".into(),
            regraph(
                g,
                |n| {
                    let mut n = n.clone();
                    if n.id == sb.id {
                        n.key = "/etc/maknae/authz.yaml#sync".into();
                    }
                    Some(n)
                },
                |_| true,
                vec![],
                vec![],
            ),
            amb(sb.id, "sync base keyed for another source"),
        ));
        let outside = "sync base outside the policy source";
        let from_sb = |e: &EdgeRecord| e.from == sb.id;
        out.push((
            "part_of dropped".into(),
            regraph(g, |n| Some(n.clone()), |e| !from_sb(e), vec![], vec![]),
            amb(sb.id, outside),
        ));
        out.push((
            "part_of doubled".into(),
            regraph(
                g,
                |n| Some(n.clone()),
                |_| true,
                vec![],
                vec![part_of(g, next_edge, sb.id, src)],
            ),
            amb(sb.id, outside),
        ));
        out.push((
            "part_of the vocabulary source".into(),
            regraph(
                g,
                |n| Some(n.clone()),
                |e| !from_sb(e),
                vec![],
                vec![part_of(g, next_edge, sb.id, vocab)],
            ),
            amb(sb.id, outside),
        ));
        out.push((
            "part_of the policy source and the vocabulary source".into(),
            regraph(
                g,
                |n| Some(n.clone()),
                |_| true,
                vec![],
                vec![part_of(g, next_edge, sb.id, vocab)],
            ),
            amb(sb.id, outside),
        ));
        out.push((
            "no policy source".into(),
            regraph(
                g,
                |n| (n.id != src && n.kind != SUBJECT).then(|| n.clone()),
                |_| true,
                vec![],
                vec![],
            ),
            amb(sb.id, "sync base without a policy source"),
        ));
        let section = g.lookup(SECTION, &bindings_section_key(SOURCE)).unwrap().id;
        out.push((
            "the bindings section removed".into(),
            regraph(
                g,
                |n| (n.id != section).then(|| n.clone()),
                |_| true,
                vec![],
                vec![],
            ),
            amb(sb.id, SECTION_LIVE),
        ));
        out
    }
}
