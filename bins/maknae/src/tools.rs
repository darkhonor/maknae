//! `maknae tools`: the subject's own tool catalog, decoded and printed. A hint for the
//! reader; nothing here decides anything.
use crate::cli::terminal_safe;
use maknae_graph::catalog::{self, BINDING_KIND, ENTRY, RUNS};
use maknae_graph::graph::Graph;
use maknae_loop::catalog::{verify, CatalogRejected};
use maknae_proto::ToolCatalogReply;

pub(crate) fn catalog_lines(reply: &ToolCatalogReply) -> Result<Vec<String>, String> {
    let g = verify(reply).map_err(|e| match e {
        CatalogRejected::DigestMismatch => "protocol error: the catalog does not match its digest",
        CatalogRejected::Undecodable => "protocol error: the catalog does not decode",
    })?;
    Ok(lines(&g))
}

fn members(members: &[String]) -> String {
    members
        .iter()
        .map(|m| format!("{m:?}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn lines(g: &Graph) -> Vec<String> {
    let mut out = Vec::new();
    for entry in g.nodes().iter().filter(|n| n.kind == ENTRY) {
        out.push(terminal_safe(&entry.key));
        for run in g.out_edges(entry.id, RUNS) {
            let Some(program) = g.node(run.to) else {
                continue;
            };
            let name = program.key.rsplit('/').next().unwrap_or(&program.key);
            for pattern in catalog::patterns(g, &entry.key, name) {
                out.push(format!(
                    "  {}  {}",
                    terminal_safe(name),
                    terminal_safe(pattern)
                ));
            }
            if catalog::open_program(g, &entry.key, name) {
                out.push(format!("  {}  (open)", terminal_safe(name)));
            }
            for shape in catalog::shapes(g, &entry.key, name) {
                out.push(format!(
                    "  {}:{}  {}  {}",
                    terminal_safe(name),
                    terminal_safe(&shape.name),
                    terminal_safe(&shape.access),
                    terminal_safe(&shape.description)
                ));
                for slot in &shape.slots {
                    out.push(format!(
                        "    {}  {}  {}  {}",
                        terminal_safe(&slot.name),
                        terminal_safe(&slot.at),
                        terminal_safe(&members(&slot.members)),
                        terminal_safe(&slot.description)
                    ));
                }
            }
        }
    }
    let forges: Vec<String> = g
        .nodes()
        .iter()
        .filter(|n| n.kind == BINDING_KIND)
        .flat_map(|kind| {
            catalog::forges(g, &kind.key)
                .into_iter()
                .map(|(host, provider)| {
                    format!(
                        "  {}  {}  {}",
                        terminal_safe(&kind.key),
                        terminal_safe(host),
                        terminal_safe(provider)
                    )
                })
        })
        .collect();
    if !forges.is_empty() {
        out.push("forges:".into());
        out.extend(forges);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_graph::catalog::{CatalogEntry, CatalogForge, CatalogInput, CatalogOutput};
    use maknae_proto::CatalogDigest;

    fn reply() -> ToolCatalogReply {
        let bytes = catalog::encode(&CatalogInput {
            entries: vec![CatalogEntry {
                name: "git".into(),
                description: None,
                executes_workspace: false,
                output: CatalogOutput::Redacted,
                binds: vec!["git".into()],
                programs: vec![("git".into(), vec!["status".into(), "log *".into()])],
                open: vec![],
                shapes: vec![],
            }],
            forges: vec![CatalogForge {
                name: "hub".into(),
                kind: "git".into(),
                host: "github.com".into(),
                provider: "github".into(),
            }],
        })
        .unwrap();
        ToolCatalogReply {
            digest: CatalogDigest(maknae_crypto::sha256(&bytes)),
            graph: maknae_proto::Bytes::new(zeroize::Zeroizing::new(bytes)),
        }
    }

    #[test]
    fn it_prints_entries_then_patterns_then_forges_and_refuses_a_bad_digest() {
        assert_eq!(
            catalog_lines(&reply()).unwrap(),
            [
                "git",
                "  git  log *",
                "  git  status",
                "forges:",
                "  git  github.com  github"
            ]
        );
        let mut bad = reply();
        bad.digest = CatalogDigest([0; 32]);
        assert!(catalog_lines(&bad).is_err());
    }

    #[test]
    fn it_prints_open_programs_and_shapes_with_their_slots() {
        use maknae_graph::catalog::{CatalogShape, CatalogSlot};
        let bytes = catalog::encode(&CatalogInput {
            entries: vec![CatalogEntry {
                name: "gh".into(),
                description: None,
                executes_workspace: false,
                output: CatalogOutput::Redacted,
                binds: vec![],
                programs: vec![],
                open: vec!["sh".into()],
                shapes: vec![(
                    "gh".into(),
                    vec![CatalogShape {
                        name: "issue.list".into(),
                        description: "List issues.".into(),
                        access: "read".into(),
                        slots: vec![CatalogSlot {
                            name: "state".into(),
                            at: "option".into(),
                            members: vec!["all".into(), "a|b,c".into()],
                            description: "Which.".into(),
                        }],
                    }],
                )],
            }],
            forges: vec![],
        })
        .unwrap();
        let reply = ToolCatalogReply {
            digest: CatalogDigest(maknae_crypto::sha256(&bytes)),
            graph: maknae_proto::Bytes::new(zeroize::Zeroizing::new(bytes)),
        };
        assert_eq!(
            catalog_lines(&reply).unwrap(),
            [
                "gh",
                "  gh:issue.list  read  List issues.",
                "    state  option  \"all\",\"a|b,c\"  Which.",
                "  sh  (open)",
            ]
        );
    }

    #[test]
    fn the_tools_command_reads_nothing_under_etc_maknae() {
        let code = include_str!("tools.rs")
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        for needle in ["/etc/maknae", "tools.yaml", "maknae.yaml", "std::fs"] {
            assert!(!code.contains(needle), "{needle}");
        }
    }

    #[test]
    fn the_cli_tools_command_parses_and_prints() {
        use clap::Parser;
        let cli = crate::cli::Cli::try_parse_from(["maknae", "tools"]).expect("parses");
        assert!(crate::cli::is_tools(&cli));
        assert_eq!(
            maknae_proto::Verb::from(crate::cli::Verb::ToolCatalog),
            maknae_proto::Verb::ToolCatalog {}
        );
        assert_eq!(crate::cli::Verb::ToolCatalog.kind(), "tools");
        assert!(crate::cli::print_payload_for_verb(
            crate::cli::Verb::ToolCatalog,
            maknae_proto::Payload::ToolCatalog(reply())
        )
        .is_ok());
        let other = maknae_proto::Payload::Pong;
        assert!(
            crate::cli::print_payload_for_verb(crate::cli::Verb::ToolCatalog, other)
                .unwrap_err()
                .contains("pong")
        );
    }
}
