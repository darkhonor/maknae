//! `maknae tools`: the subject's own tool catalog, decoded and printed. A hint for the
//! reader; nothing here decides anything.
use crate::cli::terminal_safe;
use maknae_graph::catalog::{self, BINDING_KIND, ENTRY, RUNS};
use maknae_graph::graph::Graph;
use maknae_proto::{CatalogDigest, ToolCatalogReply};

pub(crate) fn catalog_lines(reply: &ToolCatalogReply) -> Result<Vec<String>, String> {
    if CatalogDigest(maknae_crypto::sha256(&reply.graph.0)) != reply.digest {
        return Err("protocol error: the catalog does not match its digest".into());
    }
    let g = catalog::decode(&reply.graph.0).map_err(|e| format!("protocol error: {e}"))?;
    Ok(lines(&g))
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

    fn reply() -> ToolCatalogReply {
        let bytes = catalog::encode(&CatalogInput {
            entries: vec![CatalogEntry {
                name: "git".into(),
                description: None,
                executes_workspace: false,
                output: CatalogOutput::Redacted,
                binds: vec!["git".into()],
                programs: vec![("git".into(), vec!["status".into(), "log *".into()])],
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
