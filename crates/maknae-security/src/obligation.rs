//! Obligations and their merge (spec §5, §8/G4, §13 step 3).
//!
//! Obligations are opaque `{id, params}` tokens; the seam never interprets them.
//! Merge is union + dedup by full `(id, params)`. A same-`id` / different-`params`
//! pair is an unrankable conflict over opaque tokens → the caller denies
//! (fail-closed): the generic composition layer cannot decide which is "more
//! restrictive".

use crate::value::Attributes;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Obligation {
    pub id: String,
    pub params: Attributes,
}

/// Returned when two obligations share an `id` but differ in `params`. A real
/// (non-`()`) error type is required — an exported `Result<_, ()>` trips
/// `clippy::result_unit_err` under the crate's `-D warnings` gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObligationConflict;

/// Union + dedup by full `(id, params)`. Same `id` / different `params` → `Err`
/// (caller denies, §13). Public so `maknae-authz-basic` can reuse it for its G4 union.
pub fn merge_obligations(
    a: Vec<Obligation>,
    b: Vec<Obligation>,
) -> Result<Vec<Obligation>, ObligationConflict> {
    let mut out: Vec<Obligation> = Vec::new();
    for o in a.into_iter().chain(b) {
        if out.iter().any(|e| e.id == o.id && e.params == o.params) {
            continue; // identical duplicate
        }
        if out.iter().any(|e| e.id == o.id && e.params != o.params) {
            return Err(ObligationConflict); // unrankable conflict
        }
        out.push(o);
    }
    Ok(out)
}

/// The `tool.launch` obligation's id and param keys (#674, spec §5.7): the recipe a front
/// end launches a permitted tool call from.
pub mod tool_launch {
    pub const ID: &str = "tool.launch";
    pub const ENTRY: &str = "entry";
    pub const PROGRAM: &str = "program";
    pub const MODE: &str = "mode";
    pub const SHAPE: &str = "shape";
    pub const IMAGE_REF: &str = "image.ref";
    pub const IMAGE_VERIFY_SIGNATURE: &str = "image.verify.signature";
    pub const IMAGE_VERIFY_SBOM: &str = "image.verify.sbom";
    pub const ISOLATION: &str = "isolation";
    pub const NETWORK_VIA: &str = "network.via";
    pub const NETWORK_SITES: &str = "network.sites";
    pub const CREDENTIAL: &str = "credential";
    pub const WORKSPACE_MODE: &str = "workspace.mode";
    pub const WORKSPACE_ROOT: &str = "workspace.root";
    pub const RESOURCES_CPUS: &str = "resources.cpus";
    pub const RESOURCES_MEMORY: &str = "resources.memory";
    pub const LIFETIME_MAX: &str = "lifetime.max";
    pub const TIMEOUT: &str = "timeout";
    pub const OUTPUT: &str = "output";
    pub const OUTPUT_TO_MODEL: &str = "output_to_model";
    pub const VOLUMES_NAME: &str = "volumes.name";
    pub const VOLUMES_ACCESS: &str = "volumes.access";
    pub const VOLUMES_SCOPE: &str = "volumes.scope";
    pub const SHAPE_SHA256: &str = "shape.sha256";
    pub const GRAMMAR_SHA256: &str = "grammar.sha256";
    pub const ARGV: &str = "argv";
    pub const STDIN_SHA256: &str = "stdin.sha256";
    pub const FILES_PATH: &str = "files.path";
    pub const FILES_SHA256: &str = "files.sha256";
    pub const FORGE_BASE: &str = "forge.base";
    pub const FORGE_HEAD: &str = "forge.head";
    pub const TASK: &str = "task";
    pub const SUBJECT_UID: &str = "subject.uid";
}

/// The `workspace.mask` obligation's id and its one param key.
pub mod workspace_mask {
    pub const ID: &str = "workspace.mask";
    pub const PATTERNS: &str = "patterns";
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::value::{AttrValue, Attributes};

    fn ob(id: &str, k: &str, v: i64) -> Obligation {
        let mut p = Attributes::new();
        p.insert(k, AttrValue::Int(v));
        Obligation {
            id: id.into(),
            params: p,
        }
    }

    #[test]
    fn union_dedups_identical() {
        let out = merge_obligations(
            vec![ob("rate-limit", "per_min", 10)],
            vec![ob("rate-limit", "per_min", 10)],
        )
        .unwrap();
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn union_keeps_distinct_ids() {
        let a = Obligation {
            id: "audit".into(),
            params: Attributes::new(),
        };
        let out = merge_obligations(vec![a], vec![ob("rate-limit", "per_min", 10)]).unwrap();
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn same_id_different_params_is_conflict_err() {
        let r = merge_obligations(
            vec![ob("rate-limit", "per_min", 10)],
            vec![ob("rate-limit", "per_min", 60)],
        );
        assert_eq!(r, Err(ObligationConflict)); // deny-on-conflict
    }
}
