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
    for o in a.into_iter().chain(b.into_iter()) {
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
