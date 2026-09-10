//! Subject → role binding resolution (#85, spec §3/§3a/§3b).
//!
//! Identity semantics (ADR-0018: the per-request authorization principal is
//! the **uid**): `bindings:` entries are operator-facing usernames, resolved
//! to uids ONCE at [`crate::BasicAuthorizer`] construction (the `UidMap`);
//! **matching is uid vs uid, with no exception.**
//!
//! A reserved `agent` token used to sit beside the uid map, meaning the runtime
//! subject and never looked up. [ADR-0024](../../../design/adr/ADR-0024-tenancy-model-and-agent-identity.md)
//! decision 3 struck it: Maknae is multi-tenant, and one reserved runtime token
//! cannot express two agent personas. An agent holds no identity of its own —
//! it acts within a delegation from the human who invoked it — so ADR-0018's
//! uid principal now applies uniformly. `agent` is an ordinary username: if a
//! deployer creates such an account and binds it, it resolves through NSS like
//! any other, which is their call to make and not this crate's (#276).
//!
//! Fail-closed everywhere: unknown role key, dual membership, a duplicate
//! name, or a name absent from the `UidMap` (a brand-new username edited into
//! the file after construction — adding principals is restart-scoped in v0.1,
//! spec §3) all make the policy invalid.

use crate::role::Role;
use std::collections::BTreeMap;

/// username → uid, built once at construction via getpwnam.
pub(crate) type UidMap = BTreeMap<String, u32>;

/// Validated, uid-keyed bindings for one loaded policy snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResolvedBindings {
    by_uid: BTreeMap<u32, Role>,
    /// The `bindings:` key was PRESENT in the file → defaults suppressed
    /// entirely (spec §3 precedence; what makes `admin: []` mean "no admin").
    explicit: bool,
}

/// Why a `bindings:` block is invalid (spec §3a). Every variant names the
/// offending token so the boot refusal / audit record is actionable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum BindingError {
    UnknownRole(String),
    DualMembership(String),
    Duplicate(String),
    Unresolvable(String),
}

impl std::fmt::Display for BindingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BindingError::UnknownRole(k) => write!(f, "bindings names unknown role '{k}'"),
            BindingError::DualMembership(n) => {
                write!(f, "identity '{n}' appears in more than one role")
            }
            BindingError::Duplicate(n) => write!(f, "identity '{n}' listed twice in one role"),
            BindingError::Unresolvable(n) => {
                write!(
                    f,
                    "identity '{n}' has no resolved uid (restart to add principals)"
                )
            }
        }
    }
}

/// The outcome of subject resolution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Resolution {
    Role(Role),
    NoRole,
}

/// Validate a parsed `bindings` value against the closed role vocabulary and
/// the construction-time `UidMap`.
pub(crate) fn resolve(
    bindings: &Option<BTreeMap<String, Vec<String>>>,
    lookup: &UidMap,
) -> Result<ResolvedBindings, BindingError> {
    let Some(map) = bindings else {
        return Ok(ResolvedBindings {
            by_uid: BTreeMap::new(),
            explicit: false,
        });
    };
    let mut by_uid: BTreeMap<u32, Role> = BTreeMap::new();
    let mut seen: BTreeMap<&str, ()> = BTreeMap::new();
    for (key, members) in map {
        let role = Role::from_key(key).ok_or_else(|| BindingError::UnknownRole(key.clone()))?;
        for name in members {
            if seen.insert(name.as_str(), ()).is_some() {
                // Same name earlier — in this role (Duplicate) or another
                // (DualMembership). Distinguish for the error message only;
                // both refuse.
                let dup_in_this_role = members
                    .iter()
                    .filter(|m| m.as_str() == name.as_str())
                    .count()
                    > 1;
                return Err(if dup_in_this_role {
                    BindingError::Duplicate(name.clone())
                } else {
                    BindingError::DualMembership(name.clone())
                });
            }
            let uid = lookup
                .get(name)
                .copied()
                .ok_or_else(|| BindingError::Unresolvable(name.clone()))?;
            by_uid.insert(uid, role);
        }
    }
    Ok(ResolvedBindings {
        by_uid,
        explicit: true,
    })
}

impl ResolvedBindings {
    /// Render as seam-level bindings for `admin.subject.list`.
    ///
    /// Reports what the POLICY FILE binds -- the explicit `bindings:` block --
    /// and nothing else. The default-role fallback (an enrolled uid resolving
    /// to admin when no bindings key is present) is a decision rule, not a
    /// binding, and listing it as one would tell an operator a binding exists
    /// that they could then look for in the file and not find.
    /// MEMBERS ARE REPORTED BY UID -- every binding has one since #276.
    ///
    /// Worth naming, because the sibling rationale on `Role::key` argues the
    /// opposite direction for roles ("the token an operator would grep for in
    /// `authz.yaml`"). `root` reports as `uid:0`, which appears in no policy
    /// file. The uid IS the authenticated datum (ADR-0018) and the thing
    /// `role_for` keys on, so it is the honest answer to "who is bound"; a
    /// name is an input resolved once at construction that may since have been
    pub(crate) fn as_subject_bindings(&self) -> Option<Vec<maknae_security::SubjectBinding>> {
        // NO `bindings:` KEY -> `None`, not an empty list.
        //
        // The shipped `packaging/common/authz.yaml` has no `bindings:` key, so
        // the default deployment took this path and rendered `Some(vec![])` --
        // "these are the bindings, and there are none" -- while the DEFAULT
        // ROLE FALLBACK was live and the enrolled uid was resolving to admin.
        // Materially different states (`bindings: {}` and
        // no-key-with-fallback-active) would otherwise read identically as
        // "nobody is bound", which is exactly the claim the `Option` on this
        // seam exists to refuse. Only an EXPLICIT block can report a set.
        if !self.explicit {
            return None;
        }
        let mut out: std::collections::BTreeMap<String, Vec<String>> = Default::default();
        for (uid, role) in self.by_uid.iter() {
            out.entry(role.key().to_string())
                .or_default()
                .push(format!("uid:{uid}"));
        }
        Some(
            out.into_iter()
                .map(|(role, mut members)| {
                    members.sort();
                    maknae_security::SubjectBinding { role, members }
                })
                .collect(),
        )
    }

    /// Subject → role, on the uid alone.
    ///
    /// A reserved-subject-name arm used to run FIRST, never through uid
    /// (spec §3b's fixed order). [ADR-0024](../../../design/adr/ADR-0024-tenancy-model-and-agent-identity.md)
    /// decision 3 struck the reserved token, so there is no longer an ordering
    /// to state: there is one lookup (#276).
    ///
    /// `uid` is `u32`, not `Option<u32>`: the caller
    /// ([`crate::decide::decide_loaded_with_role`]) returns `Indeterminate`
    /// before reaching here when the subject carries no uid. An arm for the
    /// absent case would be production-unreachable, and in a `[t1]`
    /// zero-missed-mutant file an unreachable arm's mutants are unkillable.
    ///
    /// Defaults apply only when the file had no `bindings:` key.
    pub(crate) fn role_for(&self, uid: u32, principal_uid: u32) -> Resolution {
        if self.explicit {
            match self.by_uid.get(&uid) {
                Some(r) => Resolution::Role(*r),
                None => Resolution::NoRole,
            }
        } else if uid == principal_uid {
            Resolution::Role(Role::Admin)
        } else {
            Resolution::NoRole
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b(pairs: &[(&str, &[&str])]) -> Option<BTreeMap<String, Vec<String>>> {
        Some(
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.iter().map(|s| s.to_string()).collect()))
                .collect(),
        )
    }

    fn uids(pairs: &[(&str, u32)]) -> UidMap {
        pairs.iter().map(|(n, u)| (n.to_string(), *u)).collect()
    }

    const PRINCIPAL_UID: u32 = 501;

    #[test]
    fn unknown_role_key_is_refused_never_defaulted() {
        let got = resolve(&b(&[("advesary", &["alex"])]), &uids(&[("alex", 501)]));
        assert_eq!(got, Err(BindingError::UnknownRole("advesary".into())));
    }

    #[test]
    fn a_name_in_two_role_sets_is_dual_membership() {
        let got = resolve(
            &b(&[("admin", &["alex"]), ("user", &["alex"])]),
            &uids(&[("alex", 501)]),
        );
        assert_eq!(got, Err(BindingError::DualMembership("alex".into())));
    }

    #[test]
    fn a_name_twice_in_one_list_is_duplicate() {
        let got = resolve(&b(&[("user", &["alex", "alex"])]), &uids(&[("alex", 501)]));
        assert_eq!(got, Err(BindingError::Duplicate("alex".into())));
    }

    #[test]
    fn a_name_missing_from_the_uid_map_is_unresolvable() {
        // Spec §3: a brand-new username edited into the file after
        // construction fails closed until restart.
        let got = resolve(&b(&[("user", &["nobody-new"])]), &UidMap::new());
        assert_eq!(got, Err(BindingError::Unresolvable("nobody-new".into())));
    }

    /// #276: `agent` is an ordinary username now. It resolves through NSS like
    /// any other bound name and fails closed when no such account exists --
    /// which is the behaviour change an operator could actually notice, so it
    /// gets a test. Replaces `agent_token_is_never_looked_up`, whose subject
    /// (a name that bypasses the uid map) no longer exists.
    #[test]
    fn agent_is_an_ordinary_name_and_fails_closed_when_unresolvable() {
        let got = resolve(&b(&[("adversary", &["agent"])]), &UidMap::new());
        assert_eq!(got, Err(BindingError::Unresolvable("agent".into())));
        // And when it DOES resolve, it binds like any other name.
        let r = resolve(&b(&[("adversary", &["agent"])]), &uids(&[("agent", 4242)])).unwrap();
        assert_eq!(
            r.role_for(4242, PRINCIPAL_UID),
            Resolution::Role(Role::Adversary)
        );
    }

    #[test]
    fn present_but_empty_bindings_suppress_defaults_entirely() {
        // The no-discretionary-admin posture (spec §3): with an explicit
        // empty map, even the enrolled principal has NO role.
        let r = resolve(&Some(BTreeMap::new()), &UidMap::new()).unwrap();
        assert_eq!(r.role_for(PRINCIPAL_UID, PRINCIPAL_UID), Resolution::NoRole);
    }

    #[test]
    fn absent_bindings_apply_defaults() {
        let r = resolve(&None, &UidMap::new()).unwrap();
        assert_eq!(
            r.role_for(PRINCIPAL_UID, PRINCIPAL_UID),
            Resolution::Role(Role::Admin)
        );
        assert_eq!(r.role_for(999, PRINCIPAL_UID), Resolution::NoRole);
    }

    #[test]
    fn explicit_bindings_bind_by_resolved_uid() {
        let r = resolve(
            &b(&[("admin", &["alex"]), ("adversary", &["mallory"])]),
            &uids(&[("alex", 501), ("mallory", 666)]),
        )
        .unwrap();
        assert_eq!(r.role_for(501, 501), Resolution::Role(Role::Admin));
        assert_eq!(r.role_for(666, 501), Resolution::Role(Role::Adversary));
        assert_eq!(r.role_for(1000, 501), Resolution::NoRole);
    }

    // `missing_uid_with_no_reserved_name_is_no_role` retired with its subject
    // (#276): `role_for` now takes `u32`, so "no uid" is not expressible here.
    // The property moved UP to `decide_loaded_with_role`'s guard, which returns
    // Indeterminate before reaching this function -- see
    // `decide::tests::missing_identity_is_indeterminate_distinct_from_unbound`.
}
