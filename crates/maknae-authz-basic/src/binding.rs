//! Subject → role binding resolution (#85, spec §3/§3a/§3b).
//!
//! Identity semantics (ADR-0018: the per-request authorization principal is
//! the **uid**): `bindings:` entries are operator-facing usernames, resolved
//! to uids ONCE at [`crate::BasicAuthorizer`] construction (the `UidMap`);
//! matching is uid vs uid. The reserved token `agent` always means the
//! runtime subject — it is never looked up and a host account literally named
//! `agent` cannot be bound by username (single meaning, spec §3).
//!
//! Fail-closed everywhere: unknown role key, dual membership, a duplicate
//! name, or a name absent from the `UidMap` (a brand-new username edited into
//! the file after construction — adding principals is restart-scoped in v0.1,
//! spec §3) all make the policy invalid.

use crate::role::Role;
use std::collections::BTreeMap;

/// The reserved runtime-subject token (spec §3/§6): stamped by the daemon
/// door on runtime-originated requests, never resolved through NSS.
pub(crate) const AGENT_SUBJECT: &str = "agent";

/// username → uid, built once at construction via getpwnam (`agent` excluded).
pub(crate) type UidMap = BTreeMap<String, u32>;

/// Validated, uid-keyed bindings for one loaded policy snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ResolvedBindings {
    by_uid: BTreeMap<u32, Role>,
    agent: Option<Role>,
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
            agent: None,
            explicit: false,
        });
    };
    let mut by_uid: BTreeMap<u32, Role> = BTreeMap::new();
    let mut agent: Option<Role> = None;
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
            if name == AGENT_SUBJECT {
                agent = Some(role);
                continue;
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
        agent,
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
    /// MEMBERS ARE REPORTED BY UID; the reserved `agent` token by its name.
    ///
    /// Worth naming, because the sibling rationale on `Role::key` argues the
    /// opposite direction for roles ("the token an operator would grep for in
    /// `authz.yaml`"). `root` reports as `uid:0`, which appears in no policy
    /// file. The uid IS the authenticated datum (ADR-0018) and the thing
    /// `role_for` keys on, so it is the honest answer to "who is bound"; a
    /// name is an input resolved once at construction that may since have been
    /// re-pointed. `agent` has no uid by construction, so it reports as itself.
    pub(crate) fn as_subject_bindings(&self) -> Option<Vec<maknae_security::SubjectBinding>> {
        // NO `bindings:` KEY -> `None`, not an empty list.
        //
        // The shipped `packaging/common/authz.yaml` has no `bindings:` key, so
        // the default deployment took this path and rendered `Some(vec![])` --
        // "these are the bindings, and there are none" -- while the DEFAULT
        // ROLE FALLBACK was live and the enrolled uid was resolving to admin.
        // Three materially different states (agent-only bindings, `bindings:
        // {}`, and no-key-with-fallback-active) all read identically as
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
        // The AGENT binding is a real binding and is reported.
        //
        // It lives in its own field because the reserved token has no uid by
        // construction, and reading only `by_uid` dropped it: a policy with
        // `bindings: { admin: ["agent"] }` reported an empty list while
        // `role_for` granted admin to the UNTRUSTED AGENT RUNTIME on that same
        // binding. An operator auditing "is the agent bound to admin?" was
        // told nobody was.
        if let Some(role) = self.agent {
            out.entry(role.key().to_string())
                .or_default()
                .push(AGENT_SUBJECT.to_string());
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

    /// Subject → role, in the FIXED order of spec §3b: reserved subject name
    /// first (never through uid), then uid; defaults only when the file had
    /// no `bindings:` key.
    pub(crate) fn role_for(
        &self,
        subject_name: Option<&str>,
        uid: Option<u32>,
        principal_uid: u32,
    ) -> Resolution {
        if subject_name == Some(AGENT_SUBJECT) {
            return match (self.explicit, self.agent) {
                (true, Some(r)) => Resolution::Role(r),
                (true, None) => Resolution::NoRole,
                (false, _) => Resolution::Role(Role::User),
            };
        }
        match uid {
            Some(u) => {
                if self.explicit {
                    match self.by_uid.get(&u) {
                        Some(r) => Resolution::Role(*r),
                        None => Resolution::NoRole,
                    }
                } else if u == principal_uid {
                    Resolution::Role(Role::Admin)
                } else {
                    Resolution::NoRole
                }
            }
            None => Resolution::NoRole,
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

    #[test]
    fn agent_token_is_never_looked_up() {
        // Empty UidMap proves no lookup happens for the reserved token.
        let r = resolve(&b(&[("adversary", &[AGENT_SUBJECT])]), &UidMap::new()).unwrap();
        assert_eq!(
            r.role_for(Some(AGENT_SUBJECT), None, PRINCIPAL_UID),
            Resolution::Role(Role::Adversary)
        );
    }

    #[test]
    fn present_but_empty_bindings_suppress_defaults_entirely() {
        // The no-discretionary-admin posture (spec §3): with an explicit
        // empty map, even the enrolled principal has NO role.
        let r = resolve(&Some(BTreeMap::new()), &UidMap::new()).unwrap();
        assert_eq!(
            r.role_for(None, Some(PRINCIPAL_UID), PRINCIPAL_UID),
            Resolution::NoRole
        );
        assert_eq!(
            r.role_for(Some(AGENT_SUBJECT), None, PRINCIPAL_UID),
            Resolution::NoRole
        );
    }

    #[test]
    fn absent_bindings_apply_defaults() {
        let r = resolve(&None, &UidMap::new()).unwrap();
        assert_eq!(
            r.role_for(None, Some(PRINCIPAL_UID), PRINCIPAL_UID),
            Resolution::Role(Role::Admin)
        );
        assert_eq!(
            r.role_for(Some(AGENT_SUBJECT), None, PRINCIPAL_UID),
            Resolution::Role(Role::User)
        );
        assert_eq!(
            r.role_for(None, Some(999), PRINCIPAL_UID),
            Resolution::NoRole
        );
    }

    #[test]
    fn reserved_name_resolves_before_uid_closing_the_single_user_host_hole() {
        // Agent under the OPERATOR'S uid still lands in user, never admin
        // (spec §3b): the reserved name short-circuits uid resolution.
        let r = resolve(&None, &UidMap::new()).unwrap();
        assert_eq!(
            r.role_for(Some(AGENT_SUBJECT), Some(PRINCIPAL_UID), PRINCIPAL_UID),
            Resolution::Role(Role::User)
        );
    }

    #[test]
    fn explicit_bindings_bind_by_resolved_uid() {
        let r = resolve(
            &b(&[("admin", &["alex"]), ("adversary", &["mallory"])]),
            &uids(&[("alex", 501), ("mallory", 666)]),
        )
        .unwrap();
        assert_eq!(
            r.role_for(None, Some(501), 501),
            Resolution::Role(Role::Admin)
        );
        assert_eq!(
            r.role_for(None, Some(666), 501),
            Resolution::Role(Role::Adversary)
        );
        assert_eq!(r.role_for(None, Some(1000), 501), Resolution::NoRole);
    }

    #[test]
    fn missing_uid_with_no_reserved_name_is_no_role() {
        let r = resolve(&None, &UidMap::new()).unwrap();
        assert_eq!(r.role_for(None, None, PRINCIPAL_UID), Resolution::NoRole);
    }
}
