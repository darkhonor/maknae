//! The four shipped roles (#85, spec §2). Code-defined and structural: the
//! semantics of `Adversary` (containment: deny everything) and `Guest`
//! (liveness only) are pinned here and in `decide.rs`, never configurable
//! away. Custom yaml-defined roles are post-v1.0 (spec §8); until then the
//! vocabulary is exactly these four and an unknown role NAME anywhere in
//! `bindings:` refuses the policy (the `advesary`-typo rule).

/// One of the four shipped roles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Role {
    Admin,
    User,
    Guest,
    Adversary,
}

impl Role {
    /// The closed role vocabulary: a `bindings:` key must be exactly one of
    /// these four names. `None` = unknown → the caller refuses the policy
    /// (never defaults — a typo must not silently drop a subject to a
    /// different role).
    /// The policy-file spelling of this role — the inverse of [`Role::from_key`],
    /// so `admin.subject.list` reports the token an operator would grep for in
    /// `authz.yaml` rather than a Rust variant name.
    pub(crate) fn key(&self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::User => "user",
            Role::Guest => "guest",
            Role::Adversary => "adversary",
        }
    }

    pub(crate) fn from_key(k: &str) -> Option<Role> {
        match k {
            "admin" => Some(Role::Admin),
            "user" => Some(Role::User),
            "guest" => Some(Role::Guest),
            "adversary" => Some(Role::Adversary),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `key` is the inverse of `from_key`, and the round trip is the property
    /// worth holding: `admin.subject.list` reports the token an operator would
    /// grep for in `authz.yaml`, so a drift between the two spellings would
    /// disclose a role name that does not exist in any policy file.
    #[test]
    fn key_round_trips_through_from_key_for_every_role() {
        for r in [Role::Admin, Role::User, Role::Guest, Role::Adversary] {
            assert_eq!(Role::from_key(r.key()), Some(r), "round trip for {r:?}");
        }
        assert_eq!(Role::Admin.key(), "admin");
        assert_eq!(Role::Adversary.key(), "adversary");
    }

    #[test]
    fn the_vocabulary_is_exactly_the_four_shipped_names() {
        assert_eq!(Role::from_key("admin"), Some(Role::Admin));
        assert_eq!(Role::from_key("user"), Some(Role::User));
        assert_eq!(Role::from_key("guest"), Some(Role::Guest));
        assert_eq!(Role::from_key("adversary"), Some(Role::Adversary));
    }

    #[test]
    fn unknown_and_near_miss_names_are_refused_not_defaulted() {
        for bad in ["advesary", "Admin", "ADMIN", "operator", "", "admin "] {
            assert_eq!(Role::from_key(bad), None, "{bad:?} must be unknown");
        }
    }
}
