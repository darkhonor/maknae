//! Lane selection and the capability probe. No flag composition lives here —
//! `OpenHow`/`ResolveFlag` build in `syscall.rs`, because `ResolveFlag` is a third
//! `libc_bitflags!` family and `| -> ^` on it would be an equivalent, unkillable
//! mutant in a `[t1]` file.

use crate::anchor::{Strategy, StrategyPref};
use crate::checks::DescendantRequired;

/// Choose the lane. `openat2` is used only when there is a multi-component remainder
/// to resolve AND no per-component check to perform: you cannot check what you cannot
/// `fstat`, and the kernel-internal walk yields no intermediate fds.
///
/// A single-component remainder gains nothing from `openat2` — single-component
/// `RESOLVE_NO_SYMLINKS` is equivalent to `O_NOFOLLOW` — so it takes the portable
/// chain, of which a one-component walk is the degenerate case.
pub(crate) fn select(
    pref: StrategyPref,
    probed: Strategy,
    components: usize,
    desc: Option<&DescendantRequired>,
) -> Strategy {
    if pref == StrategyPref::ForcePortable {
        return Strategy::Portable;
    }
    if probed != Strategy::Openat2 {
        return Strategy::Portable;
    }
    if desc.is_some() {
        return Strategy::Portable;
    }
    if components < 2 {
        return Strategy::Portable;
    }
    Strategy::Openat2
}

/// Whether a call takes the openat2 fast path. Hoisted out of `anchor.rs`'s cfg'd
/// dispatch block deliberately: inside `cfg(target_os = "linux")` the comparison is
/// dead code on darwin, so a darwin-local `cargo mutants` cannot kill a mutation of
/// it. Here it compiles and is tested on every platform.
/// Called only from the cfg(linux) dispatch, so darwin sees it unused — but it must
/// live outside that block to stay mutation-visible on every platform.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn uses_openat2(lane: Strategy) -> bool {
    lane == Strategy::Openat2
}

/// Probe result -> capability. **Any** probe failure means Portable: Docker/podman
/// seccomp returns EPERM for a blocked syscall, the same errno the kernel returns for
/// an ordinary permission denial, so a closed two-errno set would leave the rest
/// undefined in a deny-by-default project.
pub(crate) fn capability_from_probe(r: Result<(), nix::errno::Errno>) -> Strategy {
    match r {
        Ok(()) => Strategy::Openat2,
        Err(_) => Strategy::Portable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d() -> DescendantRequired {
        DescendantRequired {
            owner: None,
            mode_mask: Some(0o007),
        }
    }

    #[test]
    fn multi_component_unchecked_takes_openat2() {
        assert_eq!(
            select(StrategyPref::Auto, Strategy::Openat2, 2, None),
            Strategy::Openat2
        );
    }

    #[test]
    fn any_descendant_check_forces_portable() {
        assert_eq!(
            select(StrategyPref::Auto, Strategy::Openat2, 2, Some(&d())),
            Strategy::Portable
        );
    }

    #[test]
    fn single_component_takes_portable() {
        assert_eq!(
            select(StrategyPref::Auto, Strategy::Openat2, 1, None),
            Strategy::Portable
        );
    }

    #[test]
    fn force_portable_wins() {
        assert_eq!(
            select(StrategyPref::ForcePortable, Strategy::Openat2, 3, None),
            Strategy::Portable
        );
    }

    #[test]
    fn without_the_capability_it_is_portable() {
        assert_eq!(
            select(StrategyPref::Auto, Strategy::Portable, 3, None),
            Strategy::Portable
        );
    }

    /// The fallback arm is unreachable on a lane where openat2 always succeeds, so it
    /// is covered through the injected probe result rather than the real syscall.
    #[test]
    fn uses_openat2_only_for_the_fast_lane() {
        assert!(uses_openat2(Strategy::Openat2));
        assert!(!uses_openat2(Strategy::Portable));
    }

    #[test]
    fn any_probe_failure_is_portable() {
        assert_eq!(capability_from_probe(Ok(())), Strategy::Openat2);
        for e in [
            nix::errno::Errno::ENOSYS,
            nix::errno::Errno::EPERM,
            nix::errno::Errno::EINVAL,
        ] {
            assert_eq!(capability_from_probe(Err(e)), Strategy::Portable, "{e:?}");
        }
    }
}
