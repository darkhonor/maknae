//! Peer-uid → `maknae`-group membership (spec §5). T3 I/O; fail-closed. CROSS-PLATFORM.
use nix::unistd::{Group, Uid, User};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthzError {
    Resolve(String),
}

/// Resolve the `maknae` group by name — shared by [`uid_in_maknae_group`] and
/// [`maknae_gid`] so the group name is hardcoded in exactly one place.
fn resolve_maknae_group() -> Result<Group, AuthzError> {
    Group::from_name("maknae")
        .map_err(|e| AuthzError::Resolve(e.to_string()))?
        .ok_or_else(|| AuthzError::Resolve("no `maknae` group".into()))
}

/// The `maknae` group's gid — used to group-own the daemon's UDS (codex round-7 P1) so the
/// 0660 mode actually gates on the `maknae` group rather than the daemon process's PRIMARY
/// group (which, under the normal service-account setup, is NOT `maknae`; `maknae` is a
/// supplementary group there). Fails closed (`Err`) if the group cannot be resolved — the
/// caller must refuse to serve rather than bind a socket group-owned by the wrong group.
pub fn maknae_gid() -> Result<nix::unistd::Gid, AuthzError> {
    Ok(resolve_maknae_group()?.gid)
}

pub fn uid_in_maknae_group(uid: u32) -> Result<bool, AuthzError> {
    let grp = resolve_maknae_group()?;
    let user = User::from_uid(Uid::from_raw(uid))
        .map_err(|e| AuthzError::Resolve(e.to_string()))?
        .ok_or_else(|| AuthzError::Resolve(format!("no user for uid {uid}")))?;
    // Explicit membership (gr_mem) — populated on both Linux and macOS (Directory Services).
    if grp.mem.contains(&user.name) {
        return Ok(true);
    }
    // Primary group.
    if user.gid == grp.gid {
        return Ok(true);
    }
    // Supplementary groups: getgrouplist exists on Linux; nix cfg-gates it OUT on Apple targets.
    #[cfg(target_os = "linux")]
    {
        use std::ffi::CString;
        let cname =
            CString::new(user.name.clone()).map_err(|e| AuthzError::Resolve(e.to_string()))?;
        let groups = nix::unistd::getgrouplist(&cname, user.gid)
            .map_err(|e| AuthzError::Resolve(e.to_string()))?;
        if groups.contains(&grp.gid) {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_self_without_panic() {
        let uid = nix::unistd::getuid().as_raw();
        let _ = uid_in_maknae_group(uid); // Ok(_) or Err(Resolve) — never panics/UB
    }

    /// `maknae_gid` never panics/UB on a host without a `maknae` group (this dev host):
    /// it must resolve to a `Resolve` error, not crash — matching `uid_in_maknae_group`'s
    /// documented fail-closed contract.
    #[test]
    fn maknae_gid_resolves_or_fails_closed_without_panic() {
        match maknae_gid() {
            Ok(_gid) => {} // a host that DOES have `maknae` — fine, resolved.
            Err(AuthzError::Resolve(msg)) => assert!(!msg.is_empty()),
        }
    }
}
