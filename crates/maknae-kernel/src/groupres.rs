//! Peer-uid → `maknae`-group membership (spec §5). T3 I/O; fail-closed. CROSS-PLATFORM.
use nix::unistd::{Group, Uid, User};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthzError {
    Resolve(String),
}

pub fn uid_in_maknae_group(uid: u32) -> Result<bool, AuthzError> {
    let grp = Group::from_name("maknae")
        .map_err(|e| AuthzError::Resolve(e.to_string()))?
        .ok_or_else(|| AuthzError::Resolve("no `maknae` group".into()))?;
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
}
