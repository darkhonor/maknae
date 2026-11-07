//! The peer's logind session, read without libsystemd: the session scope in
//! `/proc/<pid>/cgroup`, then logind's record under `/run/systemd/sessions`.

use std::os::fd::BorrowedFd;
use std::path::{Path, PathBuf};

use maknae_io::{IoError, IoKind, StrategyPref, TargetRequired, Zeroizing};
use nix::errno::Errno;
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};

use super::LoginFact;

const SESSIONS: &str = "/run/systemd/sessions";
const READ_CAP: usize = 64 * 1024;

const SESSION_RECORD: TargetRequired = TargetRequired {
    owner: Some(0),
    mode_mask: Some(0o022),
    nlink_exactly_one: false,
    regular_file: true,
    max_bytes: Some(READ_CAP as u64),
};

/// The login fact for the process behind `pidfd`, whose pid is `pid`, for `uid`.
pub fn login_linux(pidfd: BorrowedFd<'_>, pid: i32, uid: u32) -> LoginFact {
    let cgroup = PathBuf::from(format!("/proc/{pid}/cgroup"));
    login_at(
        Path::new(SESSIONS),
        SESSION_RECORD,
        uid,
        || pidfd_alive(pidfd),
        || maknae_io::read_pseudo_file(&cgroup, READ_CAP),
    )
}

fn login_at(
    sessions: &Path,
    record: TargetRequired,
    uid: u32,
    alive: impl Fn() -> bool,
    read_cgroup: impl FnOnce() -> Result<Zeroizing<Vec<u8>>, IoError>,
) -> LoginFact {
    if !alive() {
        return LoginFact::ProcessGone;
    }
    let cgroup = match read_cgroup() {
        Ok(bytes) => bytes,
        Err(e) => {
            return if alive() {
                LoginFact::Unavailable(format!("cgroup: {e}"))
            } else {
                LoginFact::ProcessGone
            }
        }
    };
    if !alive() {
        return LoginFact::ProcessGone;
    }
    let Some(id) = session_id_from_cgroup(&String::from_utf8_lossy(&cgroup), uid) else {
        return LoginFact::NoSession;
    };
    let path = sessions.join(id);
    match maknae_io::read_absolute(&path, record, StrategyPref::Auto) {
        Ok(out) => qualifies(&String::from_utf8_lossy(&out.value), uid),
        Err(IoError::Io {
            path: failed,
            kind: IoKind::NotFound,
        }) if failed == path => LoginFact::NoSession,
        Err(e) => LoginFact::Unavailable(format!("session record: {e}")),
    }
}

pub(crate) fn pidfd_alive(pidfd: BorrowedFd<'_>) -> bool {
    loop {
        let mut fds = [PollFd::new(pidfd, PollFlags::POLLIN)];
        match poll(&mut fds, PollTimeout::ZERO) {
            Ok(0) => return true,
            Ok(_) => return false,
            Err(Errno::EINTR) => continue,
            Err(_) => return false,
        }
    }
}

pub(crate) fn session_id_from_cgroup(text: &str, uid: u32) -> Option<String> {
    let mut unified = None;
    let mut named = None;
    for line in text.lines() {
        let mut fields = line.splitn(3, ':');
        let (Some(hierarchy), Some(controllers), Some(path)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if hierarchy == "0" && controllers.is_empty() {
            unified.get_or_insert(path);
        } else if controllers == "name=systemd" {
            named.get_or_insert(path);
        }
    }
    let path = unified.filter(|p| *p != "/").or(named)?;
    session_in_path(path, uid)
}

fn session_in_path(path: &str, uid: u32) -> Option<String> {
    let mut parts = path.strip_prefix('/')?.split('/');
    let user_slice = format!("user-{uid}.slice");
    if parts.next() != Some("user.slice") || parts.next() != Some(user_slice.as_str()) {
        return None;
    }
    let unit = parts.find(|c| !c.ends_with(".slice"))?;
    let id = unit.strip_prefix("session-")?.strip_suffix(".scope")?;
    (!id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric())).then(|| id.to_owned())
}

pub(crate) fn qualifies(record: &str, uid: u32) -> LoginFact {
    let (mut record_uid, mut class, mut state) = (None, None, None);
    for line in record.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key {
            "UID" => record_uid = Some(value),
            "CLASS" => class = Some(value),
            "STATE" => state = Some(value),
            _ => {}
        }
    }
    if record_uid.and_then(decimal_uid) != Some(uid) {
        return LoginFact::NoSession;
    }
    if class != Some("user") {
        return LoginFact::NotUserClass;
    }
    if matches!(state, Some("active" | "online")) {
        LoginFact::Live
    } else {
        LoginFact::NotActive
    }
}

fn decimal_uid(value: &str) -> Option<u32> {
    if !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::os::fd::AsFd;
    use std::os::unix::fs::PermissionsExt;

    fn private_dir() -> tempfile::TempDir {
        let d = tempfile::tempdir().expect("tempdir");
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).expect("chmod");
        d
    }

    fn sid(text: &str) -> Option<String> {
        session_id_from_cgroup(text, 1000)
    }

    #[test]
    fn the_unified_session_scope_is_found() {
        assert_eq!(
            sid("0::/user.slice/user-1000.slice/session-4.scope\n"),
            Some("4".into())
        );
    }

    #[test]
    fn a_hybrid_host_falls_back_to_the_named_systemd_line() {
        assert_eq!(
            sid("1:name=systemd:/user.slice/user-1000.slice/session-c2.scope\n0::/\n"),
            Some("c2".into())
        );
    }

    #[test]
    fn a_v1_host_with_no_unified_line_uses_the_named_systemd_line() {
        assert_eq!(
            sid("2:cpu,cpuacct:/\n1:name=systemd:/user.slice/user-1000.slice/session-7.scope\n"),
            Some("7".into())
        );
    }

    #[test]
    fn a_unified_path_that_is_not_root_is_not_overridden_by_the_named_line() {
        assert_eq!(
            sid("1:name=systemd:/user.slice/user-1000.slice/session-7.scope\n0::/system.slice/x.service\n"),
            None
        );
    }

    #[test]
    fn a_system_service_has_no_session() {
        assert_eq!(sid("0::/system.slice/cron.service\n"), None);
    }

    #[test]
    fn a_lingering_user_manager_has_no_session() {
        assert_eq!(
            sid("0::/user.slice/user-1000.slice/user@1000.service/app.slice/x.scope\n"),
            None
        );
    }

    #[test]
    fn a_session_scope_inside_the_delegated_subtree_is_refused() {
        assert_eq!(
            sid("0::/user.slice/user-1000.slice/user@1000.service/app.slice/session-4.scope\n"),
            None
        );
    }

    #[test]
    fn another_uids_slice_is_refused() {
        assert_eq!(
            sid("0::/user.slice/user-1001.slice/session-4.scope\n"),
            None
        );
    }

    #[test]
    fn a_session_id_with_path_characters_is_refused() {
        assert_eq!(sid("0::/user.slice/session-../x.scope"), None);
        assert_eq!(sid("0::/x/session-a/b.scope"), None);
        assert_eq!(
            sid("0::/user.slice/user-1000.slice/session-a.b.scope\n"),
            None
        );
        assert_eq!(sid("0::/user.slice/user-1000.slice/session-.scope\n"), None);
    }

    #[test]
    fn nested_slices_before_the_scope_are_skipped() {
        assert_eq!(
            sid("0::/user.slice/user-1000.slice/extra.slice/session-9.scope/sub\n"),
            Some("9".into())
        );
    }

    #[test]
    fn a_path_outside_user_slice_is_refused() {
        assert_eq!(sid("0::/user-1000.slice/session-4.scope\n"), None);
        assert_eq!(sid("0::/\n"), None);
        assert_eq!(sid(""), None);
        assert_eq!(sid("0::user.slice/user-1000.slice/session-4.scope\n"), None);
        assert_eq!(sid("0::/user.slice\n"), None);
        assert_eq!(sid("0::/user.slice/user-1000.slice\n"), None);
        assert_eq!(
            sid("0::/user.slice/user-1000.slice/session-4.service\n"),
            None
        );
    }

    #[test]
    fn a_line_without_three_fields_is_skipped() {
        assert_eq!(
            sid("garbage\n0::/user.slice/user-1000.slice/session-4.scope\n"),
            Some("4".into())
        );
    }

    fn q(record: &str) -> LoginFact {
        qualifies(record, 1000)
    }

    #[test]
    fn an_active_user_session_is_live() {
        assert_eq!(q("UID=1000\nCLASS=user\nSTATE=active"), LoginFact::Live);
    }

    #[test]
    fn an_online_user_session_is_live() {
        assert_eq!(q("UID=1000\nCLASS=user\nSTATE=online"), LoginFact::Live);
    }

    #[test]
    fn the_real_record_shape_is_live() {
        let record = "# This is private data. Do not parse.\nUID=1000\nUSER=alice\nACTIVE=1\n\
                      IS_DISPLAY=0\nSTATE=active\nREMOTE=1\nTYPE=tty\nCLASS=user\n\
                      SCOPE=session-4.scope\nLEADER=1234\n";
        assert_eq!(q(record), LoginFact::Live);
    }

    #[test]
    fn a_background_session_is_not_user_class() {
        assert_eq!(
            q("UID=1000\nCLASS=background\nSTATE=active"),
            LoginFact::NotUserClass
        );
    }

    #[test]
    fn a_manager_session_is_not_user_class() {
        assert_eq!(
            q("UID=1000\nCLASS=manager\nSTATE=active"),
            LoginFact::NotUserClass
        );
    }

    #[test]
    fn a_closing_session_is_not_active() {
        assert_eq!(
            q("UID=1000\nCLASS=user\nSTATE=closing"),
            LoginFact::NotActive
        );
    }

    #[test]
    fn a_missing_state_is_not_active() {
        assert_eq!(q("UID=1000\nCLASS=user"), LoginFact::NotActive);
    }

    #[test]
    fn another_uids_record_is_no_session() {
        assert_eq!(
            q("UID=1001\nCLASS=user\nSTATE=active"),
            LoginFact::NoSession
        );
    }

    #[test]
    fn a_missing_or_malformed_uid_is_no_session() {
        assert_eq!(q("CLASS=user\nSTATE=active"), LoginFact::NoSession);
        assert_eq!(
            q("UID=+1000\nCLASS=user\nSTATE=active"),
            LoginFact::NoSession
        );
        assert_eq!(q("UID=\nCLASS=user\nSTATE=active"), LoginFact::NoSession);
    }

    #[test]
    fn a_missing_class_is_not_user_class() {
        assert_eq!(q("UID=1000\nSTATE=active"), LoginFact::NotUserClass);
    }

    #[test]
    fn a_later_assignment_wins_as_in_libsystemd() {
        assert_eq!(
            q("UID=1000\nCLASS=user\nSTATE=active\nSTATE=closing"),
            LoginFact::NotActive
        );
    }

    fn uid() -> u32 {
        nix::unistd::getuid().as_raw()
    }

    fn owned_by_me() -> TargetRequired {
        TargetRequired {
            owner: Some(uid()),
            ..SESSION_RECORD
        }
    }

    fn cgroup_of(id: &str) -> impl FnOnce() -> Result<Zeroizing<Vec<u8>>, IoError> {
        let text = format!("0::/user.slice/user-{}.slice/session-{id}.scope\n", uid());
        move || Ok(Zeroizing::new(text.into_bytes()))
    }

    fn answers(seq: &'static [bool]) -> impl Fn() -> bool {
        let at = Cell::new(0);
        move || {
            let i = at.get();
            at.set(i + 1);
            seq[i.min(seq.len() - 1)]
        }
    }

    fn denied() -> Result<Zeroizing<Vec<u8>>, IoError> {
        Err(IoError::Io {
            path: "/proc/1/cgroup".into(),
            kind: maknae_io::IoKind::PermissionDenied,
        })
    }

    fn sessions_with(id: &str, body: &str) -> tempfile::TempDir {
        let dir = private_dir();
        let path = dir.path().join(id);
        std::fs::write(&path, body).expect("write record");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .expect("chmod record");
        dir
    }

    #[test]
    fn a_process_dead_before_the_read_is_gone() {
        let dir = private_dir();
        let got = login_at(
            dir.path(),
            owned_by_me(),
            uid(),
            answers(&[false]),
            cgroup_of("4"),
        );
        assert_eq!(got, LoginFact::ProcessGone);
    }

    #[test]
    fn a_failed_cgroup_read_of_a_live_process_is_unavailable() {
        let dir = private_dir();
        let got = login_at(dir.path(), owned_by_me(), uid(), answers(&[true]), denied);
        assert!(matches!(got, LoginFact::Unavailable(_)), "{got:?}");
    }

    #[test]
    fn a_failed_cgroup_read_of_an_exited_process_is_gone() {
        let dir = private_dir();
        let got = login_at(
            dir.path(),
            owned_by_me(),
            uid(),
            answers(&[true, false]),
            denied,
        );
        assert_eq!(got, LoginFact::ProcessGone);
    }

    #[test]
    fn a_process_that_exits_during_the_cgroup_read_is_gone() {
        let dir = sessions_with("4", &format!("UID={}\nCLASS=user\nSTATE=active\n", uid()));
        let got = login_at(
            dir.path(),
            owned_by_me(),
            uid(),
            answers(&[true, false]),
            cgroup_of("4"),
        );
        assert_eq!(got, LoginFact::ProcessGone);
    }

    #[test]
    fn a_process_outside_a_session_scope_has_no_session() {
        let dir = private_dir();
        let got = login_at(dir.path(), owned_by_me(), uid(), answers(&[true]), || {
            Ok(Zeroizing::new(b"0::/system.slice/cron.service\n".to_vec()))
        });
        assert_eq!(got, LoginFact::NoSession);
    }

    #[test]
    fn a_qualifying_record_is_live() {
        let dir = sessions_with("4", &format!("UID={}\nCLASS=user\nSTATE=active\n", uid()));
        let got = login_at(
            dir.path(),
            owned_by_me(),
            uid(),
            answers(&[true]),
            cgroup_of("4"),
        );
        assert_eq!(got, LoginFact::Live);
    }

    #[test]
    fn a_closing_record_is_not_active() {
        let dir = sessions_with("4", &format!("UID={}\nCLASS=user\nSTATE=closing\n", uid()));
        let got = login_at(
            dir.path(),
            owned_by_me(),
            uid(),
            answers(&[true]),
            cgroup_of("4"),
        );
        assert_eq!(got, LoginFact::NotActive);
    }

    #[test]
    fn a_missing_record_is_no_session() {
        let dir = sessions_with("5", &format!("UID={}\nCLASS=user\nSTATE=active\n", uid()));
        let got = login_at(
            dir.path(),
            owned_by_me(),
            uid(),
            answers(&[true]),
            cgroup_of("4"),
        );
        assert_eq!(got, LoginFact::NoSession);
    }

    #[test]
    fn a_missing_sessions_directory_is_unavailable() {
        let dir = private_dir();
        let absent = dir.path().join("sessions");
        let got = login_at(
            &absent,
            owned_by_me(),
            uid(),
            answers(&[true]),
            cgroup_of("4"),
        );
        assert!(matches!(got, LoginFact::Unavailable(_)), "{got:?}");
    }

    #[test]
    fn a_record_not_owned_by_root_is_unavailable() {
        if uid() == 0 {
            eprintln!("SKIP: running as root, the record would be root-owned");
            return;
        }
        let dir = sessions_with("4", &format!("UID={}\nCLASS=user\nSTATE=active\n", uid()));
        let got = login_at(
            dir.path(),
            SESSION_RECORD,
            uid(),
            answers(&[true]),
            cgroup_of("4"),
        );
        assert!(matches!(got, LoginFact::Unavailable(_)), "{got:?}");
    }

    #[test]
    fn a_group_writable_record_is_unavailable() {
        let dir = sessions_with("4", &format!("UID={}\nCLASS=user\nSTATE=active\n", uid()));
        std::fs::set_permissions(dir.path().join("4"), std::fs::Permissions::from_mode(0o664))
            .expect("chmod");
        let got = login_at(
            dir.path(),
            owned_by_me(),
            uid(),
            answers(&[true]),
            cgroup_of("4"),
        );
        assert!(matches!(got, LoginFact::Unavailable(_)), "{got:?}");
    }

    #[test]
    fn this_process_is_alive() {
        let pidfd = maknae_io::pidfd_open(std::process::id() as i32).expect("pidfd");
        assert!(pidfd_alive(pidfd.as_fd()));
    }

    #[test]
    fn an_exited_process_is_not_alive() {
        let mut child = std::process::Command::new("true").spawn().expect("spawn");
        let pidfd = maknae_io::pidfd_open(child.id() as i32).expect("pidfd");
        child.wait().expect("wait");
        assert!(!pidfd_alive(pidfd.as_fd()));
    }

    #[test]
    fn the_host_entry_point_reports_an_exited_process_as_gone() {
        let mut child = std::process::Command::new("true").spawn().expect("spawn");
        let pid = child.id() as i32;
        let pidfd = maknae_io::pidfd_open(pid).expect("pidfd");
        child.wait().expect("wait");
        assert_eq!(
            login_linux(pidfd.as_fd(), pid, uid()),
            LoginFact::ProcessGone
        );
    }

    #[test]
    fn the_host_entry_point_reports_an_unreadable_cgroup_of_a_live_process_as_unavailable() {
        let pidfd = maknae_io::pidfd_open(std::process::id() as i32).expect("pidfd");
        let got = login_linux(pidfd.as_fd(), i32::MAX, uid());
        assert!(matches!(got, LoginFact::Unavailable(_)), "{got:?}");
    }
}
