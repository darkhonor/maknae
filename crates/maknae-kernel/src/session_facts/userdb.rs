//! A local account's state from systemd-userdbd's Multiplexer over Varlink, and
//! whether an account is local at all.

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use maknae_io::TargetRequired;

use super::AccountState;

/// The whole userdb exchange's wall-clock budget, well under the session-facts bound.
pub const USERDB_DEADLINE: Duration = Duration::from_secs(2);

const MULTIPLEXER: &str = "/run/systemd/userdb/io.systemd.Multiplexer";
const REPLY_CAP: usize = 64 * 1024;
const PASSWD: &str = "/etc/passwd";

const PASSWD_FILE: TargetRequired = TargetRequired {
    owner: Some(0),
    mode_mask: Some(0o022),
    nlink_exactly_one: false,
    regular_file: true,
    max_bytes: Some(16 * 1024 * 1024),
};

/// The state userdb reports for `uid`; anything but a well-formed record is `Unknown`.
pub fn account_linux(uid: u32, deadline: Duration) -> AccountState {
    account_linux_at(Path::new(MULTIPLEXER), 0, uid, deadline)
}

fn account_linux_at(path: &Path, listener_uid: u32, uid: u32, deadline: Duration) -> AccountState {
    let frame =
        match super::varlink::call(path, listener_uid, &request_frame(uid), deadline, REPLY_CAP) {
            Ok(frame) => frame,
            Err(e) => return unknown(format!("userdb: {e}")),
        };
    let reply: serde_json::Value = match serde_json::from_slice(&frame) {
        Ok(v) => v,
        Err(_) => return unknown("userdb: malformed reply"),
    };
    let now_usec = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(u64::MAX, |d| {
            u64::try_from(d.as_micros()).unwrap_or(u64::MAX)
        });
    map_record(&reply, uid, now_usec)
}

fn request_frame(uid: u32) -> Vec<u8> {
    let mut frame = format!(
        "{{\"method\":\"io.systemd.UserDatabase.GetUserRecord\",\"parameters\":{{\"uid\":{uid},\"service\":\"io.systemd.Multiplexer\"}}}}"
    )
    .into_bytes();
    frame.push(0);
    frame
}

const AGING_FIELDS: [&str; 4] = [
    "lastPasswordChangeUSec",
    "passwordChangeMinUSec",
    "passwordChangeMaxUSec",
    "passwordChangeWarnUSec",
];

pub(crate) fn map_record(json: &serde_json::Value, uid: u32, now_usec: u64) -> AccountState {
    if let Some(error) = json.get("error") {
        return unknown(format!("userdb error {}", error_name(error)));
    }
    let Some(record) = json
        .get("parameters")
        .and_then(|p| p.get("record"))
        .and_then(serde_json::Value::as_object)
    else {
        return unknown("userdb: no record");
    };
    if record.get("uid").and_then(serde_json::Value::as_u64) != Some(u64::from(uid)) {
        return unknown("userdb: record is for another uid");
    }
    match record.get("locked") {
        None => {}
        Some(serde_json::Value::Bool(false)) => {}
        Some(serde_json::Value::Bool(true)) => return AccountState::Locked,
        Some(_) => return unknown("userdb: malformed locked"),
    }
    if let Some(not_after) = record.get("notAfterUSec") {
        let Some(not_after) = not_after.as_u64() else {
            return unknown("userdb: malformed notAfterUSec");
        };
        if not_after < now_usec {
            return AccountState::Expired;
        }
    }
    if let Some(not_before) = record.get("notBeforeUSec") {
        let Some(not_before) = not_before.as_u64() else {
            return unknown("userdb: malformed notBeforeUSec");
        };
        if not_before > now_usec {
            return AccountState::Disabled;
        }
    }
    if !AGING_FIELDS
        .iter()
        .any(|k| record.get(*k).is_some_and(|v| !v.is_null()))
    {
        return unknown("no shadow");
    }
    AccountState::Active
}

fn error_name(error: &serde_json::Value) -> &str {
    match error.as_str() {
        Some(name)
            if name.len() <= 128
                && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.') =>
        {
            name
        }
        Some(_) | None => "(unprintable)",
    }
}

fn unknown(why: impl Into<String>) -> AccountState {
    AccountState::Unknown(why.into())
}

/// Whether `/etc/passwd` has a line for `uid`.
pub fn is_local_linux(uid: u32) -> Result<bool, String> {
    is_local_at(Path::new(PASSWD), PASSWD_FILE, uid)
}

fn is_local_at(path: &Path, required: TargetRequired, uid: u32) -> Result<bool, String> {
    let out = maknae_io::read_absolute(path, required, maknae_io::StrategyPref::Auto)
        .map_err(|e| e.to_string())?;
    Ok(uid_in_passwd(&String::from_utf8_lossy(&out.value), uid))
}

pub(crate) fn uid_in_passwd(text: &str, uid: u32) -> bool {
    text.lines()
        .filter(|line| !line.starts_with(['#', '+', '-']))
        .filter_map(|line| line.split(':').nth(2))
        .any(|field| field.bytes().all(|b| b.is_ascii_digit()) && field.parse::<u32>() == Ok(uid))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    use std::time::Instant;

    const NOW: u64 = 1_800_000_000_000_000;

    fn aging() -> serde_json::Value {
        json!({
            "userName": "alice",
            "uid": 1000,
            "gid": 1000,
            "lastPasswordChangeUSec": 1_700_000_000_000_000u64,
            "passwordChangeMinUSec": 0,
            "passwordChangeMaxUSec": 8_640_000_000_000u64,
            "passwordChangeWarnUSec": 604_800_000_000u64,
            "passwordChangeInactiveUSec": 2_592_000_000_000u64,
            "status": {"0123456789abcdef": {"service": "io.systemd.NameServiceSwitch"}}
        })
    }

    fn reply(record: serde_json::Value) -> serde_json::Value {
        json!({"parameters": {"record": record}})
    }

    fn with(key: &str, value: serde_json::Value) -> serde_json::Value {
        let mut r = aging();
        r[key] = value;
        reply(r)
    }

    #[test]
    fn a_record_with_aging_fields_is_active() {
        assert_eq!(map_record(&reply(aging()), 1000, NOW), AccountState::Active);
    }

    #[test]
    fn a_locked_record_is_locked() {
        assert_eq!(
            map_record(&with("locked", json!(true)), 1000, NOW),
            AccountState::Locked
        );
    }

    #[test]
    fn an_explicitly_unlocked_record_is_active() {
        assert_eq!(
            map_record(&with("locked", json!(false)), 1000, NOW),
            AccountState::Active
        );
    }

    #[test]
    fn a_malformed_locked_field_is_unknown() {
        let got = map_record(&with("locked", json!("yes")), 1000, NOW);
        assert!(matches!(got, AccountState::Unknown(_)), "{got:?}");
    }

    #[test]
    fn a_past_not_after_is_expired() {
        assert_eq!(
            map_record(&with("notAfterUSec", json!(NOW - 1)), 1000, NOW),
            AccountState::Expired
        );
    }

    #[test]
    fn a_not_after_equal_to_now_is_active() {
        assert_eq!(
            map_record(&with("notAfterUSec", json!(NOW)), 1000, NOW),
            AccountState::Active
        );
    }

    #[test]
    fn a_future_not_after_is_active() {
        assert_eq!(
            map_record(&with("notAfterUSec", json!(NOW + 1_000_000_000)), 1000, NOW),
            AccountState::Active
        );
    }

    #[test]
    fn a_malformed_not_after_is_unknown() {
        let got = map_record(&with("notAfterUSec", json!(-1)), 1000, NOW);
        assert!(matches!(got, AccountState::Unknown(_)), "{got:?}");
    }

    #[test]
    fn a_future_not_before_is_disabled() {
        assert_eq!(
            map_record(&with("notBeforeUSec", json!(NOW + 1)), 1000, NOW),
            AccountState::Disabled
        );
    }

    #[test]
    fn a_not_before_equal_to_now_is_active() {
        assert_eq!(
            map_record(&with("notBeforeUSec", json!(NOW)), 1000, NOW),
            AccountState::Active
        );
    }

    #[test]
    fn a_past_not_before_is_active() {
        assert_eq!(
            map_record(&with("notBeforeUSec", json!(NOW - 1)), 1000, NOW),
            AccountState::Active
        );
    }

    #[test]
    fn a_malformed_not_before_is_unknown() {
        assert_eq!(
            map_record(&with("notBeforeUSec", json!("soon")), 1000, NOW),
            AccountState::Unknown("userdb: malformed notBeforeUSec".into())
        );
    }

    #[test]
    fn an_expiry_outranks_a_future_start() {
        let mut r = aging();
        r["notAfterUSec"] = json!(NOW - 1);
        r["notBeforeUSec"] = json!(NOW + 1);
        assert_eq!(map_record(&reply(r), 1000, NOW), AccountState::Expired);
    }

    #[test]
    fn a_lock_outranks_a_future_start() {
        let mut r = aging();
        r["locked"] = json!(true);
        r["notBeforeUSec"] = json!(NOW + 1);
        assert_eq!(map_record(&reply(r), 1000, NOW), AccountState::Locked);
    }

    #[test]
    fn a_record_with_no_aging_fields_is_unknown() {
        let got = map_record(&reply(json!({"userName": "alice", "uid": 1000})), 1000, NOW);
        assert_eq!(got, AccountState::Unknown("no shadow".into()));
    }

    #[test]
    fn each_aging_field_alone_counts_as_shadow() {
        for key in [
            "lastPasswordChangeUSec",
            "passwordChangeMinUSec",
            "passwordChangeMaxUSec",
            "passwordChangeWarnUSec",
        ] {
            let rec = json!({"uid": 1000, key: 1});
            assert_eq!(
                map_record(&reply(rec), 1000, NOW),
                AccountState::Active,
                "{key}"
            );
        }
        let rec = json!({"uid": 1000, "passwordChangeInactiveUSec": 1});
        assert_eq!(
            map_record(&reply(rec), 1000, NOW),
            AccountState::Unknown("no shadow".into())
        );
    }

    #[test]
    fn the_measured_unprivileged_envelope_is_active() {
        let env = json!({"parameters": {"record": aging(), "incomplete": true}});
        assert_eq!(map_record(&env, 1000, NOW), AccountState::Active);
        let wire = br#"{"parameters":{"record":{"userName":"byeori","uid":1004,"gid":1004,"homeDirectory":"/home/byeori","shell":"/bin/bash","passwordChangeNow":false,"lastPasswordChangeUSec":1792195200000000,"passwordChangeMinUSec":86400000000,"passwordChangeMaxUSec":5184000000000,"passwordChangeWarnUSec":604800000000,"passwordChangeInactiveUSec":3024000000000,"status":{"00000000000000000000000000000000":{"service":"io.systemd.NameServiceSwitch"}}},"incomplete":true}}"#;
        let env: serde_json::Value = serde_json::from_slice(wire).expect("json");
        assert_eq!(map_record(&env, 1004, NOW), AccountState::Active);
    }

    #[test]
    fn a_record_for_another_uid_is_unknown() {
        let got = map_record(&with("uid", json!(1001)), 1000, NOW);
        assert!(matches!(got, AccountState::Unknown(_)), "{got:?}");
        let mut r = aging();
        r.as_object_mut().expect("object").remove("uid");
        let got = map_record(&reply(r), 1000, NOW);
        assert!(matches!(got, AccountState::Unknown(_)), "{got:?}");
    }

    #[test]
    fn an_error_reply_is_unknown() {
        let got = map_record(
            &json!({"error": "io.systemd.UserDatabase.NoRecordFound", "parameters": {}}),
            1000,
            NOW,
        );
        assert_eq!(
            got,
            AccountState::Unknown("userdb error io.systemd.UserDatabase.NoRecordFound".into())
        );
    }

    #[test]
    fn an_error_name_is_reported_only_when_it_is_a_short_dotted_name() {
        let named = |e: serde_json::Value| map_record(&json!({"error": e}), 1000, NOW);
        let long = "a".repeat(128);
        assert_eq!(
            named(json!(long)),
            AccountState::Unknown(format!("userdb error {long}"))
        );
        let unprintable = AccountState::Unknown("userdb error (unprintable)".into());
        assert_eq!(named(json!("a".repeat(129))), unprintable);
        assert_eq!(named(json!("a/b")), unprintable);
        assert_eq!(named(json!(7)), unprintable);
    }

    #[test]
    fn null_aging_fields_are_no_shadow() {
        let rec = json!({
            "uid": 1000,
            "lastPasswordChangeUSec": null,
            "passwordChangeMinUSec": null,
            "passwordChangeMaxUSec": null,
            "passwordChangeWarnUSec": null
        });
        assert_eq!(
            map_record(&reply(rec), 1000, NOW),
            AccountState::Unknown("no shadow".into())
        );
    }

    #[test]
    fn a_reply_with_no_record_is_unknown() {
        let got = map_record(&json!({"parameters": {}}), 1000, NOW);
        assert!(matches!(got, AccountState::Unknown(_)), "{got:?}");
        let got = map_record(&json!([]), 1000, NOW);
        assert!(matches!(got, AccountState::Unknown(_)), "{got:?}");
    }

    #[test]
    fn the_request_is_the_multiplexer_lookup_by_uid() {
        assert_eq!(
            request_frame(1000),
            b"{\"method\":\"io.systemd.UserDatabase.GetUserRecord\",\"parameters\":{\"uid\":1000,\"service\":\"io.systemd.Multiplexer\"}}\0"
        );
    }

    const PASSWD_TEXT: &str =
        "root:x:0:0::/root:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/bash\n";

    #[test]
    fn a_passwd_line_for_the_uid_is_local() {
        assert!(uid_in_passwd(PASSWD_TEXT, 1000));
        assert!(uid_in_passwd(PASSWD_TEXT, 0));
    }

    #[test]
    fn a_uid_prefix_is_not_a_match() {
        assert!(!uid_in_passwd(PASSWD_TEXT, 100));
        assert!(!uid_in_passwd(PASSWD_TEXT, 10000));
    }

    #[test]
    fn nis_comment_blank_and_short_lines_are_skipped() {
        assert!(!uid_in_passwd("+@nis::::::\n", 0));
        assert!(!uid_in_passwd("-bob:x:1000:1000::/:/bin/sh\n", 1000));
        assert!(!uid_in_passwd("#bob:x:1000:1000::/:/bin/sh\n\n", 1000));
        assert!(!uid_in_passwd("bob:x\n", 1000));
        assert!(!uid_in_passwd("bob:x::1000::/:/bin/sh\n", 1000));
        assert!(!uid_in_passwd("bob:x:+1000:1000::/:/bin/sh\n", 1000));
    }

    #[test]
    fn the_host_passwd_has_root() {
        assert_eq!(is_local_linux(0), Ok(true));
        assert_eq!(is_local_linux(4_000_000_000), Ok(false));
    }

    #[test]
    fn an_unreadable_passwd_is_an_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(is_local_at(&dir.path().join("passwd"), PASSWD_FILE, 0).is_err());
    }

    #[test]
    fn a_passwd_not_owned_by_root_is_an_error() {
        if nix::unistd::getuid().is_root() {
            eprintln!("SKIP: running as root, the file would be root-owned");
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let p = dir.path().join("passwd");
        std::fs::write(&p, PASSWD_TEXT).expect("write");
        assert!(is_local_at(&p, PASSWD_FILE, 0).is_err());
    }

    fn me() -> u32 {
        nix::unistd::getuid().as_raw()
    }

    struct Fake {
        _dir: tempfile::TempDir,
        path: std::path::PathBuf,
        server: std::thread::JoinHandle<Vec<u8>>,
    }

    fn serve(answer: impl FnOnce(&mut std::os::unix::net::UnixStream) + Send + 'static) -> Fake {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("io.systemd.Multiplexer");
        let listener = UnixListener::bind(&path).expect("bind");
        let server = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().expect("accept");
            let mut got = Vec::new();
            let mut byte = [0u8; 1];
            while let Ok(1) = s.read(&mut byte) {
                got.push(byte[0]);
                if byte[0] == 0 {
                    break;
                }
            }
            answer(&mut s);
            got
        });
        Fake {
            _dir: dir,
            path,
            server,
        }
    }

    fn drain(s: &mut std::os::unix::net::UnixStream) {
        let mut sink = [0u8; 64];
        while let Ok(n) = s.read(&mut sink) {
            if n == 0 {
                break;
            }
        }
    }

    #[test]
    fn a_locked_reply_over_the_socket_is_locked() {
        let fake = serve(|s| {
            s.write_all(b"{\"parameters\":{\"record\":{\"uid\":1000,\"locked\":true}}}\0")
                .expect("reply");
        });
        let got = account_linux_at(&fake.path, me(), 1000, Duration::from_secs(2));
        assert_eq!(got, AccountState::Locked);
        assert_eq!(fake.server.join().expect("server"), request_frame(1000));
    }

    #[test]
    fn a_listener_of_another_uid_is_refused_before_the_request_is_written() {
        if nix::unistd::getuid().is_root() {
            eprintln!("SKIP: running as root, which the listener check admits");
            return;
        }
        let fake = serve(drain);
        let got = account_linux_at(&fake.path, 0, 1000, Duration::from_secs(2));
        assert!(matches!(got, AccountState::Unknown(_)), "{got:?}");
        assert!(fake.server.join().expect("server").is_empty());
    }

    #[test]
    fn a_silent_server_is_unknown_within_the_deadline() {
        let fake = serve(drain);
        let started = Instant::now();
        let got = account_linux_at(&fake.path, me(), 1000, Duration::from_millis(200));
        let took = started.elapsed();
        assert!(matches!(got, AccountState::Unknown(_)), "{got:?}");
        assert!(took >= Duration::from_millis(200), "{took:?}");
        assert!(took < Duration::from_millis(1000), "{took:?}");
        fake.server.join().expect("server");
    }

    #[test]
    fn a_reply_over_the_cap_is_unknown() {
        let fake = serve(|s| {
            let _ = s.write_all(&vec![b' '; REPLY_CAP + 1]);
        });
        let got = account_linux_at(&fake.path, me(), 1000, Duration::from_secs(5));
        assert!(matches!(got, AccountState::Unknown(_)), "{got:?}");
        fake.server.join().expect("server");
    }

    #[test]
    fn a_reply_of_exactly_the_cap_is_read() {
        let fake = serve(|s| {
            let body = b"{\"parameters\":{\"record\":{\"uid\":1000,\"locked\":true}}}";
            let mut frame = body.to_vec();
            frame.resize(REPLY_CAP - 1, b' ');
            frame.push(0);
            s.write_all(&frame).expect("reply");
        });
        let got = account_linux_at(&fake.path, me(), 1000, Duration::from_secs(5));
        assert_eq!(got, AccountState::Locked);
        fake.server.join().expect("server");
    }

    #[test]
    fn a_reply_closed_before_its_terminator_is_unknown() {
        let fake = serve(|s| {
            s.write_all(b"{\"parameters\":{\"record\":{\"uid\":1000}}}")
                .expect("reply");
        });
        let got = account_linux_at(&fake.path, me(), 1000, Duration::from_secs(2));
        assert!(matches!(got, AccountState::Unknown(_)), "{got:?}");
        fake.server.join().expect("server");
    }

    #[test]
    fn a_malformed_reply_is_unknown() {
        let fake = serve(|s| {
            s.write_all(b"not json\0").expect("reply");
        });
        let got = account_linux_at(&fake.path, me(), 1000, Duration::from_secs(2));
        assert!(matches!(got, AccountState::Unknown(_)), "{got:?}");
        fake.server.join().expect("server");
    }

    #[test]
    fn an_absent_socket_is_unknown() {
        let dir = tempfile::tempdir().expect("tempdir");
        let got = account_linux_at(
            &dir.path().join("io.systemd.Multiplexer"),
            0,
            1000,
            USERDB_DEADLINE,
        );
        assert!(matches!(got, AccountState::Unknown(_)), "{got:?}");
    }

    #[test]
    fn the_host_entry_point_with_a_spent_deadline_is_unknown() {
        let got = account_linux(me(), Duration::ZERO);
        assert!(matches!(got, AccountState::Unknown(_)), "{got:?}");
    }

    #[test]
    #[ignore = "manual: run as the daemon user on a host with systemd-userdbd"]
    fn manual_host_lookup() {
        let uid = std::env::var("MAKNAE_USERDB_UID")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(me);
        eprintln!("is_local_linux({uid}) = {:?}", is_local_linux(uid));
        eprintln!(
            "account_linux({uid}) = {:?}",
            account_linux(uid, USERDB_DEADLINE)
        );
    }
}
