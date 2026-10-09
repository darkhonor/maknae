//! `sudo maknae audit-readers` (#500): print the accounts `audit.readers` grants read on
//! the audit trail, one validated name per line and nothing else. The packages parse
//! this output after every hold of `/var/log/maknae`, so its format is a contract.

use maknae_config::{
    audit_from_section, load_config_root_owned, resolve_readers, Document, ReaderLookup,
    SectionSpec, AUDIT_SECTION, DAEMON_SECTIONS, STATE_DIR,
};
use maknae_io::{open_anchor, AnchorRequired, IoError, StrategyPref};
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

const CONFIG_DIR: &str = "/etc/maknae";

fn preflight(euid: u32) -> Result<(), String> {
    if euid == 0 {
        Ok(())
    } else {
        Err("maknae audit-readers must run as root: run `sudo maknae audit-readers`".into())
    }
}

/// `Err` while another process (maknaed) holds the state directory's exclusive lock.
/// The lock is taken and released; nothing is written.
pub(crate) fn daemon_stopped(state_dir: &Path, owner: u32) -> Result<(), String> {
    let anchor = open_anchor(
        state_dir,
        AnchorRequired {
            owner: Some(owner),
            mode_mask: Some(0o077),
        },
        StrategyPref::Auto,
    )
    .map_err(|e| {
        format!(
            "cannot use the state directory {}: {e}",
            state_dir.display()
        )
    })?;
    match anchor.try_lock_exclusive() {
        Ok(_held) => Ok(()),
        Err(IoError::Locked { .. }) => Err(
            "maknaed is running: stop it first, then run `sudo maknae audit-readers --stopped`"
                .into(),
        ),
        Err(e) => Err(format!(
            "cannot lock the state directory {}: {e}",
            state_dir.display()
        )),
    }
}

/// An absent `audit` section or `readers` key grants no one.
pub(crate) fn validated(
    doc: &Document,
    dir: &Path,
    lookup: &dyn ReaderLookup,
) -> Result<Vec<String>, String> {
    let Some(section) = doc.section(AUDIT_SECTION) else {
        return Ok(Vec::new());
    };
    let audit = audit_from_section(Some(section), dir).map_err(|e| e.to_string())?;
    resolve_readers(&audit.readers, lookup).map_err(|e| e.to_string())?;
    Ok(audit.readers)
}

fn load(dir: &Path) -> Result<Document, String> {
    let specs = DAEMON_SECTIONS.map(|n| SectionSpec {
        name: n.into(),
        required: false,
    });
    load_config_root_owned(dir, &specs).map_err(|e| e.to_string())
}

pub(crate) fn readers(dir: &Path, lookup: &dyn ReaderLookup) -> Result<Vec<String>, String> {
    validated(&load(dir)?, dir, lookup)
}

fn emit(names: &[String], out: &mut dyn Write) -> Result<(), String> {
    let text: String = names.iter().map(|n| format!("{n}\n")).collect();
    out.write_all(text.as_bytes())
        .and_then(|()| out.flush())
        .map_err(|e| format!("cannot write the readers: {e}"))
}

fn collect(euid: u32, stopped: bool) -> Result<Vec<String>, String> {
    preflight(euid)?;
    if stopped {
        daemon_stopped(Path::new(STATE_DIR), crate::reseed::kernel_uid()?)?;
    }
    readers(Path::new(CONFIG_DIR), &maknae_vault::NssAccounts::HOST)
}

pub(crate) fn run(euid: u32, stopped: bool) -> ExitCode {
    match collect(euid, stopped).and_then(|names| emit(&names, &mut std::io::stdout().lock())) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("maknae: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_config::{BaselineSections, ReaderAccount};
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    struct Accounts(Vec<ReaderAccount>);
    impl ReaderLookup for Accounts {
        fn account(&self, name: &str) -> Result<Option<ReaderAccount>, String> {
            Ok(self.0.iter().find(|a| a.name == name).cloned())
        }
        fn daemon_gid(&self) -> Result<Option<u32>, String> {
            Ok(Some(980))
        }
        fn service_uids(&self) -> Result<Vec<u32>, String> {
            Ok(vec![980, 981])
        }
    }

    fn accounts() -> Accounts {
        let a = |name: &str, uid, groups: &[u32]| ReaderAccount {
            name: name.into(),
            uid,
            gid: uid,
            groups: groups.to_vec(),
        };
        Accounts(vec![
            a("alice", 1001, &[]),
            a("bob", 1002, &[20]),
            a("mallory", 1003, &[980]),
        ])
    }

    fn doc(sections: &[(&str, &str)]) -> Document {
        let mut s = BaselineSections::new();
        for (name, json) in sections {
            s.insert(name.to_string(), json.to_string());
        }
        Document::from_baseline(&s).unwrap()
    }

    fn check(sections: &[(&str, &str)]) -> Result<Vec<String>, String> {
        validated(&doc(sections), Path::new("/etc/maknae"), &accounts())
    }

    #[test]
    fn no_audit_section_or_no_readers_grants_no_one() {
        assert_eq!(check(&[]), Ok(vec![]));
        assert_eq!(check(&[("transport", "{}")]), Ok(vec![]));
        assert_eq!(check(&[("audit", "{}")]), Ok(vec![]));
        assert_eq!(check(&[("audit", r#"{"readers":[]}"#)]), Ok(vec![]));
    }

    #[test]
    fn the_validated_readers_come_back_in_file_order() {
        assert_eq!(
            check(&[("audit", r#"{"readers":["bob","alice"]}"#)]),
            Ok(vec!["bob".to_string(), "alice".to_string()])
        );
    }

    #[test]
    fn one_refused_reader_refuses_them_all_by_name() {
        for (readers, name) in [
            (r#"{"readers":["alice","mallory"]}"#, "mallory"),
            (r#"{"readers":["alice","nosuch"]}"#, "nosuch"),
            (r#"{"readers":["root"]}"#, "root"),
        ] {
            let err = check(&[("audit", readers)]).unwrap_err();
            assert!(err.contains(&format!("audit.readers {name}:")), "{err}");
        }
        let err = check(&[("audit", r#"{"readers":"alice"}"#)]).unwrap_err();
        assert!(err.contains("must be a list of account names"), "{err}");
        let err = check(&[("audit", r#"{"reader":["alice"]}"#)]).unwrap_err();
        assert!(err.contains("reader"), "{err}");
    }

    #[test]
    fn a_directory_name_that_differs_from_the_configured_one_prints_nothing() {
        struct Lying;
        impl ReaderLookup for Lying {
            fn account(&self, _: &str) -> Result<Option<ReaderAccount>, String> {
                Ok(Some(ReaderAccount {
                    name: "alice\neve".into(),
                    uid: 1001,
                    gid: 1001,
                    groups: Vec::new(),
                }))
            }
            fn daemon_gid(&self) -> Result<Option<u32>, String> {
                Ok(Some(980))
            }
            fn service_uids(&self) -> Result<Vec<u32>, String> {
                Ok(vec![980, 981])
            }
        }
        let mut out = Vec::new();
        let got = validated(
            &doc(&[("audit", r#"{"readers":["alice"]}"#)]),
            Path::new("/etc/maknae"),
            &Lying,
        )
        .and_then(|names| emit(&names, &mut out));
        assert!(
            matches!(got, Err(ref e) if e.contains("audit.readers alice: ")),
            "{got:?}"
        );
        assert!(out.is_empty());
    }

    #[test]
    fn the_output_is_one_name_per_line_and_nothing_else() {
        let mut out = Vec::new();
        emit(&["bob".into(), "alice".into()], &mut out).unwrap();
        assert_eq!(out, b"bob\nalice\n");
        let mut out = Vec::new();
        emit(&[], &mut out).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn a_failed_write_is_an_error() {
        struct Closed;
        impl Write for Closed {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let err = emit(&["bob".into()], &mut Closed).unwrap_err();
        assert!(err.starts_with("cannot write the readers: "), "{err}");
    }

    #[test]
    fn a_non_root_caller_is_refused_before_anything_is_read() {
        assert_eq!(preflight(0), Ok(()));
        let refusal = "maknae audit-readers must run as root: run `sudo maknae audit-readers`";
        assert_eq!(preflight(1000), Err(refusal.into()));
        assert_eq!(preflight(1), Err(refusal.into()));
        assert_eq!(collect(1000, false), Err(refusal.into()));
        assert_eq!(collect(1000, true), Err(refusal.into()));
        assert_eq!(run(1000, false), ExitCode::FAILURE);
    }

    #[test]
    fn files_root_does_not_own_are_refused() {
        if euid() == 0 {
            return;
        }
        let scratch = Scratch::new("load");
        let yaml = scratch.0.join("maknae.yaml");
        std::fs::write(&yaml, "audit:\n  readers: [alice]\n").unwrap();
        std::fs::set_permissions(&yaml, std::fs::Permissions::from_mode(0o600)).unwrap();
        let err = readers(&scratch.0, &accounts()).unwrap_err();
        assert!(err.contains("must be owned by root"), "{err}");
    }

    struct Scratch(PathBuf);
    impl Scratch {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!(
                "maknae_cli_audit_readers_{}_{tag}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
            Scratch(p)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn euid() -> u32 {
        nix::unistd::geteuid().as_raw()
    }

    #[test]
    fn a_held_state_directory_means_maknaed_is_running() {
        let scratch = Scratch::new("lock");
        assert_eq!(daemon_stopped(&scratch.0, euid()), Ok(()));
        let held = open_anchor(
            &scratch.0,
            AnchorRequired {
                owner: Some(euid()),
                mode_mask: Some(0o077),
            },
            StrategyPref::Auto,
        )
        .unwrap()
        .try_lock_exclusive()
        .unwrap();
        assert_eq!(
            daemon_stopped(&scratch.0, euid()),
            Err(
                "maknaed is running: stop it first, then run `sudo maknae audit-readers --stopped`"
                    .into()
            )
        );
        drop(held);
        assert_eq!(daemon_stopped(&scratch.0, euid()), Ok(()));
        assert_eq!(std::fs::read_dir(&scratch.0).unwrap().count(), 0);
    }

    #[test]
    fn the_state_directory_must_be_the_daemons_and_private() {
        let scratch = Scratch::new("dir");
        let err = daemon_stopped(&scratch.0, euid() + 1).unwrap_err();
        assert!(err.starts_with("cannot use the state directory "), "{err}");
        std::fs::set_permissions(&scratch.0, std::fs::Permissions::from_mode(0o750)).unwrap();
        let err = daemon_stopped(&scratch.0, euid()).unwrap_err();
        assert!(err.starts_with("cannot use the state directory "), "{err}");
    }
}
