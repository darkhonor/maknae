use super::EnrollError;
use maknae_vault::{KeychainPlane, KEYCHAIN_ACCOUNT, SYSTEM_KEYCHAIN};
use zeroize::Zeroizing;

#[cfg(target_os = "macos")]
pub(crate) const SECURITY: &str = "/usr/bin/security";
#[cfg(target_os = "macos")]
pub(crate) const CODESIGN: &str = "/usr/bin/codesign";
#[cfg(target_os = "macos")]
pub(crate) const DAEMON_BINARY: &str = "/usr/local/bin/maknaed";
pub(crate) const EGRESS_BINARY: &str = "/usr/local/bin/maknae-egress";
const DEVELOPER_ID_CA_OID: &str = "1.2.840.113635.100.6.2.6";
const DEVELOPER_ID_LEAF_OID: &str = "1.2.840.113635.100.6.1.13";

pub(crate) fn validate_secret_id(s: &str) -> Result<(), EnrollError> {
    let b = s.as_bytes();
    let ok = b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_digit() || (b'a'..=b'f').contains(c),
        });
    if ok {
        Ok(())
    } else {
        Err(EnrollError::SecretIdShape)
    }
}

pub(crate) fn add_command(
    secret: &Zeroizing<String>,
    plane: KeychainPlane,
    binary: &str,
) -> Zeroizing<String> {
    let parts = [
        "add-generic-password -a ",
        KEYCHAIN_ACCOUNT,
        " -s ",
        plane.service(),
        " -T ",
        binary,
        " -w ",
        secret.as_str(),
        " ",
        SYSTEM_KEYCHAIN,
        "\n",
    ];
    let mut cmd = Zeroizing::new(String::with_capacity(parts.iter().map(|p| p.len()).sum()));
    for p in parts {
        cmd.push_str(p);
    }
    cmd
}

pub(crate) fn delete_args(plane: KeychainPlane) -> [&'static str; 6] {
    [
        "delete-generic-password",
        "-a",
        KEYCHAIN_ACCOUNT,
        "-s",
        plane.service(),
        SYSTEM_KEYCHAIN,
    ]
}

pub(crate) fn find_args(plane: KeychainPlane) -> [&'static str; 6] {
    [
        "find-generic-password",
        "-a",
        KEYCHAIN_ACCOUNT,
        "-s",
        plane.service(),
        SYSTEM_KEYCHAIN,
    ]
}

pub(crate) fn parse_keychain_line(out: &str) -> Option<&str> {
    out.lines()
        .find_map(|l| l.trim().strip_prefix("keychain: \"")?.strip_suffix('"'))
}

pub(crate) fn anchor_requirement(team: &str) -> String {
    format!(
        "=anchor apple generic and certificate 1[field.{DEVELOPER_ID_CA_OID}] and certificate leaf[field.{DEVELOPER_ID_LEAF_OID}] and certificate leaf[subject.OU] = \"{team}\""
    )
}

pub(crate) fn requirement(identifier: &str, team: &str) -> String {
    format!(
        "=identifier \"{identifier}\" and {}",
        &anchor_requirement(team)[1..]
    )
}

pub(crate) fn parse_team(details: &str) -> Option<&str> {
    details
        .lines()
        .find_map(|l| l.strip_prefix("TeamIdentifier="))
        .map(str::trim)
        .filter(|t| !t.is_empty() && t.bytes().all(|b| b.is_ascii_alphanumeric()))
}

pub(crate) fn check_runtime_and_entitlements(
    details: &str,
    entitlements: &str,
) -> Result<(), String> {
    let flags = details
        .lines()
        .filter(|l| l.starts_with("CodeDirectory "))
        .find_map(|l| l.split_whitespace().find_map(|w| w.strip_prefix("flags=")))
        .and_then(|f| f.split_once('('))
        .map(|(_, names)| names.trim_end_matches(')').split(',').collect::<Vec<_>>())
        .ok_or("codesign reported no CodeDirectory flags")?;
    if flags.contains(&"adhoc") || details.lines().any(|l| l.trim() == "Signature=adhoc") {
        return Err("it is ad-hoc signed".to_string());
    }
    if !flags.contains(&"runtime") {
        return Err("it is not signed with Hardened Runtime".to_string());
    }
    if entitlements.contains("<key>") {
        return Err("it carries entitlements; decision 6 requires none".to_string());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub(crate) async fn run(program: &str, args: &[&str]) -> Result<std::process::Output, EnrollError> {
    tokio::process::Command::new(program)
        .args(args)
        .output()
        .await
        .map_err(|e| EnrollError::Command {
            program: program.to_string(),
            detail: e.to_string(),
        })
}

#[cfg(target_os = "macos")]
pub(crate) async fn seal_secret_macos(
    secret: &Zeroizing<String>,
    plane: KeychainPlane,
    binary: &'static str,
    team: &str,
) -> Result<(), EnrollError> {
    use tokio::io::AsyncWriteExt;
    validate_secret_id(secret)?;
    let stderr = |o: &std::process::Output| String::from_utf8_lossy(&o.stderr).trim().to_string();
    let io = |e: std::io::Error| EnrollError::Command {
        program: SECURITY.to_string(),
        detail: e.to_string(),
    };

    let del = run(SECURITY, &delete_args(plane)).await?;
    if !matches!(del.status.code(), Some(0) | Some(44)) {
        return Err(EnrollError::Keychain {
            op: "delete",
            detail: stderr(&del),
        });
    }

    check_install_path(std::path::Path::new(binary))?;
    verify_release(binary, plane, team).await?;
    let mut child = tokio::process::Command::new(SECURITY)
        .arg("-i")
        .kill_on_drop(true)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(io)?;
    {
        let cmd = add_command(secret, plane, binary);
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| io(std::io::Error::other("no stdin pipe")))?;
        stdin.write_all(cmd.as_bytes()).await.map_err(io)?;
    }
    let add = child.wait_with_output().await.map_err(io)?;
    if !add.status.success() {
        return Err(EnrollError::Keychain {
            op: "add",
            detail: stderr(&add),
        });
    }

    let find = run(SECURITY, &find_args(plane)).await?;
    if !find.status.success() {
        return Err(EnrollError::Keychain {
            op: "verify",
            detail: stderr(&find),
        });
    }
    match parse_keychain_line(&String::from_utf8_lossy(&find.stdout)) {
        Some(k) if k == SYSTEM_KEYCHAIN => Ok(()),
        other => {
            let _ = run(
                SECURITY,
                &[
                    "delete-generic-password",
                    "-a",
                    KEYCHAIN_ACCOUNT,
                    "-s",
                    plane.service(),
                ],
            )
            .await;
            Err(EnrollError::Keychain {
                op: "verify",
                detail: format!("the item landed in {other:?}, not {SYSTEM_KEYCHAIN}"),
            })
        }
    }
}

#[cfg(target_os = "macos")]
async fn codesign_verify(path: &str, req: &str) -> Result<Option<String>, EnrollError> {
    let o = run(CODESIGN, &["--verify", "--strict", "-R", req, path]).await?;
    Ok((!o.status.success()).then(|| {
        format!(
            "codesign --verify exited {:?}: {}",
            o.status.code(),
            String::from_utf8_lossy(&o.stderr).trim()
        )
    }))
}

#[cfg(target_os = "macos")]
struct Display {
    requirement: String,
    details: String,
    entitlements: String,
}

#[cfg(target_os = "macos")]
async fn display(path: &str) -> Result<Display, String> {
    let req = run(CODESIGN, &["-d", "-r-", path])
        .await
        .map_err(|e| e.to_string())?;
    let dv = run(CODESIGN, &["-dv", path])
        .await
        .map_err(|e| e.to_string())?;
    let ents = run(CODESIGN, &["-d", "--entitlements", "-", "--xml", path])
        .await
        .map_err(|e| e.to_string())?;
    for (what, o) in [("-d -r-", &req), ("-dv", &dv), ("-d --entitlements", &ents)] {
        if !o.status.success() {
            return Err(format!(
                "codesign {what} exited {:?}: {}",
                o.status.code(),
                String::from_utf8_lossy(&o.stderr).trim()
            ));
        }
    }
    Ok(Display {
        requirement: String::from_utf8_lossy(&req.stdout).into_owned(),
        details: String::from_utf8_lossy(&dv.stderr).into_owned(),
        entitlements: String::from_utf8_lossy(&ents.stdout).into_owned(),
    })
}

#[cfg(target_os = "macos")]
pub(crate) async fn own_team() -> Result<String, EnrollError> {
    let me = std::env::current_exe().map_err(|e| EnrollError::Command {
        program: "current_exe".to_string(),
        detail: e.to_string(),
    })?;
    let me_s = me.to_string_lossy().into_owned();
    let refuse = |reason: String| EnrollError::NotDeveloperIdSigned {
        binary: me_s.clone(),
        reason,
    };
    let d = display(&me_s).await.map_err(refuse)?;
    let team = parse_team(&d.details)
        .ok_or_else(|| refuse("no team identifier".to_string()))?
        .to_string();
    if let Some(why) = codesign_verify(&me_s, &anchor_requirement(&team)).await? {
        return Err(refuse(why));
    }
    let verified = display(&me_s).await.map_err(refuse)?;
    check_runtime_and_entitlements(&verified.details, &verified.entitlements).map_err(refuse)?;
    Ok(team)
}

#[cfg(target_os = "macos")]
pub(crate) async fn verify_release(
    binary: &'static str,
    plane: KeychainPlane,
    team: &str,
) -> Result<(), EnrollError> {
    let refuse = |reason: String| EnrollError::NotDeveloperIdSigned {
        binary: binary.to_string(),
        reason,
    };
    if let Some(why) = codesign_verify(binary, &requirement(plane.service(), team)).await? {
        return Err(refuse(why));
    }
    let d = display(binary).await.map_err(refuse)?;
    if !embedded_requirement_is_strong(&d.requirement, plane.service(), team) {
        return Err(refuse("its embedded designated requirement does not pin the Developer ID chain and team; the keychain ACL records that requirement".to_string()));
    }
    check_runtime_and_entitlements(&d.details, &d.entitlements).map_err(refuse)
}

#[cfg(target_os = "macos")]
pub(crate) fn binary_requirement(owner: u32) -> maknae_io::TargetRequired {
    maknae_io::TargetRequired {
        owner: Some(owner),
        mode_mask: Some(0o022),
        nlink_exactly_one: false,
        regular_file: true,
        max_bytes: Some(1 << 30),
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn check_install_path(bin: &std::path::Path) -> Result<(), EnrollError> {
    use maknae_io::{open_anchor, AnchorRequired, IoError, IoKind, StrategyPref};
    use std::path::Path;
    let refuse = |path: &Path, detail: String| EnrollError::NotRootInstalled {
        path: path.display().to_string(),
        detail,
    };
    let not_found = |path: &Path, e: IoError| {
        if matches!(
            e,
            IoError::Io {
                kind: IoKind::NotFound,
                ..
            }
        ) {
            EnrollError::NotInstalled {
                path: path.display().to_string(),
            }
        } else {
            refuse(path, e.to_string())
        }
    };
    let root_only = AnchorRequired {
        owner: Some(0),
        mode_mask: Some(0o022),
    };
    let dir = bin
        .parent()
        .ok_or_else(|| refuse(bin, "no parent directory".to_string()))?;
    let name = bin
        .file_name()
        .ok_or_else(|| refuse(bin, "no file name".to_string()))?;
    let mut chain: Vec<&Path> = dir.ancestors().filter(|a| a.parent().is_some()).collect();
    chain.reverse();
    let mut last = None;
    for d in chain {
        last = Some(
            open_anchor(d, root_only.clone(), StrategyPref::Auto).map_err(|e| not_found(d, e))?,
        );
    }
    let anchor = last.ok_or_else(|| refuse(dir, "no directory to anchor".to_string()))?;
    anchor
        .read(Path::new(name), None, binary_requirement(0))
        .map_err(|e| not_found(bin, e))?;
    Ok(())
}

pub(crate) fn embedded_requirement_is_strong(display: &str, identifier: &str, team: &str) -> bool {
    let canonical = |t: &str| {
        format!(
            "designated => identifier \"{identifier}\" and anchor apple generic and certificate 1[field.{DEVELOPER_ID_CA_OID}] /* exists */ and certificate leaf[field.{DEVELOPER_ID_LEAF_OID}] /* exists */ and certificate leaf[subject.OU] = {t}"
        )
    };
    let (bare, quoted) = (canonical(team), canonical(&format!("\"{team}\"")));
    display
        .lines()
        .map(str::trim)
        .any(|l| l == bare || l == quoted)
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "4f3c2a10-9b7e-4d21-8c55-0a1b2c3d4e5f";
    const DEV_DV: &str = "Identifier=io.maknae.maknaed\nCodeDirectory v=20500 size=317 flags=0x10000(runtime) hashes=4+2 location=embedded\nSignature size=8987\nTeamIdentifier=TEAM123456\n";
    const FORGED_DV: &str = "Identifier=io.maknae.maknaed\nCodeDirectory v=20500 size=306 flags=0x10002(adhoc,runtime) hashes=4+2 location=embedded\nSignature=adhoc\nTeamIdentifier=not set\n";
    const ENTS: &str = "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>com.apple.security.cs.disable-library-validation</key><true/></dict></plist>";

    #[test]
    fn a_secret_id_must_be_a_lowercase_uuid() {
        assert!(validate_secret_id(UUID).is_ok());
        for bad in [
            "",
            "4F3C2A10-9B7E-4D21-8C55-0A1B2C3D4E5F",
            "4f3c2a10 9b7e-4d21-8c55-0a1b2c3d4e5f",
            "4f3c2a10-9b7e-4d21-8c55-0a1b2c3d4e5",
            "4f3c2a10-9b7e-4d21-8c55-0a1b2c3d4e5f\n",
            "4f3c2a109b7e-4d21-8c55-0a1b2c3d4e5f-",
        ] {
            assert!(
                matches!(validate_secret_id(bad), Err(EnrollError::SecretIdShape)),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn the_add_command_is_exact_and_sized_once() {
        let s = Zeroizing::new(UUID.to_string());
        let c = add_command(&s, KeychainPlane::Egress, EGRESS_BINARY);
        assert_eq!(
            c.as_str(),
            format!("add-generic-password -a secret-id -s io.maknae.maknae-egress -T /usr/local/bin/maknae-egress -w {UUID} /Library/Keychains/System.keychain\n")
        );
        assert_eq!(c.capacity(), c.len());
    }

    #[test]
    fn delete_and_find_carry_no_secret() {
        assert_eq!(
            delete_args(KeychainPlane::Daemon),
            [
                "delete-generic-password",
                "-a",
                "secret-id",
                "-s",
                "io.maknae.maknaed",
                "/Library/Keychains/System.keychain"
            ]
        );
        assert_eq!(find_args(KeychainPlane::Daemon)[0], "find-generic-password");
        assert_eq!(
            &find_args(KeychainPlane::Daemon)[1..],
            &delete_args(KeychainPlane::Daemon)[1..]
        );
    }

    #[test]
    fn the_keychain_line_names_where_the_item_landed() {
        let out = "keychain: \"/Library/Keychains/System.keychain\"\nversion: 256\n";
        assert_eq!(
            parse_keychain_line(out),
            Some("/Library/Keychains/System.keychain")
        );
        assert_eq!(
            parse_keychain_line("keychain: \"/Users/op/Library/Keychains/login.keychain-db\"\n"),
            Some("/Users/op/Library/Keychains/login.keychain-db")
        );
        assert_eq!(parse_keychain_line("version: 256\n"), None);
    }

    #[test]
    fn the_requirements_pin_identifier_developer_id_and_team() {
        assert_eq!(
            requirement("io.maknae.maknaed", "TEAM123456"),
            "=identifier \"io.maknae.maknaed\" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] and certificate leaf[field.1.2.840.113635.100.6.1.13] and certificate leaf[subject.OU] = \"TEAM123456\""
        );
        assert_eq!(
            anchor_requirement("TEAM123456"),
            "=anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] and certificate leaf[field.1.2.840.113635.100.6.1.13] and certificate leaf[subject.OU] = \"TEAM123456\""
        );
    }

    #[test]
    fn the_team_is_read_only_from_a_real_team_line() {
        assert_eq!(parse_team(DEV_DV), Some("TEAM123456"));
        assert_eq!(parse_team(FORGED_DV), None);
        assert_eq!(parse_team("Identifier=x\n"), None);
        assert_eq!(parse_team("TeamIdentifier=TEAM\"1\n"), None);
    }

    #[test]
    fn an_adhoc_flag_is_refused_even_with_no_signature_adhoc_line() {
        let dv = "Identifier=io.maknae.maknaed\nCodeDirectory v=20500 size=306 flags=0x10002(adhoc,runtime) hashes=4+2 location=embedded\nSignature size=8987\nTeamIdentifier=TEAM123456\n";
        assert!(check_runtime_and_entitlements(dv, "").is_err());
    }

    #[test]
    fn a_secret_id_hex_digit_out_of_range_is_refused() {
        assert!(matches!(
            validate_secret_id("4f3c2a10-9b7e-4d21-8c55-0a1b2c3d4e5g"),
            Err(EnrollError::SecretIdShape)
        ));
    }

    #[test]
    fn runtime_without_adhoc_and_no_entitlements_is_required() {
        assert!(check_runtime_and_entitlements(DEV_DV, "").is_ok());
        assert!(check_runtime_and_entitlements(FORGED_DV, "").is_err());
        assert!(check_runtime_and_entitlements(&format!("{DEV_DV}Signature=adhoc\n"), "").is_err());
        assert!(
            check_runtime_and_entitlements(&DEV_DV.replace("(runtime)", "(none)"), "").is_err()
        );
        assert!(check_runtime_and_entitlements(DEV_DV, ENTS).is_err());
    }

    #[test]
    fn the_embedded_requirement_must_itself_pin_the_chain_and_team() {
        let strong = "designated => identifier \"io.maknae.maknaed\" and anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = TEAM123456";
        assert!(embedded_requirement_is_strong(
            strong,
            "io.maknae.maknaed",
            "TEAM123456"
        ));
        assert!(embedded_requirement_is_strong(
            &strong.replace("= TEAM123456", "= \"TEAM123456\""),
            "io.maknae.maknaed",
            "TEAM123456"
        ));
        assert!(!embedded_requirement_is_strong(
            "designated => identifier \"io.maknae.maknaed\"",
            "io.maknae.maknaed",
            "TEAM123456"
        ));
        assert!(!embedded_requirement_is_strong(
            strong,
            "io.maknae.maknaed",
            "OTHERTEAM1"
        ));
        assert!(!embedded_requirement_is_strong(
            strong,
            "io.maknae.maknae-egress",
            "TEAM123456"
        ));
        assert!(!embedded_requirement_is_strong(
            &strong.replace("anchor apple generic and ", ""),
            "io.maknae.maknaed",
            "TEAM123456"
        ));
        assert!(!embedded_requirement_is_strong(
            &format!("# {strong}"),
            "io.maknae.maknaed",
            "TEAM123456"
        ));
        assert!(!embedded_requirement_is_strong(
            &strong.replace(
                "certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and ",
                ""
            ),
            "io.maknae.maknaed",
            "TEAM123456"
        ));
        assert!(!embedded_requirement_is_strong(
            &strong.replace(
                "certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and ",
                ""
            ),
            "io.maknae.maknaed",
            "TEAM123456"
        ));
        let with_or = strong.replace(
            " and certificate leaf[subject.OU] = TEAM123456",
            " or identifier \"io.maknae.maknaed\" and certificate leaf[subject.OU] = TEAM123456",
        );
        assert!(!embedded_requirement_is_strong(
            &with_or,
            "io.maknae.maknaed",
            "TEAM123456"
        ));
    }
}

#[cfg(all(test, target_os = "macos"))]
mod darwin_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn a_hard_link_does_not_disqualify_an_installed_binary() {
        let uid = nix::unistd::geteuid().as_raw();
        let req = binary_requirement(uid);

        let dir = std::env::temp_dir().join(format!("maknae-nlink-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let bin = dir.join("maknaed");
        std::fs::write(&bin, b"binary").unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::hard_link(&bin, dir.join("second-name")).unwrap();

        let anchor = maknae_io::open_anchor(
            &dir,
            maknae_io::AnchorRequired::OS_DAC,
            maknae_io::StrategyPref::Auto,
        )
        .unwrap();
        let read = anchor.read(std::path::Path::new("maknaed"), None, req.clone());
        let _ = std::fs::remove_dir_all(&dir);
        assert!(read.is_ok(), "{:?}", read.err());
        assert!(!req.nlink_exactly_one);
        assert!(req.regular_file);
        assert_eq!(req.owner, Some(uid));
        assert_eq!(req.mode_mask, Some(0o022));
    }

    #[test]
    fn a_missing_binary_is_reported_as_not_installed() {
        let e = EnrollError::NotInstalled {
            path: DAEMON_BINARY.to_string(),
        };
        let text = e.to_string();
        assert!(!text.contains("replaced"), "{text}");
        assert!(text.contains("is not installed"), "{text}");
    }
}
