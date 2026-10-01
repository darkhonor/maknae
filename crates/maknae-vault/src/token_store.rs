use crate::token_record::{
    decrypt_refusal, encrypt_output_refusal, erase_every, every_custody, first_present,
    keychain_erase_outcome, read_record, systemd_major, token_dir_refusal, token_dir_required,
    token_file_refusal, token_file_required, StoredToken, SystemdCreds, TokenCustody,
    MAX_CREDS_FILE_BYTES, MAX_TOKEN_RECORD_BYTES, SYSTEMD_CREDS, TOKEN_CREDS_NAME, TOKEN_FILE_MODE,
};
use crate::{UserToken, VaultError};
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use zeroize::Zeroizing;

#[cfg(target_os = "macos")]
use crate::token_record::keychain_read_refusal;

const MAX_STDERR_BYTES: u64 = 4096;
const MAX_STDERR_DRAIN: u64 = 1 << 20;

fn store_failure(what: &str, detail: impl std::fmt::Display) -> VaultError {
    VaultError::TokenStore(format!("{what}: {detail}"))
}

fn euid() -> u32 {
    nix::unistd::geteuid().as_raw()
}

pub fn observe_systemd_creds() -> Result<SystemdCreds, VaultError> {
    match Command::new(SYSTEMD_CREDS).arg("--version").output() {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(SystemdCreds::Absent),
        Err(e) => Err(store_failure("systemd-creds --version", e)),
        Ok(out) if !out.status.success() => {
            Err(store_failure("systemd-creds --version", out.status))
        }
        Ok(out) => systemd_major(&String::from_utf8_lossy(&out.stdout))
            .map(SystemdCreds::Version)
            .ok_or_else(|| store_failure("systemd-creds --version", "printed no version")),
    }
}

pub fn store_user_token(custody: &TokenCustody, stored: &StoredToken) -> Result<(), VaultError> {
    let record = stored.encode();
    match custody {
        TokenCustody::Keychain => keychain_store(&record),
        TokenCustody::UserCreds(path) => publish(path, &encrypt(&record)?),
        TokenCustody::Residual(path) => publish(path, &record),
    }
}

pub fn read_user_token(cli_dir: &Path) -> Result<StoredToken, VaultError> {
    first_present(
        every_custody(cli_dir, cfg!(target_os = "macos"))
            .iter()
            .map(read_custody),
    )
}

pub fn load_user_token(
    cli_dir: &Path,
    vault_addr: &str,
    now: u64,
) -> Result<UserToken, VaultError> {
    read_user_token(cli_dir)?.usable_at(vault_addr, now)
}

pub fn erase_user_token(cli_dir: &Path, keep: Option<&TokenCustody>) -> Result<bool, VaultError> {
    erase_every(
        every_custody(cli_dir, cfg!(target_os = "macos")),
        keep,
        erase_custody,
    )
}

fn read_custody(custody: &TokenCustody) -> Result<StoredToken, VaultError> {
    let record = match custody {
        TokenCustody::Keychain => keychain_read()?,
        TokenCustody::UserCreds(path) => decrypt(&read_file(path, MAX_CREDS_FILE_BYTES)?)?,
        TokenCustody::Residual(path) => read_file(path, MAX_TOKEN_RECORD_BYTES)?,
    };
    StoredToken::decode(&record)
}

fn erase_custody(custody: &TokenCustody) -> Result<bool, VaultError> {
    match custody {
        TokenCustody::Keychain => keychain_erase(),
        TokenCustody::UserCreds(path) | TokenCustody::Residual(path) => remove(path),
    }
}

fn anchor_for(file: &Path) -> Result<Option<(maknae_io::Anchor, &Path)>, VaultError> {
    let dir = file
        .parent()
        .ok_or_else(|| store_failure("token path", "has no directory"))?;
    let name = file
        .file_name()
        .map(Path::new)
        .ok_or_else(|| store_failure("token path", "has no file name"))?;
    let dir = std::path::absolute(dir).map_err(|e| store_failure("token directory", e))?;
    match maknae_io::open_anchor(
        &dir,
        token_dir_required(euid()),
        maknae_io::StrategyPref::Auto,
    ) {
        Ok(anchor) => Ok(Some((anchor, name))),
        Err(e) => token_dir_refusal(e).map_or(Ok(None), Err),
    }
}

fn publish(path: &Path, bytes: &[u8]) -> Result<(), VaultError> {
    let (anchor, name) = anchor_for(path)?.ok_or_else(|| {
        store_failure(
            "token directory",
            "does not exist; run `sudo maknae enroll`",
        )
    })?;
    anchor
        .publish(name, None, bytes, maknae_io::Mode(TOKEN_FILE_MODE))
        .map(drop)
        .map_err(|e| store_failure("writing the token", e))
}

fn read_file(path: &Path, max: usize) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let Some((anchor, name)) = anchor_for(path)? else {
        return Err(VaultError::TokenAbsent);
    };
    anchor
        .read(name, None, token_file_required(euid(), max))
        .map(|out| out.value)
        .map_err(token_file_refusal)
}

fn remove(path: &Path) -> Result<bool, VaultError> {
    let Some((anchor, name)) = anchor_for(path)? else {
        return Ok(false);
    };
    anchor
        .remove(name, None)
        .map(|out| out.value)
        .map_err(|e| store_failure("erasing the token", e))
}

fn stderr_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .trim()
        .chars()
        .take(200)
        .collect()
}

fn creds_command(verb: &str) -> Command {
    let mut cmd = Command::new(SYSTEMD_CREDS);
    cmd.arg(verb).arg("--user");
    if verb == "encrypt" {
        cmd.arg("--with-key=auto");
    }
    cmd.arg(format!("--name={TOKEN_CREDS_NAME}"))
        .args(["-", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

fn feed(child: &mut std::process::Child, input: &[u8]) -> std::io::Result<()> {
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| std::io::Error::other("no stdin"))?;
    stdin.write_all(input)
}

struct CredsRun {
    out: Result<Zeroizing<Vec<u8>>, VaultError>,
    stderr: Vec<u8>,
    status: std::process::ExitStatus,
}

fn reap(child: &mut std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn run_creds(verb: &str, input: &[u8], cap: usize) -> Result<CredsRun, String> {
    let mut child = creds_command(verb).spawn().map_err(|e| e.to_string())?;
    if let Err(e) = feed(&mut child, input) {
        reap(&mut child);
        return Err(e.to_string());
    }
    let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
        reap(&mut child);
        return Err("no output pipe".to_string());
    };
    let out = read_record(stdout, cap);
    let mut err_bytes = Vec::new();
    let mut stderr = stderr;
    let _ = (&mut stderr)
        .take(MAX_STDERR_BYTES)
        .read_to_end(&mut err_bytes);
    let _ = std::io::copy(&mut stderr.take(MAX_STDERR_DRAIN), &mut std::io::sink());
    if out.is_err() {
        let _ = child.kill();
    }
    let status = child.wait().map_err(|e| e.to_string())?;
    Ok(CredsRun {
        out,
        stderr: err_bytes,
        status,
    })
}

fn encrypt(record: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let what = "systemd-creds encrypt --user";
    let run =
        run_creds("encrypt", record, MAX_CREDS_FILE_BYTES).map_err(|e| store_failure(what, e))?;
    if !run.status.success() && run.out.is_ok() {
        return Err(store_failure(what, stderr_text(&run.stderr)));
    }
    run.out
        .map_err(|e| store_failure(what, encrypt_output_refusal(&e)))
}

fn decrypt(ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    let run = run_creds("decrypt", ciphertext, MAX_TOKEN_RECORD_BYTES)
        .map_err(|e| decrypt_refusal(&e))?;
    if !run.status.success() {
        return Err(decrypt_refusal(&stderr_text(&run.stderr)));
    }
    run.out
}

#[cfg(target_os = "macos")]
type Keychain = security_framework::os::macos::keychain::SecKeychain;

#[cfg(target_os = "macos")]
fn default_keychain() -> Result<Keychain, VaultError> {
    crate::keychain::default_keychain()
        .map_err(|e| store_failure("keychain open", format!("status {}", e.code())))
}

#[cfg(target_os = "macos")]
fn keychain_store(record: &[u8]) -> Result<(), VaultError> {
    keychain_store_in(&default_keychain()?, record)
}

#[cfg(target_os = "macos")]
fn keychain_read() -> Result<Zeroizing<Vec<u8>>, VaultError> {
    keychain_read_in(&default_keychain()?)
}

#[cfg(target_os = "macos")]
fn keychain_erase() -> Result<bool, VaultError> {
    keychain_erase_in(&default_keychain()?)
}

#[cfg(target_os = "macos")]
fn keychain_store_in(kc: &Keychain, record: &[u8]) -> Result<(), VaultError> {
    keychain_erase_in(kc)?;
    let item = crate::CLI_TOKEN_KEYCHAIN_ITEM;
    kc.add_generic_password(item.service, item.account, record)
        .map_err(|e| store_failure("keychain add", format!("status {}", e.code())))?;
    match keychain_read_in(kc) {
        Ok(back) if back.as_slice() == record => Ok(()),
        Ok(_) => Err(store_failure(
            "keychain verify",
            "the item read back differs from the token stored",
        )),
        Err(_) => Err(store_failure(
            "keychain verify",
            "the item just stored could not be read back",
        )),
    }
}

#[cfg(target_os = "macos")]
fn keychain_read_in(kc: &Keychain) -> Result<Zeroizing<Vec<u8>>, VaultError> {
    crate::keychain::read_item_in(|| Ok(kc.clone()), &crate::CLI_TOKEN_KEYCHAIN_ITEM)
        .map(|mut text| Zeroizing::new(std::mem::take(&mut *text).into_bytes()))
        .map_err(keychain_read_refusal)
}

#[cfg(target_os = "macos")]
fn keychain_erase_in(kc: &Keychain) -> Result<bool, VaultError> {
    keychain_erase_outcome(crate::keychain::delete_item_in(
        || Ok(kc.clone()),
        &crate::CLI_TOKEN_KEYCHAIN_ITEM,
    ))
}

#[cfg(not(target_os = "macos"))]
fn keychain_store(_record: &[u8]) -> Result<(), VaultError> {
    Err(store_failure("keychain", "exists only on macOS"))
}

#[cfg(not(target_os = "macos"))]
fn keychain_read() -> Result<Zeroizing<Vec<u8>>, VaultError> {
    Err(store_failure("keychain", "exists only on macOS"))
}

#[cfg(not(target_os = "macos"))]
fn keychain_erase() -> Result<bool, VaultError> {
    keychain_erase_outcome(Ok(crate::KeychainDelete::Absent))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token_record::{TOKEN_CREDS_FILE, TOKEN_RESIDUAL_FILE};
    use std::fs::Permissions;
    use std::os::unix::fs::PermissionsExt;
    use std::time::Duration;

    fn cli_dir() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        std::fs::set_permissions(d.path(), Permissions::from_mode(0o700)).unwrap();
        d
    }

    fn stored(token: &str, expires_at: u64) -> StoredToken {
        let login = crate::UserLogin {
            token: UserToken::new(Zeroizing::new(token.into())).unwrap(),
            lease: Duration::from_secs(expires_at),
            renewable: true,
        };
        StoredToken::from_login(login, 0, ADDR).unwrap()
    }

    const ADDR: &str = "https://vault.example:8200/v1/";

    fn residual(d: &Path) -> TokenCustody {
        TokenCustody::Residual(d.join(TOKEN_RESIDUAL_FILE))
    }

    #[test]
    fn a_residual_token_round_trips_owner_only() {
        let d = cli_dir();
        let c = residual(d.path());
        store_user_token(&c, &stored("hvs.residual", 5_000)).unwrap();
        let mode = std::fs::metadata(d.path().join(TOKEN_RESIDUAL_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o077, 0, "{mode:o}");
        let back = read_custody(&c).unwrap();
        assert!(back.token().expose() == "hvs.residual");
        assert_eq!(back.expires_at(), 5_000);
        assert!(erase_custody(&c).unwrap());
        assert!(matches!(read_custody(&c), Err(VaultError::TokenAbsent)));
        assert!(!erase_custody(&c).unwrap());
    }

    #[test]
    fn a_group_readable_or_linked_residual_is_refused_with_the_login_hint() {
        let d = cli_dir();
        let c = residual(d.path());
        let p = d.path().join(TOKEN_RESIDUAL_FILE);
        std::fs::write(&p, stored("hvs.x", 9).encode().as_slice()).unwrap();
        std::fs::set_permissions(&p, Permissions::from_mode(0o640)).unwrap();
        assert!(matches!(
            read_custody(&c),
            Err(VaultError::TokenUnreadable(_))
        ));
        std::fs::remove_file(&p).unwrap();
        let real = d.path().join("elsewhere");
        std::fs::write(&real, stored("hvs.x", 9).encode().as_slice()).unwrap();
        std::fs::set_permissions(&real, Permissions::from_mode(0o600)).unwrap();
        std::os::unix::fs::symlink(&real, &p).unwrap();
        assert!(matches!(
            read_custody(&c),
            Err(VaultError::TokenUnreadable(_))
        ));
    }

    #[test]
    fn storing_replaces_a_refused_residual_instead_of_writing_into_it() {
        let d = cli_dir();
        let c = residual(d.path());
        let p = d.path().join(TOKEN_RESIDUAL_FILE);
        let elsewhere = d.path().join("elsewhere");
        std::fs::write(&elsewhere, b"untouched").unwrap();
        std::os::unix::fs::symlink(&elsewhere, &p).unwrap();
        store_user_token(&c, &stored("hvs.fresh", 9_000)).unwrap();
        assert_eq!(std::fs::read(&elsewhere).unwrap(), b"untouched");
        assert!(read_custody(&c).unwrap().token().expose() == "hvs.fresh");
        std::fs::set_permissions(&p, Permissions::from_mode(0o666)).unwrap();
        assert!(matches!(
            read_custody(&c),
            Err(VaultError::TokenUnreadable(_))
        ));
        store_user_token(&c, &stored("hvs.again", 9_000)).unwrap();
        assert!(read_custody(&c).unwrap().token().expose() == "hvs.again");
    }

    #[test]
    fn a_missing_cli_directory_holds_no_token_and_takes_none() {
        let d = cli_dir();
        let c = residual(&d.path().join("absent"));
        assert!(matches!(read_custody(&c), Err(VaultError::TokenAbsent)));
        assert!(!erase_custody(&c).unwrap());
        assert!(matches!(
            store_user_token(&c, &stored("hvs.x", 9)),
            Err(VaultError::TokenStore(_))
        ));
    }

    #[test]
    fn a_group_accessible_cli_directory_is_refused_without_a_login_hint() {
        let d = cli_dir();
        std::fs::set_permissions(d.path(), Permissions::from_mode(0o750)).unwrap();
        assert!(matches!(
            store_user_token(&residual(d.path()), &stored("hvs.x", 9)),
            Err(VaultError::TokenStore(_))
        ));
        assert!(matches!(
            read_custody(&residual(d.path())),
            Err(VaultError::TokenStore(_))
        ));
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn on_linux_the_residual_is_read_loaded_and_erased() {
        let d = cli_dir();
        assert!(matches!(
            read_user_token(d.path()),
            Err(VaultError::TokenAbsent)
        ));
        assert!(!erase_user_token(d.path(), None).unwrap());
        store_user_token(&residual(d.path()), &stored("hvs.r", 10_000)).unwrap();
        assert!(load_user_token(d.path(), ADDR, 0).unwrap().expose() == "hvs.r");
        assert!(matches!(
            load_user_token(d.path(), ADDR, 10_000),
            Err(VaultError::TokenExpired)
        ));
        assert!(matches!(
            load_user_token(d.path(), "https://vault.other:8200/v1/", 0),
            Err(VaultError::TokenOtherVault(a)) if a == ADDR
        ));
        assert!(!erase_user_token(d.path(), Some(&residual(d.path()))).unwrap());
        assert!(erase_user_token(d.path(), None).unwrap());
        assert!(matches!(
            read_user_token(d.path()),
            Err(VaultError::TokenAbsent)
        ));
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn a_failed_credential_erase_still_removes_the_residual_and_is_reported() {
        let d = cli_dir();
        store_user_token(&residual(d.path()), &stored("hvs.r", 10_000)).unwrap();
        std::fs::create_dir(d.path().join(TOKEN_CREDS_FILE)).unwrap();
        assert!(matches!(
            erase_user_token(d.path(), None),
            Err(VaultError::TokenStore(_))
        ));
        assert!(!d.path().join(TOKEN_RESIDUAL_FILE).exists());
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn a_broken_credential_is_not_skipped_for_the_residual() {
        let d = cli_dir();
        store_user_token(&residual(d.path()), &stored("hvs.r", 10_000)).unwrap();
        let cred = d.path().join(TOKEN_CREDS_FILE);
        std::fs::write(&cred, b"not a credential").unwrap();
        std::fs::set_permissions(&cred, Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            read_user_token(d.path()),
            Err(VaultError::TokenUnreadable(_))
        ));
    }

    #[cfg(target_os = "macos")]
    fn within_30s<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)));
        });
        match rx.recv_timeout(Duration::from_secs(30)) {
            Ok(Ok(value)) => value,
            Ok(Err(panic)) => std::panic::resume_unwind(panic),
            Err(_) => panic!("the keychain call did not return in 30 s: a dialog is waiting"),
        }
    }

    #[cfg(target_os = "macos")]
    fn default_keychain_refs() -> Option<usize> {
        within_30s(|| {
            let default = Keychain::default().ok()?;
            Some(
                crate::keychain::item_refs(&default, &crate::CLI_TOKEN_KEYCHAIN_ITEM)
                    .unwrap()
                    .len(),
            )
        })
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_keychain_token_round_trips_replaces_and_erases() {
        let _serial = crate::keychain::tests::KEYCHAIN_UI
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let before = default_keychain_refs();
        let kc = crate::keychain::tests::scratch_with_cli_item(None);
        let path = kc.path.clone();
        within_30s(move || {
            let open = Keychain::open(&path).unwrap();
            assert!(matches!(
                keychain_read_in(&open),
                Err(VaultError::TokenAbsent)
            ));
            keychain_store_in(&open, &stored("hvs.kc", 7_000).encode()).unwrap();
            keychain_store_in(&open, &stored("hvs.kc2", 8_000).encode()).unwrap();
            let back = StoredToken::decode(&keychain_read_in(&open).unwrap()).unwrap();
            assert!(back.token().expose() == "hvs.kc2");
            assert_eq!(back.expires_at(), 8_000);
            assert!(keychain_erase_in(&open).unwrap());
            assert!(!keychain_erase_in(&open).unwrap());
            assert!(matches!(
                keychain_read_in(&open),
                Err(VaultError::TokenAbsent)
            ));
        });
        assert_eq!(default_keychain_refs(), before);
    }

    #[cfg(target_os = "macos")]
    fn with_an_item_not_trusting_this_binary() -> crate::keychain::tests::Scratch {
        let kc = crate::keychain::tests::scratch_with_cli_item(None);
        let item = crate::CLI_TOKEN_KEYCHAIN_ITEM;
        let added = std::process::Command::new("/usr/bin/security")
            .args([
                "add-generic-password",
                "-s",
                item.service,
                "-a",
                item.account,
                "-T",
                "/usr/bin/true",
                "-w",
                "maknae-vault-token v1 9 https://vault.example:8200/v1/ hvs.untrusted",
                kc.path.to_str().unwrap(),
            ])
            .status()
            .unwrap();
        assert!(added.success());
        kc
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_keychain_item_this_binary_cannot_read_is_still_replaced() {
        let _serial = crate::keychain::tests::KEYCHAIN_UI
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let kc = with_an_item_not_trusting_this_binary();
        let path = kc.path.clone();
        within_30s(move || {
            let open = Keychain::open(&path).unwrap();
            assert!(matches!(
                keychain_read_in(&open),
                Err(VaultError::TokenUnreadable(m)) if m == "keychain status -25293"
            ));
            keychain_store_in(&open, &stored("hvs.replaced", 9_000).encode()).unwrap();
            let back = StoredToken::decode(&keychain_read_in(&open).unwrap()).unwrap();
            assert!(back.token().expose() == "hvs.replaced");
        });
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_keychain_item_this_binary_cannot_read_is_still_erased() {
        let _serial = crate::keychain::tests::KEYCHAIN_UI
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let kc = with_an_item_not_trusting_this_binary();
        let path = kc.path.clone();
        within_30s(move || {
            let open = Keychain::open(&path).unwrap();
            assert!(keychain_erase_in(&open).unwrap());
            assert!(matches!(
                keychain_read_in(&open),
                Err(VaultError::TokenAbsent)
            ));
        });
    }

    #[test]
    #[ignore = "needs systemd-creds --user (systemd >= 256): run on the Rocky 10 host"]
    fn a_user_credential_token_round_trips() {
        assert!(matches!(
            observe_systemd_creds().unwrap(),
            SystemdCreds::Version(v) if v >= 256
        ));
        let d = cli_dir();
        let c = TokenCustody::UserCreds(d.path().join(TOKEN_CREDS_FILE));
        store_user_token(&c, &stored("hvs.creds-sentinel", 6_000)).unwrap();
        let raw = std::fs::read(d.path().join(TOKEN_CREDS_FILE)).unwrap();
        assert!(!raw.windows(18).any(|w| w == b"hvs.creds-sentinel"));
        assert!(read_custody(&c).unwrap().token().expose() == "hvs.creds-sentinel");
        assert!(erase_custody(&c).unwrap());
        assert!(matches!(read_custody(&c), Err(VaultError::TokenAbsent)));
    }
}
