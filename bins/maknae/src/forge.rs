use crate::stderr::errln;
use crate::tty::{HiddenLine, PromptError};
use maknae_agent::hints::Forge;
use maknae_loop::tasker::{TaskerClient, TaskerError};
use maknae_vault::{KvSecret, PasswordFeed, UserToken, VaultApi, VaultError, MAX_TOKEN_BYTES};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;
use zeroize::{Zeroize, Zeroizing};

/// Where the person's forge logins live in Vault.
pub(crate) struct Place<'a> {
    pub(crate) kv_mount: &'a str,
    pub(crate) user_prefix: &'a str,
    pub(crate) username: &'a str,
}

pub(crate) trait LoginStore {
    async fn write(
        &self,
        kv_mount: &str,
        path: &str,
        field: &str,
        secret: &KvSecret,
        wrap_ttl: Duration,
    ) -> Result<(), VaultError>;

    async fn delete(&self, kv_mount: &str, path: &str) -> Result<(), VaultError>;
}

pub(crate) fn login_path(
    forges: &[Forge],
    server: &str,
    place: &Place<'_>,
) -> Result<String, String> {
    let Some(forge) = forges.iter().find(|f| f.host == server) else {
        return Err(unknown_server(forges, server));
    };
    if !maknae_forge::observes_reach(forge.provider) {
        return Err(format!(
            "{server} is a {} forge, which maknae does not check reach on, so it takes no forge \
             login",
            forge.provider.as_str()
        ));
    }
    let subpath = maknae_vault::forge_token_subpath(server).ok_or_else(|| {
        format!(
            "{server} has no forge login path: maknae stores none for an IPv6 literal or an \
             over-long host"
        )
    })?;
    maknae_config::user_key_path(place.user_prefix, place.username, subpath.as_str())
        .map_err(|e| format!("{server} has no forge login path: {e}"))
}

fn unknown_server(forges: &[Forge], server: &str) -> String {
    let named = crate::cli::terminal_safe(server);
    if forges.is_empty() {
        return format!("{named} is not a forge this host configures: it configures no forges");
    }
    let hosts: Vec<&str> = forges.iter().map(|f| f.host.as_str()).collect();
    format!(
        "{named} is not a forge this host configures; its forges are: {}",
        crate::cli::terminal_safe(&hosts.join(", "))
    )
}

pub(crate) async fn login(
    store: &impl LoginStore,
    place: &Place<'_>,
    forges: &[Forge],
    server: &str,
    token: impl FnOnce() -> Result<KvSecret, String>,
) -> Result<String, String> {
    let path = login_path(forges, server, place)?;
    let secret = token()?;
    store
        .write(
            place.kv_mount,
            &path,
            maknae_vault::FORGE_TOKEN_FIELD,
            &secret,
            maknae_vault::USER_KEY_WRAP_TTL,
        )
        .await
        .map_err(|e| vault_failure("store", server, &e))?;
    Ok(format!(
        "maknae: your forge login for {server} is stored in Vault"
    ))
}

pub(crate) async fn logout(
    store: &impl LoginStore,
    place: &Place<'_>,
    forges: &[Forge],
    server: &str,
) -> Result<String, String> {
    let path = login_path(forges, server, place)?;
    store
        .delete(place.kv_mount, &path)
        .await
        .map_err(|e| vault_failure("erase", server, &e))?;
    Ok(format!(
        "maknae: your forge login for {server} is erased from Vault"
    ))
}

fn vault_failure(what: &str, server: &str, e: &VaultError) -> String {
    match e {
        VaultError::VaultStatus { status: 403, .. } => format!(
            "Vault refused to {what} your forge login for {server} (HTTP 403): it is outside your \
             Vault policy, or your login was revoked: run `maknae login`"
        ),
        other => format!("Vault could not {what} your forge login for {server}: {other}"),
    }
}

/// The typed token, in a buffer sized once for the longest acceptable token.
pub(crate) struct TokenLine {
    buf: Zeroizing<Vec<u8>>,
    invalid: bool,
    ended: Option<PasswordFeed>,
}

impl TokenLine {
    pub(crate) fn new() -> Self {
        Self {
            buf: Zeroizing::new(Vec::with_capacity(MAX_TOKEN_BYTES)),
            invalid: false,
            ended: None,
        }
    }

    fn step(&mut self, byte: u8) -> PasswordFeed {
        match byte {
            b'\r' | b'\n' => PasswordFeed::Done,
            0x03 | 0x1c => PasswordFeed::Interrupted,
            0x04 if self.buf.is_empty() => PasswordFeed::Eof,
            0x7f | 0x08 => {
                if let Some(last) = self.buf.last_mut() {
                    *last = 0;
                    self.buf.pop();
                }
                PasswordFeed::More
            }
            0x15 => {
                self.buf.zeroize();
                self.invalid = false;
                PasswordFeed::More
            }
            _ if self.buf.len() == MAX_TOKEN_BYTES => PasswordFeed::TooLong,
            b if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-') => {
                self.buf.push(b);
                PasswordFeed::More
            }
            _ => {
                self.invalid = true;
                PasswordFeed::More
            }
        }
    }

    pub(crate) fn finish(mut self) -> Result<KvSecret, String> {
        if self.ended != Some(PasswordFeed::Done) {
            return Err("the token line was not completed".into());
        }
        if self.invalid {
            return Err("a forge token holds only A-Z, a-z, 0-9, '.', '_' and '-'".into());
        }
        let token = String::from_utf8(std::mem::take(&mut *self.buf)).map_err(|e| {
            drop(Zeroizing::new(e.into_bytes()));
            "the token is not UTF-8".to_string()
        })?;
        KvSecret::new(Zeroizing::new(token)).map_err(|e| e.to_string())
    }
}

impl HiddenLine for TokenLine {
    fn feed(&mut self, byte: u8) -> PasswordFeed {
        if let Some(end) = self.ended {
            return end;
        }
        let fed = self.step(byte);
        if fed != PasswordFeed::More {
            self.ended = Some(fed);
        }
        fed
    }
}

pub(crate) fn prompt_failure(e: PromptError) -> String {
    match e {
        PromptError::NotATerminal => "no terminal on standard input: run it interactively; the \
                                      token is read only from a hidden prompt, never from \
                                      arguments, the environment or a pipe"
            .into(),
        PromptError::NoPassword => "no token was entered".into(),
        PromptError::TooLong => format!("the token is longer than {MAX_TOKEN_BYTES} bytes"),
        other => other.to_string(),
    }
}

fn read_token(server: &str) -> Result<KvSecret, String> {
    let mut line = TokenLine::new();
    crate::tty::read_hidden(&format!("Token for {server} (will be hidden): "), &mut line)
        .map_err(prompt_failure)?;
    line.finish()
}

struct Vault<'a> {
    api: &'a VaultApi,
    token: &'a UserToken,
}

impl LoginStore for Vault<'_> {
    async fn write(
        &self,
        kv_mount: &str,
        path: &str,
        field: &str,
        secret: &KvSecret,
        wrap_ttl: Duration,
    ) -> Result<(), VaultError> {
        self.api
            .write_wrapped(self.token, kv_mount, path, field, secret, wrap_ttl)
            .await
    }

    async fn delete(&self, kv_mount: &str, path: &str) -> Result<(), VaultError> {
        self.api.delete_metadata(self.token, kv_mount, path).await
    }
}

enum Action {
    Login,
    Logout,
}

async fn act(action: Action, server: &str) -> Result<String, String> {
    if matches!(action, Action::Login) && !crate::tty::stdin_is_terminal() {
        return Err(prompt_failure(PromptError::NotATerminal));
    }
    let (dir, document, transport) = crate::cli::cli_config()?;
    let session = crate::login::user_session(&document, &dir)?;
    if crate::agent::login_expired(session.expires_at, maknae_io::now_unix()?) {
        return Err(crate::agent::LOGIN_EXPIRED.into());
    }
    let vault = maknae_vault::vault_config_from_document(&document).map_err(|e| e.to_string())?;
    let (kv_mount, user_prefix) =
        crate::agent::key_location(vault.kv_mount.as_deref(), vault.user_prefix.as_deref())?;
    let username = crate::login::local_username()?;
    let forges = catalog(&document, &dir, transport, &session.token).await?;
    let place = Place {
        kv_mount,
        user_prefix,
        username: &username,
    };
    let store = Vault {
        api: &session.api,
        token: &session.token,
    };
    match action {
        Action::Login => login(&store, &place, &forges, server, || read_token(server)).await,
        Action::Logout => logout(&store, &place, &forges, server).await,
    }
}

async fn catalog(
    document: &maknae_config::Document,
    dir: &std::path::Path,
    transport: maknae_config::TransportConfig,
    token: &UserToken,
) -> Result<Vec<Forge>, String> {
    let (client, trust) = crate::cli::minted_plane(document, dir, token).await?;
    let client = Arc::new(client);
    let forges = TaskerClient::new(transport, Arc::clone(&client), trust)
        .forges()
        .await;
    if let Err(e) = client.shutdown().await {
        errln!("maknae-vault: {e}");
    }
    forges.map_err(|e| match e {
        TaskerError::Refused { .. } => "the kernel refused the tool catalog".into(),
        TaskerError::Unreachable { why, .. } => format!("the kernel could not be reached: {why}"),
        TaskerError::Protocol(why) => why,
    })
}

async fn run(action: Action, server: &str) -> ExitCode {
    let verb = match action {
        Action::Login => "login",
        Action::Logout => "logout",
    };
    match act(action, server).await {
        Ok(line) => {
            println!("{line}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            errln!("maknae forge {verb}: {e}");
            ExitCode::FAILURE
        }
    }
}

pub(crate) async fn run_login(server: &str) -> ExitCode {
    run(Action::Login, server).await
}

pub(crate) async fn run_logout(server: &str) -> ExitCode {
    run(Action::Logout, server).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_config::ForgeProvider;
    use maknae_vault::{FORGE_TOKEN_FIELD, USER_KEY_WRAP_TTL};
    use std::cell::RefCell;

    #[derive(Debug, PartialEq, Eq)]
    enum Call {
        Write {
            kv_mount: String,
            path: String,
            field: String,
            secret: String,
            wrap_ttl: Duration,
        },
        Delete {
            kv_mount: String,
            path: String,
        },
    }

    #[derive(Default)]
    struct Recorder(RefCell<Vec<Call>>);

    impl LoginStore for Recorder {
        async fn write(
            &self,
            kv_mount: &str,
            path: &str,
            field: &str,
            secret: &KvSecret,
            wrap_ttl: Duration,
        ) -> Result<(), VaultError> {
            self.0.borrow_mut().push(Call::Write {
                kv_mount: kv_mount.into(),
                path: path.into(),
                field: field.into(),
                secret: secret.expose().into(),
                wrap_ttl,
            });
            Ok(())
        }

        async fn delete(&self, kv_mount: &str, path: &str) -> Result<(), VaultError> {
            self.0.borrow_mut().push(Call::Delete {
                kv_mount: kv_mount.into(),
                path: path.into(),
            });
            Ok(())
        }
    }

    const PLACE: Place<'static> = Place {
        kv_mount: "maknae-kv",
        user_prefix: "users",
        username: "alice",
    };

    fn forge(host: &str, provider: ForgeProvider) -> Forge {
        Forge {
            host: host.into(),
            provider,
        }
    }

    fn catalog() -> Vec<Forge> {
        vec![
            forge("github.com", ForgeProvider::Github),
            forge("ghe.example:8443", ForgeProvider::Github),
            forge("gitlab.example", ForgeProvider::Gitlab),
            forge("[::1]:8443", ForgeProvider::Github),
        ]
    }

    fn typed(token: &str) -> Result<KvSecret, String> {
        KvSecret::new(Zeroizing::new(token.to_string())).map_err(|e| e.to_string())
    }

    fn block<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(f)
    }

    #[test]
    fn login_writes_wrapped_under_the_users_forge_path() {
        let store = Recorder::default();
        let line = block(login(
            &store,
            &PLACE,
            &catalog(),
            "ghe.example:8443",
            || typed("ghp_abc123"),
        ))
        .unwrap();
        let read_path = maknae_config::user_key_path(
            "users",
            "alice",
            maknae_vault::forge_token_subpath("ghe.example:8443")
                .unwrap()
                .as_str(),
        )
        .unwrap();
        assert_eq!(read_path, "users/alice/forges/ghe.example_8443");
        assert_eq!(
            store.0.into_inner(),
            vec![Call::Write {
                kv_mount: "maknae-kv".into(),
                path: read_path,
                field: FORGE_TOKEN_FIELD.into(),
                secret: "ghp_abc123".into(),
                wrap_ttl: USER_KEY_WRAP_TTL,
            }]
        );
        assert!(line.contains("ghe.example:8443"), "{line}");
        assert!(!line.contains("ghp_abc123"), "{line}");
    }

    #[test]
    fn login_refuses_a_gitlab_forge_and_an_ipv6_literal() {
        for (server, says) in [
            ("gitlab.example", "does not check reach"),
            ("[::1]:8443", "no forge login path"),
            ("ghe.example", "not a forge this host configures"),
        ] {
            let store = Recorder::default();
            let prompted = RefCell::new(false);
            let refused = block(login(&store, &PLACE, &catalog(), server, || {
                *prompted.borrow_mut() = true;
                typed("ghp_abc123")
            }))
            .unwrap_err();
            assert!(refused.contains(says), "{server}: {refused}");
            assert!(!*prompted.borrow(), "{server}: the token was asked for");
            assert!(store.0.borrow().is_empty(), "{server}: Vault was written");
        }
        let unknown = login_path(&catalog(), "ghe.example", &PLACE).unwrap_err();
        assert!(
            unknown.contains("github.com, ghe.example:8443"),
            "{unknown}"
        );
        let none = login_path(&[], "github.com", &PLACE).unwrap_err();
        assert!(none.contains("configures no forges"), "{none}");
    }

    #[test]
    fn logout_deletes_the_metadata() {
        let store = Recorder::default();
        let line = block(logout(&store, &PLACE, &catalog(), "github.com")).unwrap();
        assert_eq!(
            store.0.into_inner(),
            vec![Call::Delete {
                kv_mount: "maknae-kv".into(),
                path: "users/alice/forges/github.com".into(),
            }]
        );
        assert!(line.contains("github.com"), "{line}");
        let store = Recorder::default();
        assert!(block(logout(&store, &PLACE, &catalog(), "gitlab.example")).is_err());
        assert!(store.0.borrow().is_empty());
    }

    fn fed(line: &mut TokenLine, bytes: &[u8]) -> PasswordFeed {
        let mut last = PasswordFeed::More;
        for &b in bytes {
            last = line.feed(b);
        }
        last
    }

    #[test]
    fn the_token_buffer_is_zeroizing_and_never_grows() {
        let mut line = TokenLine::new();
        let held: &Zeroizing<Vec<u8>> = &line.buf;
        let (at, room) = (held.as_ptr(), held.capacity());
        assert!(room >= MAX_TOKEN_BYTES, "sized {room}");
        assert_eq!(fed(&mut line, &[b'a'; MAX_TOKEN_BYTES]), PasswordFeed::More);
        assert_eq!(line.feed(b'a'), PasswordFeed::TooLong);
        assert_eq!(line.buf.len(), MAX_TOKEN_BYTES);
        assert_eq!((line.buf.as_ptr(), line.buf.capacity()), (at, room));
        assert!(line.finish().is_err());

        let mut line = TokenLine::new();
        assert_eq!(
            fed(&mut line, b"xy\x15gh\x1bp_a\x7f\x7fabc\r"),
            PasswordFeed::Done
        );
        assert!(
            line.finish().is_err(),
            "an escape byte is never part of a token"
        );

        let mut line = TokenLine::new();
        assert_eq!(
            fed(&mut line, b"xy\x15ghp_aZ\x7f1-2.3\r"),
            PasswordFeed::Done
        );
        assert_eq!(line.finish().unwrap().expose(), "ghp_a1-2.3");

        let mut line = TokenLine::new();
        assert_eq!(fed(&mut line, b"ghp abc\r"), PasswordFeed::Done);
        let refused = line.finish().unwrap_err();
        assert!(!refused.contains("ghp"), "{refused}");

        assert_eq!(
            fed(&mut TokenLine::new(), b"ab\x03"),
            PasswordFeed::Interrupted
        );
        assert_eq!(fed(&mut TokenLine::new(), b"\x04"), PasswordFeed::Eof);
    }
}
