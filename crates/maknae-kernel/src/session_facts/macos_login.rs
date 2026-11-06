//! The macOS login fact: a human audit session, and either a utmpx login record
//! for the user or ownership of the console.

use std::io;

use super::LoginFact;

pub(crate) fn auid_is_human(token: &[u32; 8]) -> bool {
    token[0] != u32::MAX
}

/// The login fact for the peer whose audit token is `token`, bound to `uid` and `user`.
pub fn login_macos(token: &[u32; 8], uid: u32, user: Option<&str>) -> LoginFact {
    login_from(
        token,
        uid,
        user,
        maknae_io::logged_in_users,
        maknae_io::console_owner_uid,
    )
}

fn login_from(
    token: &[u32; 8],
    uid: u32,
    user: Option<&str>,
    users: impl FnOnce() -> io::Result<Vec<String>>,
    console_owner: impl FnOnce() -> io::Result<u32>,
) -> LoginFact {
    if !auid_is_human(token) {
        return LoginFact::NotUserClass;
    }
    let in_utmpx = match user {
        Some(name) => users().map(|names| names.iter().any(|n| n == name)),
        None => Ok(false),
    };
    let owns_console = console_owner().map(|owner| owner == uid);
    match (in_utmpx, owns_console) {
        (Ok(true), Ok(_) | Err(_)) | (Ok(false) | Err(_), Ok(true)) => LoginFact::Live,
        (Ok(false), Ok(false)) => LoginFact::NoSession,
        (Err(e), Ok(false)) => LoginFact::Unavailable(format!("utmpx: {e}")),
        (Ok(false), Err(e)) => LoginFact::Unavailable(format!("console: {e}")),
        (Err(a), Err(b)) => LoginFact::Unavailable(format!("utmpx: {a}; console: {b}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HUMAN: [u32; 8] = [501, 501, 20, 501, 20, 4242, 100_001, 0];

    fn background() -> [u32; 8] {
        let mut t = HUMAN;
        t[0] = u32::MAX;
        t
    }

    fn users(names: &[&str]) -> impl FnOnce() -> io::Result<Vec<String>> {
        let v: Vec<String> = names.iter().map(|s| s.to_string()).collect();
        move || Ok(v)
    }

    fn owner(uid: u32) -> impl FnOnce() -> io::Result<u32> {
        move || Ok(uid)
    }

    fn broken<T>() -> io::Result<T> {
        Err(io::Error::other("source failed"))
    }

    #[test]
    fn the_default_audit_id_is_not_human() {
        assert!(!auid_is_human(&background()));
    }

    #[test]
    fn a_set_audit_id_is_human() {
        assert!(auid_is_human(&HUMAN));
        let mut root = HUMAN;
        root[0] = 0;
        assert!(auid_is_human(&root));
    }

    #[test]
    fn a_background_process_is_not_user_class() {
        assert_eq!(
            login_from(
                &background(),
                501,
                Some("alice"),
                users(&["alice"]),
                owner(501)
            ),
            LoginFact::NotUserClass
        );
    }

    #[test]
    fn a_utmpx_record_for_the_user_is_live() {
        assert_eq!(
            login_from(
                &HUMAN,
                501,
                Some("alice"),
                users(&["bob", "alice"]),
                owner(0)
            ),
            LoginFact::Live
        );
    }

    #[test]
    fn owning_the_console_is_live() {
        assert_eq!(
            login_from(&HUMAN, 501, Some("alice"), users(&["bob"]), owner(501)),
            LoginFact::Live
        );
    }

    #[test]
    fn neither_record_nor_console_is_no_session() {
        assert_eq!(
            login_from(&HUMAN, 501, Some("alice"), users(&["bob"]), owner(0)),
            LoginFact::NoSession
        );
    }

    #[test]
    fn no_user_name_cannot_match_utmpx() {
        assert_eq!(
            login_from(&HUMAN, 501, None, users(&["alice"]), owner(0)),
            LoginFact::NoSession
        );
        assert_eq!(
            login_from(&HUMAN, 501, None, broken, owner(501)),
            LoginFact::Live
        );
    }

    #[test]
    fn a_failed_source_with_no_positive_is_unavailable() {
        let got = login_from(&HUMAN, 501, Some("alice"), broken, owner(0));
        assert!(matches!(got, LoginFact::Unavailable(_)), "{got:?}");
        let got = login_from(&HUMAN, 501, Some("alice"), users(&[]), broken);
        assert!(matches!(got, LoginFact::Unavailable(_)), "{got:?}");
        let got = login_from(&HUMAN, 501, Some("alice"), broken, broken);
        assert!(matches!(got, LoginFact::Unavailable(_)), "{got:?}");
        let got = login_from(&HUMAN, 501, None, users(&[]), broken);
        assert!(matches!(got, LoginFact::Unavailable(_)), "{got:?}");
    }

    #[test]
    fn one_positive_outweighs_a_failed_source() {
        assert_eq!(
            login_from(&HUMAN, 501, Some("alice"), broken, owner(501)),
            LoginFact::Live
        );
        assert_eq!(
            login_from(&HUMAN, 501, Some("alice"), users(&["alice"]), broken),
            LoginFact::Live
        );
    }
}
