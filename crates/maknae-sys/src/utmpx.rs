use std::io;
use std::sync::{Mutex, PoisonError};

static UTMPX: Mutex<()> = Mutex::new(());

/// The `ut_user` of every `USER_PROCESS` record in the login records. A name that is
/// not UTF-8 is skipped.
#[allow(unsafe_code)]
pub fn utmpx_user_processes() -> io::Result<Vec<String>> {
    let _serialized = UTMPX.lock().unwrap_or_else(PoisonError::into_inner);
    // SAFETY: takes no arguments and only rewinds libc's process-wide utmpx cursor,
    // which `UTMPX` serializes within this process.
    unsafe { libc::setutxent() };
    let mut users = Vec::new();
    loop {
        // SAFETY: takes no arguments; the cursor it advances is serialized by `UTMPX`.
        let entry = unsafe { libc::getutxent() };
        if entry.is_null() {
            break;
        }
        // SAFETY: `entry` is non-null and points to libc's static `utmpx` record,
        // valid until the next utmpx call, which `UTMPX` holds off. `read` copies it
        // out, so nothing refers to libc's buffer after this line.
        let record = unsafe { entry.read() };
        if record.ut_type == libc::USER_PROCESS {
            if let Some(user) = user_name(&record.ut_user) {
                users.push(user);
            }
        }
    }
    // SAFETY: takes no arguments and closes libc's utmpx handle under `UTMPX`.
    unsafe { libc::endutxent() };
    Ok(users)
}

fn user_name(field: &[libc::c_char]) -> Option<String> {
    let bytes: Vec<u8> = field
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect();
    String::from_utf8(bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listing_returns_ok() {
        assert!(utmpx_user_processes().is_ok());
    }

    fn field(bytes: &[u8]) -> [libc::c_char; 8] {
        let mut f = [0 as libc::c_char; 8];
        for (slot, b) in f.iter_mut().zip(bytes) {
            *slot = *b as libc::c_char;
        }
        f
    }

    #[test]
    fn a_name_ends_at_the_first_nul() {
        assert_eq!(user_name(&field(b"op\0junk")), Some("op".to_owned()));
    }

    #[test]
    fn a_name_that_fills_the_field_is_whole() {
        assert_eq!(user_name(&field(b"abcdefgh")), Some("abcdefgh".to_owned()));
    }

    #[test]
    fn a_non_utf8_name_is_skipped() {
        assert_eq!(user_name(&field(b"o\xffp")), None);
    }
}
