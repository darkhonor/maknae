/// `host[:port]`, answering whether the host is loopback.
pub fn host_port(authority: &str) -> Option<bool> {
    let (loopback, port) = if let Some(v6) = authority.strip_prefix('[') {
        let (h, rest) = v6.split_once(']')?;
        let addr = h.parse::<std::net::Ipv6Addr>().ok()?;
        let port = match rest.strip_prefix(':') {
            Some(p) => Some(p),
            None if rest.is_empty() => None,
            None => return None,
        };
        (addr.is_loopback(), port)
    } else {
        let (h, port) = match authority.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        };
        let ok = !h.is_empty()
            && h.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
            && !h.starts_with(['-', '.'])
            && !h.ends_with(['-', '.'])
            && !h.contains("..");
        if !ok {
            return None;
        }
        let loopback = if h.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
            h.parse::<std::net::Ipv4Addr>().ok()?.is_loopback()
        } else {
            h == "localhost"
        };
        (loopback, port)
    };
    if let Some(p) = port {
        let digits = !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit());
        if !digits || p.starts_with('0') || p.parse::<u16>().is_err() {
            return None;
        }
    }
    Some(loopback)
}

pub const SERVER_MAX_BYTES: usize = 255;

pub fn server_is_acceptable(s: &str) -> bool {
    s.len() <= SERVER_MAX_BYTES
        && !s.bytes().any(|b| b.is_ascii_uppercase())
        && host_port(s).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_port_is_unchanged_by_the_move() {
        for (h, accepted) in [
            ("github.com", true),
            ("ghe.example:8443", true),
            ("[::1]:8443", true),
            ("[::1]", true),
            ("[FE80::1]", true),
            ("10.0.0.5", true),
            ("A.B", true),
            ("x:65535", true),
            ("", false),
            ("a..b", false),
            ("-a", false),
            ("a-", false),
            (".a", false),
            ("a.", false),
            ("a:0", false),
            ("a:08", false),
            ("a:65536", false),
            ("a:+80", false),
            ("a:", false),
            (":22", false),
            ("u@a", false),
            ("a b", false),
            ("https://github.com", false),
            ("github.com/org", false),
            ("[::1", false),
            ("[::1]x", false),
            ("[]", false),
            ("[1]", false),
            ("256.256.256.256", false),
            ("1.2.3", false),
            ("127.0.0.01", false),
        ] {
            assert_eq!(host_port(h).is_some(), accepted, "{h:?}");
        }
        assert_eq!(host_port("localhost"), Some(true));
        assert_eq!(host_port("127.0.0.1:80"), Some(true));
        assert_eq!(host_port("[::1]"), Some(true));
        assert_eq!(host_port("github.com"), Some(false));
        assert_eq!(host_port("[fe80::1]"), Some(false));
    }

    #[test]
    fn a_server_is_a_lowercase_host_port_of_at_most_255_bytes() {
        for ok in [
            "github.com",
            "ghe.example:8443",
            "[::1]:8443",
            "[fe80::1]",
            "10.0.0.5:22",
        ] {
            assert!(server_is_acceptable(ok), "{ok:?}");
        }
        for bad in [
            "GitHub.com",
            "ghe.example:8443/x",
            "https://github.com",
            "u@github.com",
            "git hub.com",
            "",
            ":22",
            "a..b",
            "-a",
            "a-",
            ".a",
            "a.",
            "a:0",
            "a:08",
            "a:65536",
            "[FE80::1]",
        ] {
            assert!(!server_is_acceptable(bad), "{bad:?}");
        }
        let at_cap = format!("{}.com", "a".repeat(251));
        assert_eq!(at_cap.len(), 255);
        assert!(server_is_acceptable(&at_cap));
        let over = format!("{}.com", "a".repeat(252));
        assert_eq!(over.len(), 256);
        assert!(!server_is_acceptable(&over));
    }
}
