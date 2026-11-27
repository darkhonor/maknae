//! The GitHub App JWT: the RS256 signing input, and the token once Transit has signed it.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use maknae_io::{MaknaeSecret, SecretError};
use zeroize::Zeroizing;

pub const JWT_BACKDATE_SECS: u64 = 60;
pub const JWT_LIFETIME_SECS: u64 = 540;

const HEADER: &str = r#"{"alg":"RS256","typ":"JWT"}"#;

pub fn signing_input(app_id: u64, now: u64) -> String {
    let claims = format!(
        r#"{{"iat":{},"exp":{},"iss":"{app_id}"}}"#,
        now.saturating_sub(JWT_BACKDATE_SECS),
        now.saturating_add(JWT_LIFETIME_SECS),
    );
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(HEADER),
        URL_SAFE_NO_PAD.encode(claims)
    )
}

/// The JWT is a bearer credential, so its buffer is sized once and never grows (ADR-0026).
pub fn assemble_jwt(signing_input: &str, signature: &[u8]) -> Result<MaknaeSecret, SecretError> {
    MaknaeSecret::new(jwt_text(signing_input, signature))
}

fn jwt_text(signing_input: &str, signature: &[u8]) -> Zeroizing<String> {
    let encoded = base64::encoded_len(signature.len(), false).unwrap_or(usize::MAX);
    let mut jwt = Zeroizing::new(String::with_capacity(
        signing_input
            .len()
            .saturating_add(1)
            .saturating_add(encoded),
    ));
    jwt.push_str(signing_input);
    jwt.push('.');
    URL_SAFE_NO_PAD.encode_string(signature, &mut jwt);
    jwt
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(part: &str) -> String {
        String::from_utf8(URL_SAFE_NO_PAD.decode(part).expect("base64url")).expect("utf-8")
    }

    #[test]
    fn the_signing_input_is_the_pinned_header_and_claims_for_a_fixed_clock() {
        let input = signing_input(5834363, 1_800_000_000);
        assert_eq!(
            input,
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.\
             eyJpYXQiOjE3OTk5OTk5NDAsImV4cCI6MTgwMDAwMDU0MCwiaXNzIjoiNTgzNDM2MyJ9"
        );
        let (header, claims) = input.split_once('.').expect("two parts");
        assert_eq!(decode(header), r#"{"alg":"RS256","typ":"JWT"}"#);
        assert_eq!(
            decode(claims),
            r#"{"iat":1799999940,"exp":1800000540,"iss":"5834363"}"#
        );
        let (_, early) = signing_input(1, 59)
            .split_once('.')
            .map(|(h, c)| (h.to_string(), decode(c)))
            .expect("two parts");
        assert_eq!(early, r#"{"iat":0,"exp":599,"iss":"1"}"#);
    }

    #[test]
    fn assemble_jwt_appends_base64url_signature_without_padding() {
        let signature = [0xfb, 0xff, 0xfe, 0x00, 0x3e];
        let jwt = jwt_text("aGVhZA.Y2xhaW1z", &signature);
        assert_eq!(jwt.as_str(), "aGVhZA.Y2xhaW1z.-__-AD4");
        assert_eq!(jwt.capacity(), jwt.len());
        assert_eq!(
            assemble_jwt("aGVhZA.Y2xhaW1z", &signature)
                .unwrap()
                .expose(),
            "aGVhZA.Y2xhaW1z.-__-AD4"
        );
        for n in [0usize, 1, 2, 3, 256, 512] {
            let sig = vec![0xab; n];
            let jwt = jwt_text("h.c", &sig);
            let (prefix, encoded) = jwt.rsplit_once('.').expect("three parts");
            assert_eq!(prefix, "h.c");
            assert!(!encoded.contains('='), "{n}");
            assert_eq!(URL_SAFE_NO_PAD.decode(encoded).expect("base64url"), sig);
            assert_eq!(jwt.capacity(), jwt.len(), "{n}");
        }
    }
}
