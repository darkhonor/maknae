use crate::SealError;

pub const SEAL_PUB_PEM_LEN: usize = 215;
const PEM_TAG: &str = "PUBLIC KEY";

pub(crate) fn encode_seal_pub(spki: &[u8]) -> String {
    pem::encode_config(
        &pem::Pem::new(PEM_TAG, spki.to_vec()),
        pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
    )
}

pub(crate) fn check_length(text: &str) -> Result<(), SealError> {
    if text.len() != SEAL_PUB_PEM_LEN {
        return Err(SealError::PublicKey);
    }
    Ok(())
}

pub(crate) fn check_tag(tag: &str) -> Result<(), SealError> {
    if tag != PEM_TAG {
        return Err(SealError::PublicKey);
    }
    Ok(())
}

pub(crate) fn check_canonical(text: &str, spki: &[u8]) -> Result<(), SealError> {
    if encode_seal_pub(spki) != text {
        return Err(SealError::PublicKey);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPKI: [u8; 120] = [7u8; 120];

    #[test]
    fn the_encoding_is_215_bytes_of_lf_pem() {
        let text = encode_seal_pub(&SPKI);
        assert_eq!(text.len(), SEAL_PUB_PEM_LEN);
        assert!(text.starts_with("-----BEGIN PUBLIC KEY-----\n"));
        assert!(text.ends_with("-----END PUBLIC KEY-----\n"));
        assert!(!text.contains('\r'));
    }

    #[test]
    fn the_length_must_be_exact() {
        assert_eq!(check_length(&"x".repeat(SEAL_PUB_PEM_LEN)), Ok(()));
        for n in [0, SEAL_PUB_PEM_LEN - 1, SEAL_PUB_PEM_LEN + 1] {
            assert_eq!(
                check_length(&"x".repeat(n)),
                Err(SealError::PublicKey),
                "{n}"
            );
        }
    }

    #[test]
    fn only_the_public_key_tag_is_accepted() {
        assert_eq!(check_tag("PUBLIC KEY"), Ok(()));
        for tag in ["PUBLIC KEZ", "PRIVATE KEY", "EC PUBLIC KEY", ""] {
            assert_eq!(check_tag(tag), Err(SealError::PublicKey), "{tag:?}");
        }
    }

    #[test]
    fn only_the_byte_exact_re_encoding_is_canonical() {
        let text = encode_seal_pub(&SPKI);
        assert_eq!(check_canonical(&text, &SPKI), Ok(()));
        let mut other = SPKI;
        other[0] = 8;
        assert_eq!(check_canonical(&text, &other), Err(SealError::PublicKey));
        assert_eq!(
            check_canonical(&text.replace('\n', "\r\n"), &SPKI),
            Err(SealError::PublicKey)
        );
    }
}
