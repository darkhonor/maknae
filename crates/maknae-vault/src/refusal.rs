use maknae_crypto::CryptoError;
use maknae_msgs::MsgId;

pub fn crypto_refusal_message(e: &CryptoError) -> String {
    let id = match e {
        CryptoError::NotFips => MsgId::CryptoFipsUnavailable,
        CryptoError::PolicyDrift => MsgId::CryptoPolicyDrift,
        _ => return e.to_string(),
    };
    format!(
        "{}: {e}",
        maknae_msgs::msg(maknae_msgs::detect_locale(), id)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn catalog(id: MsgId) -> &'static str {
        maknae_msgs::msg(maknae_msgs::detect_locale(), id)
    }

    #[test]
    fn each_boot_refusal_leads_with_its_catalog_headline_and_keeps_the_detail() {
        for (e, id) in [
            (CryptoError::NotFips, MsgId::CryptoFipsUnavailable),
            (CryptoError::PolicyDrift, MsgId::CryptoPolicyDrift),
        ] {
            let got = crypto_refusal_message(&e);
            assert!(got.starts_with(catalog(id)), "{got}");
            assert!(got.ends_with(&e.to_string()), "{got}");
            assert_eq!(got, format!("{}: {e}", catalog(id)));
        }
    }

    #[test]
    fn any_other_refusal_is_its_display_alone() {
        let e = CryptoError::Random;
        assert_eq!(crypto_refusal_message(&e), e.to_string());
    }
}
