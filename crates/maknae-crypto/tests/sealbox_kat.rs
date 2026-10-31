//! A blob sealed before the crypto-profile swap still opens (#589).
use maknae_crypto::sealbox::{open, PrivateKey};

const DOMAIN: &[u8] = b"maknae-seal-v1";
const KAT_RECIPIENT_PKCS8: &str = "3081b6020100301006072a8648ce3d020106052b8104002204819e30819b0201010430111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111a16403620004386e767ea5cb716c9cd620ff7342129c892a6fccefe612140c80bff59e943468019dda16e5079b0c1d9001d23a624b6dd088d0c3826394194787403e8a7d07e5e22f7e9c0b8e80fa1faff5d28b4bb597b267f0b87023ca61fc8454bddefd2e0e";
const KAT_BLOB: &str = "01044f2bda7fd2105f8467e21f45223ad58863ffa4c084832d9f6c64ffc47fdd519727ab53cb71f9c40de24b64acde61f02fc7dce130b612fa5dbcac94573a2354fd005d8e9caefdc5fde48304474708bbd82f77e1fd2c630bea236f6f8dccc1678e000102030405060708090a0b9e5112a45c454d89052a69d413fb8bab9027d5b1ee8f724947f1375c31bf4f0cca4de10984b9e6f2057ce1ec13c1185fb116";
const KAT_PLAINTEXT: &[u8] = b"maknae-seal known-answer plaintext";

fn kat_aad() -> Vec<u8> {
    let mut out = b"maknae-seal-aad-v1".to_vec();
    for field in [
        "c-1",
        "openai",
        "gpt-5.6-luna",
        "maknae-kv/data/maknae/users/alice/openai/personal",
        "api_key",
    ] {
        out.extend_from_slice(&(field.len() as u16).to_be_bytes());
        out.extend_from_slice(field.as_bytes());
    }
    out
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn a_blob_sealed_before_the_swap_opens() {
    let key = PrivateKey::from_pkcs8_der(&unhex(KAT_RECIPIENT_PKCS8)).unwrap();
    let opened = open(&key, DOMAIN, &kat_aad(), &unhex(KAT_BLOB)).unwrap();
    assert!(opened.as_slice() == KAT_PLAINTEXT);
}

#[test]
fn the_same_blob_does_not_open_under_another_domain() {
    let key = PrivateKey::from_pkcs8_der(&unhex(KAT_RECIPIENT_PKCS8)).unwrap();
    assert!(open(&key, b"maknae-seal-v2", &kat_aad(), &unhex(KAT_BLOB)).is_err());
}
