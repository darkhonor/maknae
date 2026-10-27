use crate::{SealAad, SealError};
use maknae_crypto::sealbox;
use std::fmt;
use zeroize::Zeroizing;

pub use maknae_crypto::sealbox::SealedBlob;
pub use maknae_crypto::sealbox::{EPHEMERAL_KEY_LEN, HEADER_LEN, NONCE_LEN, TAG_LEN};

pub const SEAL_VERSION: u8 = sealbox::VERSION;
pub const SPKI_P384_LEN: usize = sealbox::SPKI_LEN;
pub const SEAL_PUB_PEM_LEN: usize = sealbox::PEM_LEN;
pub const MAX_PLAINTEXT_LEN: usize = 1024;
pub const MIN_SEALED_LEN: usize = HEADER_LEN + 1 + TAG_LEN;
pub const MAX_SEALED_LEN: usize = HEADER_LEN + MAX_PLAINTEXT_LEN + TAG_LEN;

const DOMAIN: &[u8] = b"maknae-seal-v1";

#[derive(Clone, PartialEq, Eq)]
pub struct SealPublicKey(sealbox::PublicKey);

impl SealPublicKey {
    pub fn from_spki_der(der: &[u8]) -> Result<Self, SealError> {
        Ok(Self(sealbox::PublicKey::from_spki_der(der)?))
    }

    pub fn from_pem(text: &str) -> Result<Self, SealError> {
        Ok(Self(sealbox::PublicKey::from_pem(text)?))
    }

    pub fn to_pem(&self) -> String {
        self.0.to_pem()
    }

    pub fn spki_der(&self) -> &[u8] {
        self.0.spki_der()
    }

    pub(crate) fn inner(&self) -> &sealbox::PublicKey {
        &self.0
    }
}

impl fmt::Debug for SealPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SealPublicKey(P-384)")
    }
}

pub struct SealPrivateKey {
    key: sealbox::PrivateKey,
    public: SealPublicKey,
}

impl SealPrivateKey {
    pub fn generate() -> Result<Self, SealError> {
        sealbox::PrivateKey::generate()
            .map(Self::from_key)
            .map_err(SealError::from)
    }

    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, SealError> {
        sealbox::PrivateKey::from_pkcs8_der(der)
            .map(Self::from_key)
            .map_err(SealError::from)
    }

    fn from_key(key: sealbox::PrivateKey) -> Self {
        let public = SealPublicKey(key.public_key().clone());
        Self { key, public }
    }

    pub fn to_pkcs8_der(&self) -> Result<Zeroizing<Vec<u8>>, SealError> {
        self.key.to_pkcs8_der().map_err(SealError::from)
    }

    pub fn public_key(&self) -> &SealPublicKey {
        &self.public
    }

    pub(crate) fn inner(&self) -> &sealbox::PrivateKey {
        &self.key
    }
}

impl fmt::Debug for SealPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SealPrivateKey(<redacted>)")
    }
}

fn check_plaintext_len(n: usize) -> Result<(), SealError> {
    if !(1..=MAX_PLAINTEXT_LEN).contains(&n) {
        return Err(SealError::PlaintextLength);
    }
    Ok(())
}

fn check_blob_len(n: usize) -> Result<(), SealError> {
    if !(MIN_SEALED_LEN..=MAX_SEALED_LEN).contains(&n) {
        return Err(SealError::BlobLength);
    }
    Ok(())
}

pub fn seal(
    recipient: &SealPublicKey,
    aad: &SealAad,
    plaintext: &[u8],
) -> Result<SealedBlob, SealError> {
    maknae_crypto::fips::assert_fips_module()
        .map_err(SealError::from)
        .and_then(|()| check_plaintext_len(plaintext.len()))?;
    sealbox::seal(recipient.inner(), DOMAIN, aad.as_bytes(), plaintext).map_err(SealError::from)
}

pub fn open(
    recipient: &SealPrivateKey,
    aad: &SealAad,
    blob: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SealError> {
    maknae_crypto::fips::assert_fips_module()
        .map_err(SealError::from)
        .and_then(|()| check_blob_len(blob.len()))?;
    sealbox::open(recipient.inner(), DOMAIN, aad.as_bytes(), blob).map_err(SealError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SealContext;
    use std::time::{Duration, Instant};

    const TOKEN: &[u8] = b"hvs.CAESIJ-wrapping-token-sentinel-0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX";

    fn ctx() -> SealContext<'static> {
        SealContext {
            conversation: "c-1",
            provider: "openai",
            model: "gpt-5.6-luna",
            expected_path: "maknae-kv/data/maknae/users/alice/openai/personal",
            key_field: "api_key",
        }
    }

    fn aad(c: SealContext<'_>) -> SealAad {
        SealAad::new(&c).unwrap()
    }

    fn refused(r: Result<Zeroizing<Vec<u8>>, SealError>) -> SealError {
        match r {
            Ok(_) => panic!("a blob that must be refused opened"),
            Err(e) => e,
        }
    }

    const KAT_RECIPIENT_PKCS8: &str = "3081b6020100301006072a8648ce3d020106052b8104002204819e30819b0201010430111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111a16403620004386e767ea5cb716c9cd620ff7342129c892a6fccefe612140c80bff59e943468019dda16e5079b0c1d9001d23a624b6dd088d0c3826394194787403e8a7d07e5e22f7e9c0b8e80fa1faff5d28b4bb597b267f0b87023ca61fc8454bddefd2e0e";
    const KAT_BLOB: &str = "01044f2bda7fd2105f8467e21f45223ad58863ffa4c084832d9f6c64ffc47fdd519727ab53cb71f9c40de24b64acde61f02fc7dce130b612fa5dbcac94573a2354fd005d8e9caefdc5fde48304474708bbd82f77e1fd2c630bea236f6f8dccc1678e000102030405060708090a0b9e5112a45c454d89052a69d413fb8bab9027d5b1ee8f724947f1375c31bf4f0cca4de10984b9e6f2057ce1ec13c1185fb116";
    const KAT_PLAINTEXT: &[u8] = b"maknae-seal known-answer plaintext";

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn kat_recipient() -> SealPrivateKey {
        SealPrivateKey::from_pkcs8_der(&unhex(KAT_RECIPIENT_PKCS8)).unwrap()
    }

    fn flip(blob: &[u8], i: usize) -> Vec<u8> {
        let mut b = blob.to_vec();
        b[i] ^= 0x01;
        b
    }

    #[test]
    fn a_sealed_token_opens_to_itself_at_exact_sizes() {
        let key = SealPrivateKey::generate().unwrap();
        let blob = seal(key.public_key(), &aad(ctx()), TOKEN).unwrap();
        assert_eq!(blob.as_bytes().len(), HEADER_LEN + TOKEN.len() + TAG_LEN);
        assert_eq!(blob.as_bytes()[0], SEAL_VERSION);
        let opened = open(&key, &aad(ctx()), blob.as_bytes()).unwrap();
        assert!(opened.as_slice() == TOKEN);
        assert_eq!(opened.capacity(), blob.as_bytes().len() - HEADER_LEN);
        assert_eq!(
            format!("{blob:?}"),
            format!("SealedBlob(<{} bytes>)", blob.as_bytes().len())
        );
        let copy = blob.as_bytes().to_vec();
        assert_eq!(blob.into_bytes(), copy);
    }

    #[test]
    fn the_plaintext_bounds_hold_at_both_ends() {
        let key = SealPrivateKey::generate().unwrap();
        for n in [1, MAX_PLAINTEXT_LEN] {
            let pt = vec![b'x'; n];
            let blob = seal(key.public_key(), &aad(ctx()), &pt).unwrap();
            let opened = open(&key, &aad(ctx()), blob.as_bytes()).unwrap();
            assert!(opened.as_slice() == &pt[..]);
        }
        assert_eq!(
            seal(key.public_key(), &aad(ctx()), b"").unwrap_err(),
            SealError::PlaintextLength
        );
        assert_eq!(
            seal(
                key.public_key(),
                &aad(ctx()),
                &vec![b'x'; MAX_PLAINTEXT_LEN + 1]
            )
            .unwrap_err(),
            SealError::PlaintextLength
        );
    }

    #[test]
    fn two_seals_of_the_same_token_differ() {
        let key = SealPrivateKey::generate().unwrap();
        let a = seal(key.public_key(), &aad(ctx()), TOKEN).unwrap();
        let b = seal(key.public_key(), &aad(ctx()), TOKEN).unwrap();
        assert_ne!(a.as_bytes()[1..HEADER_LEN], b.as_bytes()[1..HEADER_LEN]);
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn a_known_answer_blob_from_an_independent_implementation_opens() {
        let opened = open(&kat_recipient(), &aad(ctx()), &unhex(KAT_BLOB)).unwrap();
        assert!(opened.as_slice() == KAT_PLAINTEXT);
    }

    #[test]
    fn a_blob_retargeted_to_another_request_fails_to_open() {
        let key = SealPrivateKey::generate().unwrap();
        let blob = seal(key.public_key(), &aad(ctx()), TOKEN).unwrap();
        let others = [
            SealContext {
                conversation: "c-2",
                ..ctx()
            },
            SealContext {
                provider: "anthropic",
                ..ctx()
            },
            SealContext {
                model: "gpt-5.6",
                ..ctx()
            },
            SealContext {
                expected_path: "maknae-kv/data/maknae/users/bob/openai/personal",
                ..ctx()
            },
            SealContext {
                key_field: "org",
                ..ctx()
            },
        ];
        for (i, other) in others.into_iter().enumerate() {
            assert_eq!(
                refused(open(&key, &aad(other), blob.as_bytes())),
                SealError::Open,
                "field {i}"
            );
        }
    }

    #[test]
    fn a_blob_sealed_to_another_key_fails_to_open() {
        let key = SealPrivateKey::generate().unwrap();
        let other = SealPrivateKey::generate().unwrap();
        let blob = seal(other.public_key(), &aad(ctx()), TOKEN).unwrap();
        assert_eq!(
            refused(open(&key, &aad(ctx()), blob.as_bytes())),
            SealError::Open
        );
    }

    #[test]
    fn a_key_reloaded_from_pkcs8_opens_what_was_sealed_to_it() {
        let key = SealPrivateKey::generate().unwrap();
        let blob = seal(key.public_key(), &aad(ctx()), TOKEN).unwrap();
        let reloaded = SealPrivateKey::from_pkcs8_der(&key.to_pkcs8_der().unwrap()).unwrap();
        let opened = open(&reloaded, &aad(ctx()), blob.as_bytes()).unwrap();
        assert!(opened.as_slice() == TOKEN);
    }

    #[test]
    fn tampering_with_any_field_is_refused() {
        let key = SealPrivateKey::generate().unwrap();
        let blob = seal(key.public_key(), &aad(ctx()), TOKEN).unwrap();
        let b = blob.as_bytes();
        let open_it = |bytes: &[u8]| open(&key, &aad(ctx()), bytes);
        assert_eq!(refused(open_it(&flip(b, 0))), SealError::Version);
        let mut compressed = b.to_vec();
        compressed[1] = 0x02;
        assert_eq!(refused(open_it(&compressed)), SealError::EphemeralKey);
        assert!(matches!(
            open_it(&flip(b, 40)),
            Err(SealError::EphemeralKey | SealError::Open)
        ));
        let mut off_curve = b.to_vec();
        off_curve[2..1 + EPHEMERAL_KEY_LEN].fill(0);
        assert_eq!(refused(open_it(&off_curve)), SealError::EphemeralKey);
        assert_eq!(
            refused(open_it(&flip(b, 1 + EPHEMERAL_KEY_LEN))),
            SealError::Open
        );
        assert_eq!(refused(open_it(&flip(b, HEADER_LEN - 1))), SealError::Open);
        assert_eq!(refused(open_it(&flip(b, HEADER_LEN))), SealError::Open);
        assert_eq!(refused(open_it(&flip(b, b.len() - 1))), SealError::Open);
        assert_eq!(
            refused(open_it(&flip(b, b.len() - TAG_LEN))),
            SealError::Open
        );
    }

    #[test]
    fn a_truncated_or_extended_blob_is_refused() {
        let key = SealPrivateKey::generate().unwrap();
        let blob = seal(key.public_key(), &aad(ctx()), TOKEN).unwrap();
        let b = blob.as_bytes();
        assert_eq!(
            refused(open(&key, &aad(ctx()), &b[..b.len() - 1])),
            SealError::Open
        );
        assert_eq!(
            refused(open(&key, &aad(ctx()), &b[..MIN_SEALED_LEN - 1])),
            SealError::BlobLength
        );
        let mut longer = b.to_vec();
        longer.push(0);
        assert_eq!(refused(open(&key, &aad(ctx()), &longer)), SealError::Open);
        let mut oversize = b.to_vec();
        oversize.resize(MAX_SEALED_LEN + 1, 0);
        assert_eq!(
            refused(open(&key, &aad(ctx()), &oversize)),
            SealError::BlobLength
        );
    }

    #[test]
    fn seal_and_open_measured_per_turn() {
        let key = SealPrivateKey::generate().unwrap();
        let aad = aad(ctx());
        let rounds: u32 = 200;
        let start = Instant::now();
        let blobs: Vec<SealedBlob> = (0..rounds)
            .map(|_| seal(key.public_key(), &aad, TOKEN).unwrap())
            .collect();
        let sealed = start.elapsed();
        let start = Instant::now();
        for blob in &blobs {
            assert!(open(&key, &aad, blob.as_bytes()).unwrap().as_slice() == TOKEN);
        }
        let opened = start.elapsed();
        eprintln!(
            "maknae-seal: seal {:?}/op, open {:?}/op over {rounds} rounds",
            sealed / rounds,
            opened / rounds
        );
        assert!(
            sealed + opened < Duration::from_secs(30),
            "{rounds} seal+open rounds took {:?}",
            sealed + opened
        );
    }

    const P256_PUBLIC_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwb+kKvUQ/6NXarrQo1llFsZkKq3p\nuwMJSL1oX7GpbcalqGg9o0UfaXuMQoO4n+cJ7zqWEHgkmImfZBUhkoVpHQ==\n-----END PUBLIC KEY-----\n";
    const P256_PKCS8: &str = "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420719d0b60db369ad74e03483ddc98657a5e0769c81ecd423b91d00837197c6031a14403420004c1bfa42af510ffa3576abad0a3596516c6642aade9bb030948bd685fb1a96dc6a5a8683da3451f697b8c4283b89fe709ef3a9610782498899f6415219285691d";

    #[test]
    fn the_v1_layout_is_pinned() {
        assert_eq!(
            (SEAL_VERSION, EPHEMERAL_KEY_LEN, NONCE_LEN, TAG_LEN),
            (1, 97, 12, 16)
        );
        assert_eq!(
            (HEADER_LEN, MIN_SEALED_LEN, MAX_SEALED_LEN),
            (110, 127, 1150)
        );
        assert_eq!((SPKI_P384_LEN, SEAL_PUB_PEM_LEN), (120, 215));
    }

    #[test]
    fn the_proto_sealed_key_bounds_are_the_blob_bounds() {
        assert_eq!(
            (
                maknae_proto::SEALED_KEY_MIN_BYTES,
                maknae_proto::SEALED_KEY_MAX_BYTES
            ),
            (MIN_SEALED_LEN, MAX_SEALED_LEN)
        );
    }

    #[test]
    fn the_plaintext_bound_is_one_to_1024_inclusive() {
        assert_eq!(check_plaintext_len(0), Err(SealError::PlaintextLength));
        assert_eq!(check_plaintext_len(1), Ok(()));
        assert_eq!(check_plaintext_len(MAX_PLAINTEXT_LEN), Ok(()));
        assert_eq!(
            check_plaintext_len(MAX_PLAINTEXT_LEN + 1),
            Err(SealError::PlaintextLength)
        );
    }

    #[test]
    fn a_generated_key_has_a_120_byte_p384_spki_and_a_redacted_debug() {
        let key = SealPrivateKey::generate().unwrap();
        assert_eq!(key.public_key().spki_der().len(), SPKI_P384_LEN);
        assert_eq!(format!("{key:?}"), "SealPrivateKey(<redacted>)");
        assert_eq!(format!("{:?}", key.public_key()), "SealPublicKey(P-384)");
    }

    #[test]
    fn pkcs8_round_trips_into_the_same_public_key() {
        let key = SealPrivateKey::generate().unwrap();
        let back = SealPrivateKey::from_pkcs8_der(&key.to_pkcs8_der().unwrap()).unwrap();
        assert_eq!(back.public_key(), key.public_key());
        assert_ne!(
            SealPrivateKey::generate().unwrap().public_key(),
            key.public_key()
        );
    }

    #[test]
    fn a_p256_or_garbage_private_key_is_refused() {
        for der in [unhex(P256_PKCS8), b"not a key".to_vec()] {
            assert_eq!(
                SealPrivateKey::from_pkcs8_der(&der).unwrap_err(),
                SealError::PrivateKey
            );
        }
    }

    #[test]
    fn the_public_pem_is_canonical_and_round_trips() {
        let key = SealPrivateKey::generate().unwrap();
        let text = key.public_key().to_pem();
        assert_eq!(text.len(), SEAL_PUB_PEM_LEN);
        assert!(text.starts_with("-----BEGIN PUBLIC KEY-----\n"));
        assert_eq!(&SealPublicKey::from_pem(&text).unwrap(), key.public_key());
    }

    #[test]
    fn a_non_canonical_or_foreign_public_pem_is_refused() {
        let key = SealPrivateKey::generate().unwrap();
        let canonical = key.public_key().to_pem();
        let other = SealPrivateKey::generate().unwrap().public_key().to_pem();
        let mut reflowed = canonical.replacen('\n', "", 2);
        reflowed.insert(26, '\n');
        reflowed.push('\n');
        assert_eq!(reflowed.len(), SEAL_PUB_PEM_LEN);
        for bad in [
            canonical.replace('\n', "\r\n"),
            format!("{canonical}trailing"),
            format!("{canonical}{other}"),
            canonical.replace("PUBLIC KEY", "PRIVATE KEY"),
            canonical.replace("PUBLIC KEY", "PUBLIC KEZ"),
            P256_PUBLIC_PEM.to_string(),
            reflowed,
            "x".repeat(SEAL_PUB_PEM_LEN),
            String::new(),
        ] {
            assert_eq!(
                SealPublicKey::from_pem(&bad).unwrap_err(),
                SealError::PublicKey,
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_spki_of_the_wrong_length_or_content_is_refused() {
        let key = SealPrivateKey::generate().unwrap();
        let spki = key.public_key().spki_der();
        assert_eq!(
            &SealPublicKey::from_spki_der(spki).unwrap(),
            key.public_key()
        );
        assert_eq!(
            SealPublicKey::from_spki_der(&spki[..SPKI_P384_LEN - 1]).unwrap_err(),
            SealError::PublicKey
        );
        assert_eq!(
            SealPublicKey::from_spki_der(&[0u8; SPKI_P384_LEN]).unwrap_err(),
            SealError::PublicKey
        );
    }
}
