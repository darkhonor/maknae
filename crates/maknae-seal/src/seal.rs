use crate::glue::{fips_gate, lc};
use crate::wire::{
    check_plaintext_len, parse_blob, sealed_len, EPHEMERAL_KEY_LEN, HEADER_LEN, NONCE_LEN,
    SEAL_VERSION,
};
use crate::{SealAad, SealError, SealPrivateKey, SealPublicKey};
use aws_lc_rs::aead::{Aad, Nonce, RandomizedNonceKey, AES_256_GCM};
use aws_lc_rs::agreement::{
    agree, agree_ephemeral, EphemeralPrivateKey, ParsedPublicKey, UnparsedPublicKey, ECDH_P384,
};
use aws_lc_rs::hkdf::{Salt, HKDF_SHA384};
use aws_lc_rs::rand::SystemRandom;
use std::fmt;
use zeroize::Zeroizing;

const KDF_SALT: &[u8] = b"maknae-seal-v1";
const KDF_INFO: &[u8] = b"maknae-seal-v1 p384 hkdf-sha384 aes-256-gcm";
const AES_256_KEY_LEN: usize = 32;

pub struct SealedBlob(Vec<u8>);

impl SealedBlob {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl fmt::Debug for SealedBlob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SealedBlob(<{} bytes>)", self.0.len())
    }
}

fn derive_key(
    shared: &[u8],
    ephemeral: &[u8],
    recipient: &SealPublicKey,
) -> Result<RandomizedNonceKey, SealError> {
    let prk = Salt::new(HKDF_SHA384, KDF_SALT).extract(shared);
    let info = [KDF_INFO, ephemeral, recipient.spki_der()];
    let okm = lc(prk.expand(&info, &AES_256_GCM), SealError::Crypto)?;
    let mut key = Zeroizing::new([0u8; AES_256_KEY_LEN]);
    lc(okm.fill(&mut key[..]), SealError::Crypto)?;
    lc(
        RandomizedNonceKey::new(&AES_256_GCM, &key[..]),
        SealError::Crypto,
    )
}

pub fn seal(
    recipient: &SealPublicKey,
    aad: &SealAad,
    plaintext: &[u8],
) -> Result<SealedBlob, SealError> {
    fips_gate().and_then(|()| check_plaintext_len(plaintext.len()))?;
    let rng = SystemRandom::new();
    let generated = EphemeralPrivateKey::generate(&ECDH_P384, &rng);
    let ephemeral = lc(generated, SealError::Crypto)?;
    let ephemeral_public = lc(ephemeral.compute_public_key(), SealError::Crypto)?;
    let point = <&[u8; EPHEMERAL_KEY_LEN]>::try_from(ephemeral_public.as_ref());
    let ephemeral_bytes = lc(point, SealError::Crypto)?;
    let peer = UnparsedPublicKey::new(&ECDH_P384, recipient.spki_der());
    let derive = |shared: &[u8]| derive_key(shared, ephemeral_bytes, recipient);
    let agreed = agree_ephemeral(ephemeral, peer, SealError::Crypto, derive);
    let key = agreed?;
    let mut out = Zeroizing::new(Vec::with_capacity(sealed_len(plaintext.len())));
    out.push(SEAL_VERSION);
    out.extend_from_slice(ephemeral_bytes);
    out.extend_from_slice(&[0u8; NONCE_LEN]);
    out.extend_from_slice(plaintext);
    let bound = Aad::from(aad.as_bytes());
    let sealed = key.seal_in_place_separate_tag(bound, &mut out[HEADER_LEN..]);
    let (nonce, tag) = lc(sealed, SealError::Crypto)?;
    let nonce_bytes: &[u8; NONCE_LEN] = nonce.as_ref();
    out[1 + EPHEMERAL_KEY_LEN..HEADER_LEN].copy_from_slice(nonce_bytes);
    out.extend_from_slice(tag.as_ref());
    Ok(SealedBlob(std::mem::take(&mut *out)))
}

pub fn open(
    recipient: &SealPrivateKey,
    aad: &SealAad,
    blob: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SealError> {
    let parts = fips_gate().and_then(|()| parse_blob(blob))?;
    let peer = ParsedPublicKey::try_from(UnparsedPublicKey::new(&ECDH_P384, parts.ephemeral));
    let ephemeral = lc(peer, SealError::EphemeralKey)?;
    let unique = Nonce::try_assume_unique_for_key(parts.nonce);
    let nonce = lc(unique, SealError::BlobLength)?;
    let derive = |shared: &[u8]| derive_key(shared, parts.ephemeral, recipient.public_key());
    let agreed = agree(
        recipient.agreement_key(),
        ephemeral,
        SealError::EphemeralKey,
        derive,
    );
    let opener = agreed?;
    let mut buf = Zeroizing::new(Vec::with_capacity(parts.sealed.len()));
    buf.extend_from_slice(parts.sealed);
    let bound = Aad::from(aad.as_bytes());
    let opened = opener.open_in_place(nonce, bound, &mut buf[..]);
    let plaintext_len = lc(opened, SealError::Open)?.len();
    buf.truncate(plaintext_len);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SealContext, MAX_PLAINTEXT_LEN, MAX_SEALED_LEN, MIN_SEALED_LEN, TAG_LEN};
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
    const KAT_FIXED_SHARED_CT: &str = "0b97a82530c1e3b734c40e1d1bd3021ecd6c502e16d304d333ccdfdf7e0f35672a70c0815ce1d2c6c5ad3ab9c8968987c6c3";
    const KAT_PLAINTEXT: &[u8] = b"maknae-seal known-answer plaintext";
    const KAT_NONCE: [u8; NONCE_LEN] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn kat_recipient() -> SealPrivateKey {
        SealPrivateKey::from_pkcs8_der(&unhex(KAT_RECIPIENT_PKCS8)).unwrap()
    }

    fn kat_ephemeral() -> Vec<u8> {
        unhex(KAT_BLOB)[1..1 + EPHEMERAL_KEY_LEN].to_vec()
    }

    fn seal_with(key: &RandomizedNonceKey) -> ([u8; NONCE_LEN], Vec<u8>) {
        let mut buf = KAT_PLAINTEXT.to_vec();
        let aad = aad(ctx());
        let (nonce, tag) = key
            .seal_in_place_separate_tag(Aad::from(aad.as_bytes()), &mut buf[..])
            .unwrap();
        buf.extend_from_slice(tag.as_ref());
        (*nonce.as_ref(), buf)
    }

    fn open_with(
        key: &RandomizedNonceKey,
        nonce: [u8; NONCE_LEN],
        sealed: &[u8],
    ) -> Option<Vec<u8>> {
        let mut buf = sealed.to_vec();
        let nonce = Nonce::assume_unique_for_key(nonce);
        let aad = aad(ctx());
        let n = key
            .open_in_place(nonce, Aad::from(aad.as_bytes()), &mut buf[..])
            .ok()?
            .len();
        buf.truncate(n);
        Some(buf)
    }

    fn agreed_key(
        private: &aws_lc_rs::agreement::PrivateKey,
        ephemeral: &[u8],
        recipient: &SealPublicKey,
    ) -> RandomizedNonceKey {
        let peer =
            ParsedPublicKey::try_from(UnparsedPublicKey::new(&ECDH_P384, ephemeral)).unwrap();
        agree(private, peer, SealError::Crypto, |shared: &[u8]| {
            derive_key(shared, ephemeral, recipient)
        })
        .unwrap()
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
        assert_eq!(blob.as_bytes().len(), sealed_len(TOKEN.len()));
        assert_eq!(blob.0.capacity(), blob.as_bytes().len());
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
    fn the_derived_key_matches_a_known_answer_for_a_fixed_shared_secret() {
        let recipient = kat_recipient();
        let key = derive_key(&[0x33; 48], &kat_ephemeral(), recipient.public_key()).unwrap();
        let ct = unhex(KAT_FIXED_SHARED_CT);
        assert_eq!(
            open_with(&key, KAT_NONCE, &ct).as_deref(),
            Some(KAT_PLAINTEXT)
        );
    }

    #[test]
    fn a_different_shared_secret_with_the_same_public_inputs_derives_a_different_key() {
        let recipient = kat_recipient();
        let ephemeral = kat_ephemeral();
        let derive =
            |shared: &[u8]| derive_key(shared, &ephemeral, recipient.public_key()).unwrap();
        let (nonce, ct) = seal_with(&derive(&[0x33; 48]));
        assert_eq!(
            open_with(&derive(&[0x33; 48]), nonce, &ct).as_deref(),
            Some(KAT_PLAINTEXT)
        );
        for other in [[0x34u8; 48], [0u8; 48]] {
            assert_eq!(open_with(&derive(&other), nonce, &ct), None);
        }
    }

    #[test]
    fn a_key_agreed_by_another_recipient_private_key_does_not_open() {
        let recipient = SealPrivateKey::generate().unwrap();
        let intruder = SealPrivateKey::generate().unwrap();
        let ephemeral_key = aws_lc_rs::agreement::PrivateKey::generate(&ECDH_P384).unwrap();
        let point = ephemeral_key.compute_public_key().unwrap();
        let ephemeral = point.as_ref();
        let right = agreed_key(recipient.agreement_key(), ephemeral, recipient.public_key());
        let wrong = agreed_key(intruder.agreement_key(), ephemeral, recipient.public_key());
        let (nonce, ct) = seal_with(&right);
        assert_eq!(
            open_with(&right, nonce, &ct).as_deref(),
            Some(KAT_PLAINTEXT)
        );
        assert_eq!(open_with(&wrong, nonce, &ct), None);
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
}
