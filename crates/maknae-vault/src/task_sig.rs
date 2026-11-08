//! Kernel-signed tasks (#609, R-S). A valid signature proves a task's origin, not that it is
//! still live: the kernel's task store stays authoritative (ADR-0033).
use crate::agent_enroll::AgentId;
use crate::{Plane, PlaneIdentity, SanRule, TrustBundle, VaultError};
use maknae_crypto::plane_key::PlaneKey;
use maknae_crypto::rustls::client::danger::ServerCertVerifier;
use maknae_crypto::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use maknae_proto::{
    task_signing_bytes, Ask, SignedTask, TaskObject, TaskSignature, TASK_ENVELOPE_MARGIN,
};
use std::time::SystemTime;
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskSignatureError {
    AgentMismatch,
    Algorithm,
    NotKernel,
    KeyMismatch,
    BadSignature,
    Encoding,
}

impl std::fmt::Display for TaskSignatureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            TaskSignatureError::AgentMismatch => "the task names another agent",
            TaskSignatureError::Algorithm => "the signature names no plane key algorithm",
            TaskSignatureError::NotKernel => "the signing leaf is not a valid kernel leaf",
            TaskSignatureError::KeyMismatch => "the signing leaf's key is not the named algorithm",
            TaskSignatureError::BadSignature => "the task signature does not verify",
            TaskSignatureError::Encoding => "the task could not be encoded for verification",
        })
    }
}

impl std::error::Error for TaskSignatureError {}

fn signing_bound(task: &TaskObject) -> usize {
    match &task.ask {
        Ask::Prompt { prompt } => prompt.0.len().saturating_add(TASK_ENVELOPE_MARGIN),
    }
}

pub fn sign_task(identity: &PlaneIdentity, task: TaskObject) -> Result<SignedTask, VaultError> {
    let msg = task_signing_bytes(&task, signing_bound(&task))
        .map_err(|e| VaultError::Crypto(format!("task signing bytes: {}", e.category())))?;
    let sig = identity.sign(&msg)?;
    let (leaf, chain) = certificates(identity)?;
    Ok(SignedTask {
        task,
        signature: TaskSignature {
            alg: identity.plane_key().as_str().into(),
            leaf,
            chain,
            sig,
        },
    })
}

fn certificates(identity: &PlaneIdentity) -> Result<(Vec<u8>, Vec<Vec<u8>>), VaultError> {
    let mut certs = crate::tls::pem_chain_to_der(identity)?
        .into_iter()
        .map(|c| c.to_vec());
    let leaf = certs
        .next()
        .ok_or(VaultError::Pem("task signature: the identity has no leaf"))?;
    Ok((leaf, certs.collect()))
}

pub fn leaf_fingerprint(leaf_der: &[u8]) -> [u8; 32] {
    maknae_crypto::sha256(leaf_der)
}

/// The fingerprint of the leaf `sign_task` would put in a signature made with `identity`.
pub fn identity_fingerprint(identity: &PlaneIdentity) -> Result<[u8; 32], VaultError> {
    let (leaf, _) = certificates(identity)?;
    Ok(leaf_fingerprint(&leaf))
}

fn kernel_leaf<'a>(
    trust: &TrustBundle,
    trust_domain: &str,
    sig: &'a TaskSignature,
    now: SystemTime,
) -> Option<X509Certificate<'a>> {
    let verifier =
        crate::tls::server_verifier(trust, SanRule::for_plane(Plane::Kernel, trust_domain)).ok()?;
    let chain: Vec<CertificateDer<'_>> = sig
        .chain
        .iter()
        .map(|c| CertificateDer::from(c.as_slice()))
        .collect();
    let at = UnixTime::since_unix_epoch(now.duration_since(std::time::UNIX_EPOCH).ok()?);
    let name = ServerName::try_from("maknae.invalid").ok()?;
    verifier
        .verify_server_cert(
            &CertificateDer::from(sig.leaf.as_slice()),
            &chain,
            &name,
            &[],
            at,
        )
        .ok()?;
    X509Certificate::from_der(&sig.leaf).ok().map(|(_, c)| c)
}

pub fn verify_task(
    trust: &TrustBundle,
    trust_domain: &str,
    expected_agent: &AgentId,
    signed: &SignedTask,
    now: SystemTime,
) -> Result<(), TaskSignatureError> {
    if signed.task.agent != expected_agent.as_str() {
        return Err(TaskSignatureError::AgentMismatch);
    }
    let sig = &signed.signature;
    let alg = PlaneKey::parse(&sig.alg).ok_or(TaskSignatureError::Algorithm)?;
    let leaf = kernel_leaf(trust, trust_domain, sig, now).ok_or(TaskSignatureError::NotKernel)?;
    if !crate::csr::spki_is(leaf.public_key(), alg) {
        return Err(TaskSignatureError::KeyMismatch);
    }
    let msg = task_signing_bytes(&signed.task, signing_bound(&signed.task))
        .map_err(|_| TaskSignatureError::Encoding)?;
    maknae_crypto::signature::verify(
        maknae_crypto::admitted(),
        alg.into(),
        &leaf.public_key().subject_public_key.data,
        &msg,
        &sig.sig,
    )
    .map_err(|_| TaskSignatureError::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_pki::{TestCa, TRUST_DOMAIN};
    use maknae_proto::{Labels, SecretText, TaskId, Tasker, TASK_SCHEMA, TASK_VERSION};
    use std::time::{Duration, UNIX_EPOCH};

    const PROMPT: &str = "task-12-prompt-sentinel";

    fn agent(s: &str) -> AgentId {
        AgentId::parse(s).unwrap()
    }

    fn task(to: &str) -> TaskObject {
        TaskObject {
            schema: TASK_SCHEMA.into(),
            version: TASK_VERSION,
            task_id: TaskId([9; 16]),
            tasker: Tasker::Uid(1000),
            parent: None,
            agent: to.into(),
            ask: Ask::Prompt {
                prompt: SecretText(String::from(PROMPT).into()),
            },
            labels: Labels {},
        }
    }

    fn year(y: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs((y - 1970) * 365 * 86_400 + 30 * 86_400)
    }

    fn now() -> SystemTime {
        SystemTime::now()
    }

    fn verify(ca: &TestCa, expected: &str, signed: &SignedTask) -> Result<(), TaskSignatureError> {
        verify_task(&ca.trust(), TRUST_DOMAIN, &agent(expected), signed, now())
    }

    #[test]
    fn a_valid_task_verifies() {
        for k in PlaneKey::ALL {
            let ca = TestCa::new(k);
            let signed = sign_task(&ca.kernel(k, None), task("suga")).unwrap();
            assert_eq!(signed.signature.alg, k.as_str());
            assert_eq!(verify(&ca, "suga", &signed), Ok(()), "{k:?}");
        }
    }

    #[test]
    fn another_agents_task_fails() {
        for k in PlaneKey::ALL {
            let ca = TestCa::new(k);
            let signed = sign_task(&ca.kernel(k, None), task("suga")).unwrap();
            assert_eq!(
                verify(&ca, "hobi", &signed),
                Err(TaskSignatureError::AgentMismatch),
                "{k:?}"
            );
        }
    }

    #[test]
    fn a_tampered_field_fails() {
        type Tamper = fn(&mut TaskObject);
        let tampers: [(&str, Tamper); 5] = [
            ("prompt", |t| {
                t.ask = Ask::Prompt {
                    prompt: SecretText(String::from("task-12-forged").into()),
                }
            }),
            ("agent", |t| t.agent = "hobi".into()),
            ("tasker", |t| t.tasker = Tasker::Uid(1001)),
            ("parent", |t| t.parent = Some(TaskId([1; 16]))),
            ("task id", |t| t.task_id.0[15] ^= 1),
        ];
        for k in PlaneKey::ALL {
            let ca = TestCa::new(k);
            let signed = sign_task(&ca.kernel(k, None), task("suga")).unwrap();
            assert_eq!(verify(&ca, "suga", &signed), Ok(()));
            for (what, tamper) in tampers {
                let mut forged = signed.clone();
                tamper(&mut forged.task);
                let expected = forged.task.agent.clone();
                assert_eq!(
                    verify(&ca, &expected, &forged),
                    Err(TaskSignatureError::BadSignature),
                    "{k:?}: {what}"
                );
            }
        }
    }

    #[test]
    fn a_task_signed_by_a_non_kernel_leaf_fails() {
        for k in PlaneKey::ALL {
            let ca = TestCa::new(k);
            for leaf in [ca.cli(k), ca.agent(&agent("suga"), k)] {
                let signed = sign_task(&leaf, task("suga")).unwrap();
                assert_eq!(
                    verify(&ca, "suga", &signed),
                    Err(TaskSignatureError::NotKernel),
                    "{k:?}"
                );
            }
        }
    }

    #[test]
    fn a_task_signed_before_a_rotation_still_verifies() {
        for k in PlaneKey::ALL {
            let ca = TestCa::new(k);
            let a = ca.kernel(k, Some((2020, 2030)));
            let b = ca.kernel(k, Some((2029, 2040)));
            let before = sign_task(&a, task("suga")).unwrap();
            let after = sign_task(&b, task("suga")).unwrap();
            assert_ne!(before.signature.leaf, after.signature.leaf);
            for signed in [&before, &after] {
                assert_eq!(
                    verify_task(
                        &ca.trust(),
                        TRUST_DOMAIN,
                        &agent("suga"),
                        signed,
                        year(2029)
                    ),
                    Ok(()),
                    "{k:?}"
                );
            }
        }
    }

    #[test]
    fn a_task_whose_signing_leaf_has_expired_fails() {
        for k in PlaneKey::ALL {
            let ca = TestCa::new(k);
            let signed = sign_task(&ca.kernel(k, Some((2020, 2030))), task("suga")).unwrap();
            let at = |y| verify_task(&ca.trust(), TRUST_DOMAIN, &agent("suga"), &signed, year(y));
            assert_eq!(at(2029), Ok(()), "{k:?}");
            assert_eq!(at(2031), Err(TaskSignatureError::NotKernel), "{k:?}");
            assert_eq!(at(2019), Err(TaskSignatureError::NotKernel), "{k:?}");
        }
    }

    #[test]
    fn a_signature_from_a_foreign_ca_fails() {
        for k in PlaneKey::ALL {
            let ours = TestCa::new(k);
            let foreign = TestCa::new(k);
            let signed = sign_task(&foreign.kernel(k, None), task("suga")).unwrap();
            assert_eq!(
                verify(&ours, "suga", &signed),
                Err(TaskSignatureError::NotKernel),
                "{k:?}"
            );
            assert_eq!(verify(&foreign, "suga", &signed), Ok(()), "{k:?}");
        }
    }

    #[test]
    fn an_unknown_algorithm_fails() {
        for k in PlaneKey::ALL {
            let ca = TestCa::new(k);
            let mut signed = sign_task(&ca.kernel(k, None), task("suga")).unwrap();
            for alg in ["", "ed25519", "ML-DSA-87"] {
                signed.signature.alg = alg.into();
                assert_eq!(
                    verify(&ca, "suga", &signed),
                    Err(TaskSignatureError::Algorithm),
                    "{k:?}: {alg:?}"
                );
            }
        }
    }

    #[test]
    fn an_algorithm_that_is_not_the_leafs_key_fails() {
        for k in PlaneKey::ALL {
            let ca = TestCa::new(k);
            let mut signed = sign_task(&ca.kernel(k, None), task("suga")).unwrap();
            for other in PlaneKey::ALL.into_iter().filter(|o| *o != k) {
                signed.signature.alg = other.as_str().into();
                assert_eq!(
                    verify(&ca, "suga", &signed),
                    Err(TaskSignatureError::KeyMismatch),
                    "{k:?} named {other:?}"
                );
            }
        }
    }

    #[test]
    fn a_signature_carries_the_leaf_and_its_chain() {
        for k in PlaneKey::ALL {
            let ca = TestCa::new(k);
            let id = ca.kernel(k, None);
            let signed = sign_task(&id, task("suga")).unwrap();
            let der = crate::tls::pem_chain_to_der(&id).unwrap();
            assert_eq!(signed.signature.leaf, der[0].to_vec());
            assert_eq!(signed.signature.chain, vec![der[1].to_vec()]);
            assert_eq!(verify(&ca, "suga", &signed), Ok(()));
            let mut swapped = signed.clone();
            swapped.signature.sig = sign_task(&id, task("hobi")).unwrap().signature.sig;
            assert_eq!(
                verify(&ca, "suga", &swapped),
                Err(TaskSignatureError::BadSignature),
                "{k:?}"
            );
        }
    }

    #[test]
    fn the_identity_fingerprint_is_its_signatures_leaf_fingerprint() {
        let ca = TestCa::new(PlaneKey::EcdsaP384Sha384);
        let a = ca.kernel(PlaneKey::EcdsaP384Sha384, None);
        let b = ca.kernel(PlaneKey::EcdsaP384Sha384, None);
        let signed = sign_task(&a, task("suga")).unwrap();
        let fa = identity_fingerprint(&a).unwrap();
        assert_eq!(fa, leaf_fingerprint(&signed.signature.leaf));
        assert_eq!(fa, maknae_crypto::sha256(&signed.signature.leaf));
        assert_ne!(fa, identity_fingerprint(&b).unwrap());
    }

    #[test]
    fn a_time_before_the_epoch_fails() {
        let k = PlaneKey::EcdsaP384Sha384;
        let ca = TestCa::new(k);
        let signed = sign_task(&ca.kernel(k, None), task("suga")).unwrap();
        let before = UNIX_EPOCH - Duration::from_secs(1);
        assert_eq!(
            verify_task(&ca.trust(), TRUST_DOMAIN, &agent("suga"), &signed, before),
            Err(TaskSignatureError::NotKernel)
        );
    }

    #[test]
    fn a_task_over_the_signing_bound_is_neither_signed_nor_verified() {
        let k = PlaneKey::EcdsaP384Sha384;
        let ca = TestCa::new(k);
        let id = ca.kernel(k, None);
        let mut big = task("suga");
        big.tasker = Tasker::Remote("r".repeat(TASK_ENVELOPE_MARGIN));
        assert!(matches!(
            sign_task(&id, big.clone()),
            Err(VaultError::Crypto(_))
        ));
        let mut signed = sign_task(&id, task("suga")).unwrap();
        signed.task = big;
        assert_eq!(
            verify(&ca, "suga", &signed),
            Err(TaskSignatureError::Encoding)
        );
    }

    #[test]
    fn an_identity_with_a_malformed_leaf_signs_nothing() {
        let k = PlaneKey::EcdsaP384Sha384;
        let good = TestCa::new(k).kernel(k, None);
        let bad = PlaneIdentity::from_parts_for_test(
            k,
            "not a pem".into(),
            good.chain_pem().to_vec(),
            good.key_der().to_vec().into(),
        );
        assert!(sign_task(&bad, task("suga")).is_err());
        assert!(identity_fingerprint(&bad).is_err());
    }

    #[test]
    fn every_refusal_reads_as_its_cause() {
        let cases = [
            (
                TaskSignatureError::AgentMismatch,
                "the task names another agent",
            ),
            (
                TaskSignatureError::Algorithm,
                "the signature names no plane key algorithm",
            ),
            (
                TaskSignatureError::NotKernel,
                "the signing leaf is not a valid kernel leaf",
            ),
            (
                TaskSignatureError::KeyMismatch,
                "the signing leaf's key is not the named algorithm",
            ),
            (
                TaskSignatureError::BadSignature,
                "the task signature does not verify",
            ),
            (
                TaskSignatureError::Encoding,
                "the task could not be encoded for verification",
            ),
        ];
        for (e, text) in cases {
            assert_eq!(e.to_string(), text);
        }
    }

    #[test]
    fn the_signature_is_beside_the_object() {
        for k in PlaneKey::ALL {
            let ca = TestCa::new(k);
            let signed = sign_task(&ca.kernel(k, None), task("suga")).unwrap();
            let mut wire = Vec::new();
            ciborium::into_writer(&signed, &mut wire).unwrap();
            let value: ciborium::Value = ciborium::from_reader(wire.as_slice()).unwrap();
            let keys: Vec<&str> = value
                .as_map()
                .unwrap()
                .iter()
                .map(|(key, _)| key.as_text().unwrap())
                .collect();
            assert_eq!(keys, ["task", "signature"]);
            let back: SignedTask = ciborium::from_reader(wire.as_slice()).unwrap();
            let signed_bytes =
                task_signing_bytes(&signed.task, PROMPT.len() + TASK_ENVELOPE_MARGIN).unwrap();
            let decoded_bytes =
                task_signing_bytes(&back.task, PROMPT.len() + TASK_ENVELOPE_MARGIN).unwrap();
            assert_eq!(decoded_bytes, signed_bytes);
            maknae_crypto::signature::verify(
                maknae_crypto::admitted(),
                k.into(),
                &spki_key(&back.signature.leaf),
                &decoded_bytes,
                &back.signature.sig,
            )
            .unwrap();
            assert_eq!(verify(&ca, "suga", &back), Ok(()), "{k:?}");
        }
    }

    fn spki_key(leaf: &[u8]) -> Vec<u8> {
        use x509_parser::prelude::FromDer;
        let (_, cert) = x509_parser::certificate::X509Certificate::from_der(leaf).unwrap();
        cert.public_key().subject_public_key.data.to_vec()
    }
}
