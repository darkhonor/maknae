//! Kernel-signed tasks (#609). A valid signature proves a task's origin, not that it is
//! still live: the kernel's task store stays authoritative (ADR-0033).
use crate::agent_enroll::AgentId;
use crate::{Plane, PlaneIdentity, SanRule, TrustBundle, VaultError};
use maknae_crypto::plane_key::PlaneKey;
use maknae_crypto::rustls::client::danger::ServerCertVerifier;
use maknae_crypto::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use maknae_proto::{
    addendum_signing_bytes, task_signing_bytes, Ask, Bytes, SignedAddendum, SignedTask,
    TaskAddendum, TaskId, TaskObject, TaskSignature, TASK_ENVELOPE_MARGIN,
};
use std::time::Duration;
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaskSignatureError {
    AgentMismatch,
    TaskMismatch,
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
            TaskSignatureError::TaskMismatch => "the addendum names another task",
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
    Ok(SignedTask {
        signature: signature_over(identity, &msg)?,
        task,
    })
}

pub fn sign_addendum(
    identity: &PlaneIdentity,
    addendum: TaskAddendum,
) -> Result<SignedAddendum, VaultError> {
    let msg = addendum_signing_bytes(&addendum)
        .map_err(|e| VaultError::Crypto(format!("addendum signing bytes: {}", e.category())))?;
    Ok(SignedAddendum {
        signature: signature_over(identity, &msg)?,
        addendum,
    })
}

fn signature_over(identity: &PlaneIdentity, msg: &[u8]) -> Result<TaskSignature, VaultError> {
    let sig = identity.sign(msg)?;
    let (leaf, chain) = certificates(identity)?;
    Ok(TaskSignature {
        alg: identity.plane_key().as_str().into(),
        leaf: Bytes::new(leaf.into()),
        chain: chain.into_iter().map(|c| Bytes::new(c.into())).collect(),
        sig: Bytes::new(sig.into()),
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
    now: Duration,
) -> Option<X509Certificate<'a>> {
    let verifier =
        crate::tls::server_verifier(trust, SanRule::for_plane(Plane::Kernel, trust_domain)).ok()?;
    let chain: Vec<CertificateDer<'_>> = sig
        .chain
        .iter()
        .map(|c| CertificateDer::from(c.0.as_slice()))
        .collect();
    let at = UnixTime::since_unix_epoch(now);
    let name = ServerName::try_from("maknae.invalid").ok()?;
    verifier
        .verify_server_cert(
            &CertificateDer::from(sig.leaf.0.as_slice()),
            &chain,
            &name,
            &[],
            at,
        )
        .ok()?;
    X509Certificate::from_der(&sig.leaf.0).ok().map(|(_, c)| c)
}

pub fn verify_task(
    trust: &TrustBundle,
    trust_domain: &str,
    expected_agent: &AgentId,
    signed: &SignedTask,
    now: Duration,
) -> Result<(), TaskSignatureError> {
    if signed.task.agent != expected_agent.as_str() {
        return Err(TaskSignatureError::AgentMismatch);
    }
    let msg = task_signing_bytes(&signed.task, signing_bound(&signed.task))
        .map_err(|_| TaskSignatureError::Encoding)?;
    verify_signed(trust, trust_domain, &signed.signature, &msg, now)
}

pub fn verify_addendum(
    trust: &TrustBundle,
    trust_domain: &str,
    expected_task: &TaskId,
    signed: &SignedAddendum,
    now: Duration,
) -> Result<(), TaskSignatureError> {
    if signed.addendum.task_id() != expected_task {
        return Err(TaskSignatureError::TaskMismatch);
    }
    let msg = addendum_signing_bytes(&signed.addendum).map_err(|_| TaskSignatureError::Encoding)?;
    verify_signed(trust, trust_domain, &signed.signature, &msg, now)
}

fn verify_signed(
    trust: &TrustBundle,
    trust_domain: &str,
    sig: &TaskSignature,
    msg: &[u8],
    now: Duration,
) -> Result<(), TaskSignatureError> {
    let alg = PlaneKey::parse(&sig.alg).ok_or(TaskSignatureError::Algorithm)?;
    let leaf = kernel_leaf(trust, trust_domain, sig, now).ok_or(TaskSignatureError::NotKernel)?;
    if !crate::csr::spki_is(leaf.public_key(), alg) {
        return Err(TaskSignatureError::KeyMismatch);
    }
    maknae_crypto::signature::verify(
        maknae_crypto::admitted(),
        alg.into(),
        &leaf.public_key().subject_public_key.data,
        msg,
        &sig.sig.0,
    )
    .map_err(|_| TaskSignatureError::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_pki::{TestCa, TRUST_DOMAIN};
    use maknae_proto::{
        Binding, GitBinding, Labels, SecretText, TaskId, Tasker, TASK_SCHEMA, TASK_SIGNING_CONTEXT,
        TASK_VERSION,
    };

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
            bindings: vec![],
            reach: vec![],
        }
    }

    fn year(y: u64) -> Duration {
        Duration::from_secs((y - 1970) * 365 * 86_400 + 30 * 86_400)
    }

    fn now() -> Duration {
        maknae_io::now_since_epoch().unwrap()
    }

    fn verify(ca: &TestCa, expected: &str, signed: &SignedTask) -> Result<(), TaskSignatureError> {
        verify_task(&ca.trust(), TRUST_DOMAIN, &agent(expected), signed, now())
    }

    const V1_OBJECT: &str = "a8
         66 736368656d61 6b 6d616b6e61652e7461736b
         67 76657273696f6e 01
         67 7461736b5f6964 50 000102030405060708090a0b0c0d0e0f
         66 7461736b6572 a1 63 556964 19 03e8
         66 706172656e74 f6
         65 6167656e74 64 686f6269
         63 61736b a1 66 50726f6d7074 a1 66 70726f6d7074 62 6869
         66 6c6162656c73 a0";

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn binding(change: u64) -> Binding {
        Binding::Git(GitBinding {
            server: "forge.example".into(),
            base: "owner/repo".into(),
            head: None,
            change: Some(change),
        })
    }

    #[test]
    fn a_task_signed_before_bindings_existed_still_verifies() {
        let golden = hex(V1_OBJECT);
        let mut msg = TASK_SIGNING_CONTEXT.to_vec();
        msg.extend_from_slice(&golden);
        for k in PlaneKey::ALL {
            let ca = TestCa::new(k);
            let identity = ca.kernel(k, None);
            let template = sign_task(&identity, task("hobi")).unwrap();
            let signed = SignedTask {
                task: ciborium::from_reader(golden.as_slice()).unwrap(),
                signature: TaskSignature {
                    sig: Bytes::new(identity.sign(&msg).unwrap().into()),
                    ..template.signature
                },
            };
            assert!(signed.task.bindings.is_empty());
            assert_eq!(verify(&ca, "hobi", &signed), Ok(()), "{k:?}");
        }
    }

    fn addendum(task: TaskId) -> TaskAddendum {
        let reach = maknae_proto::BindingReach::Git(maknae_proto::GitReach {
            tasker: maknae_proto::SideReach::EMPTY,
            basis: maknae_proto::TaskerBasis::Token,
            agent: maknae_proto::AgentReach::NoForgeCredential,
            why: Some(maknae_proto::EmptyReason::NoForgeCredential),
        });
        TaskAddendum::new(task, 1, vec![binding(8)], vec![reach]).unwrap()
    }

    fn verify_added(
        ca: &TestCa,
        expected: &TaskId,
        signed: &SignedAddendum,
    ) -> Result<(), TaskSignatureError> {
        verify_addendum(&ca.trust(), TRUST_DOMAIN, expected, signed, now())
    }

    #[test]
    fn the_agent_refuses_an_addendum_signed_for_another_task() {
        for k in PlaneKey::ALL {
            let ca = TestCa::new(k);
            let id = ca.kernel(k, None);
            let held = task("suga").task_id;
            let signed = sign_addendum(&id, addendum(held)).unwrap();
            assert_eq!(verify_added(&ca, &held, &signed), Ok(()), "{k:?}");
            assert_eq!(
                verify_added(&ca, &TaskId([8; 16]), &signed),
                Err(TaskSignatureError::TaskMismatch),
                "{k:?}"
            );
            let other = sign_addendum(&id, addendum(TaskId([8; 16]))).unwrap();
            let forged = SignedAddendum {
                addendum: addendum(held),
                signature: other.signature,
            };
            assert_eq!(
                verify_added(&ca, &held, &forged),
                Err(TaskSignatureError::BadSignature),
                "{k:?}"
            );
        }
    }

    #[test]
    fn a_task_signature_never_verifies_an_addendum() {
        let k = PlaneKey::EcdsaP384Sha384;
        let ca = TestCa::new(k);
        let id = ca.kernel(k, None);
        let added = addendum(TaskId([9; 16]));
        let body = maknae_proto::addendum_signing_bytes(&added).unwrap();
        let body = &body[maknae_proto::TASK_ADDENDUM_SIGNING_CONTEXT.len()..];
        let mut as_task = TASK_SIGNING_CONTEXT.to_vec();
        as_task.extend_from_slice(body);
        let template = sign_addendum(&id, added.clone()).unwrap();
        let signed = SignedAddendum {
            addendum: added,
            signature: TaskSignature {
                sig: Bytes::new(id.sign(&as_task).unwrap().into()),
                ..template.signature
            },
        };
        assert_eq!(
            verify_added(&ca, &TaskId([9; 16]), &signed),
            Err(TaskSignatureError::BadSignature)
        );
    }

    #[test]
    fn a_task_with_bindings_signs_and_verifies() {
        for k in PlaneKey::ALL {
            let ca = TestCa::new(k);
            let mut t = task("suga");
            t.bindings = vec![binding(7)];
            let signed = sign_task(&ca.kernel(k, None), t).unwrap();
            assert_eq!(verify(&ca, "suga", &signed), Ok(()), "{k:?}");
        }
    }

    #[test]
    fn a_binding_changed_after_signing_does_not_verify() {
        type Tamper = fn(&mut TaskObject);
        let tampers: [(&str, Tamper); 3] = [
            ("changed", |t| t.bindings = vec![binding(8)]),
            ("removed", |t| t.bindings.clear()),
            ("added", |t| t.bindings.push(binding(9))),
        ];
        for k in PlaneKey::ALL {
            let ca = TestCa::new(k);
            let mut t = task("suga");
            t.bindings = vec![binding(7)];
            let signed = sign_task(&ca.kernel(k, None), t).unwrap();
            for (what, tamper) in tampers {
                let mut forged = signed.clone();
                tamper(&mut forged.task);
                assert_eq!(
                    verify(&ca, "suga", &forged),
                    Err(TaskSignatureError::BadSignature),
                    "{k:?}: {what}"
                );
            }
        }
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
            assert_eq!(*signed.signature.leaf.0, der[0].to_vec());
            assert_eq!(signed.signature.chain.len(), 1);
            assert_eq!(*signed.signature.chain[0].0, der[1].to_vec());
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
        assert_eq!(fa, leaf_fingerprint(&signed.signature.leaf.0));
        assert_eq!(fa, maknae_crypto::sha256(&signed.signature.leaf.0));
        assert_ne!(fa, identity_fingerprint(&b).unwrap());
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
                TaskSignatureError::TaskMismatch,
                "the addendum names another task",
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
    fn a_signed_ml_dsa_task_at_the_prompt_cap_fits_its_frame_formula() {
        use maknae_proto::{TASK_CHAIN_MAX, TASK_SIGNATURE_MAX_BYTES};
        let k = PlaneKey::MlDsa87;
        let ca = TestCa::new(k);
        let cap = maknae_config::TransportConfig::default().prompt_max_bytes;
        let mut big = task("suga");
        big.ask = Ask::Prompt {
            prompt: SecretText("p".repeat(cap).into()),
        };
        let signed = sign_task(&ca.kernel(k, None), big).unwrap();
        let s = &signed.signature;
        let intermediate = s.chain[0].0.len();
        let held = s.alg.len() + s.leaf.0.len() + s.sig.0.len() + intermediate;
        let worst = held + (TASK_CHAIN_MAX - s.chain.len()) * intermediate;
        assert!(worst <= TASK_SIGNATURE_MAX_BYTES, "{worst}");
        let mut wire = Vec::new();
        ciborium::into_writer(&signed, &mut wire).unwrap();
        assert!(
            wire.len() <= cap + TASK_ENVELOPE_MARGIN + TASK_SIGNATURE_MAX_BYTES,
            "{}",
            wire.len()
        );
        let back: SignedTask = ciborium::from_reader(wire.as_slice()).unwrap();
        assert_eq!(verify(&ca, "suga", &back), Ok(()));
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
                &spki_key(&back.signature.leaf.0),
                &decoded_bytes,
                &back.signature.sig.0,
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
