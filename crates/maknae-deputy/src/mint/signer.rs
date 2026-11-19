//! The seam through which the App JWT's signing input is signed by Vault Transit.

use std::future::Future;
use zeroize::Zeroizing;

/// The signature could not be had. Opaque: no Vault detail reaches the frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignError;

pub trait Signer {
    fn sign(
        &self,
        mount: &str,
        key: &str,
        input: &[u8],
    ) -> impl Future<Output = Result<Zeroizing<Vec<u8>>, SignError>> + Send;
}

#[cfg(any(test, feature = "test-support"))]
pub struct FakeSigner {
    signature: Option<Vec<u8>>,
    calls: std::sync::Mutex<Vec<FakeSignCall>>,
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeSignCall {
    pub mount: String,
    pub key: String,
    pub input: Vec<u8>,
}

#[cfg(any(test, feature = "test-support"))]
impl FakeSigner {
    pub fn signing(signature: &[u8]) -> Self {
        Self {
            signature: Some(signature.to_vec()),
            calls: std::sync::Mutex::new(Vec::new()),
        }
    }

    pub fn failing() -> Self {
        Self {
            signature: None,
            calls: std::sync::Mutex::new(Vec::new()),
        }
    }

    pub fn calls(&self) -> Vec<FakeSignCall> {
        self.calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

#[cfg(any(test, feature = "test-support"))]
impl Signer for FakeSigner {
    fn sign(
        &self,
        mount: &str,
        key: &str,
        input: &[u8],
    ) -> impl Future<Output = Result<Zeroizing<Vec<u8>>, SignError>> + Send {
        self.calls
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(FakeSignCall {
                mount: mount.to_owned(),
                key: key.to_owned(),
                input: input.to_vec(),
            });
        let out = match &self.signature {
            Some(sig) => Ok(Zeroizing::new(sig.clone())),
            None => Err(SignError),
        };
        std::future::ready(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_fake_records_each_call_and_answers_as_built() {
        let ok = FakeSigner::signing(&[1, 2, 3]);
        assert_eq!(
            ok.sign("transit", "deploy", b"in")
                .await
                .unwrap()
                .as_slice(),
            &[1, 2, 3]
        );
        assert_eq!(
            ok.calls(),
            vec![FakeSignCall {
                mount: "transit".into(),
                key: "deploy".into(),
                input: b"in".to_vec(),
            }]
        );
        let bad = FakeSigner::failing();
        assert_eq!(bad.sign("m", "k", b"x").await, Err(SignError));
        assert_eq!(bad.calls().len(), 1);
    }
}
