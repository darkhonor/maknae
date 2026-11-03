//! Where each turn's provider key comes from. The host decides: a person's
//! session reads their own wrapped key under their login (ADR-0028); a host
//! with no human login supplies its own. The loop never knows which.
use std::future::Future;

pub trait KeySupply: Send {
    fn choice(
        &mut self,
        conversation: &str,
        now: u64,
    ) -> impl Future<Output = Result<maknae_proto::ProviderChoice, String>> + Send;
}
