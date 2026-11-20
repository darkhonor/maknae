//! Rotate-new-first for one AppRole SecretID in custody: the new SecretID is
//! recorded and sealed before any earlier one is destroyed.
use super::agent::{dedup, AgentState};
use super::EnrollError;
use zeroize::Zeroizing;

pub(crate) trait SecretSlot {
    type Sealed;
    async fn mint(&self) -> Result<(Zeroizing<String>, String), EnrollError>;
    fn write_state(&self, state: &AgentState) -> Result<(), EnrollError>;
    async fn seal(&self, secret: &Zeroizing<String>) -> Result<Self::Sealed, EnrollError>;
    async fn destroy(&self, accessor: &str) -> Result<(), EnrollError>;
    fn orphaned(&self, accessor: String, cause: EnrollError, recorded: bool) -> EnrollError;
}

/// On a failure after the mint, the new accessor is destroyed, or named as orphaned.
pub(crate) async fn mint_and_seal<S: SecretSlot>(
    slot: &S,
    base: &AgentState,
) -> Result<(String, S::Sealed), EnrollError> {
    let (secret, acc) = slot.mint().await?;
    let mut pending = base.clone();
    pending.pending.push(acc.clone());
    if let Err(e) = slot.write_state(&pending) {
        drop(secret);
        return Err(match slot.destroy(&acc).await {
            Ok(()) => e,
            Err(_) => slot.orphaned(acc, e, false),
        });
    }
    let sealed = slot.seal(&secret).await;
    drop(secret);
    match sealed {
        Ok(s) => Ok((acc, s)),
        Err(e) => Err(match slot.destroy(&acc).await {
            Ok(()) => {
                let _ = slot.write_state(base);
                e
            }
            Err(_) => slot.orphaned(acc, e, true),
        }),
    }
}

pub(crate) fn retiring(base: &AgentState, listed: &[String], new: &str) -> Vec<String> {
    dedup(
        base.live
            .iter()
            .chain(&base.pending)
            .chain(&base.retiring)
            .chain(listed),
    )
    .into_iter()
    .filter(|a| a != new)
    .collect()
}

/// Destroys each accessor in `live.retiring` and records the ones that failed.
pub(crate) async fn retire<S: SecretSlot>(
    slot: &S,
    live: AgentState,
) -> Result<(AgentState, Vec<String>), EnrollError> {
    let mut failures = Vec::new();
    for a in &live.retiring {
        if slot.destroy(a).await.is_err() {
            failures.push(a.clone());
        }
    }
    let done = AgentState {
        retiring: failures.clone(),
        ..live
    };
    slot.write_state(&done)?;
    Ok((done, failures))
}
