use maknae_proto::{Observations, ReachRefusal, RepoAsk};

/// One forge API answer, as the driver received it.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HttpReply {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Whose credential the driver attaches to a request. The crate never holds one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Auth {
    Tasker,
    AppJwt,
    /// The token the last [`Step::MintMetadataRead`] minted, which the driver holds.
    Installation,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Step {
    /// `path` is rooted at the forge's API base and needs no escaping.
    Get {
        path: String,
        auth: Auth,
    },
    /// Mint, with the App JWT, an installation-wide token holding only `metadata: read`. The
    /// driver keeps the token and answers with the status and an empty body; it revokes the
    /// token itself if the exchange ends before [`Step::Revoke`].
    MintMetadataRead {
        installation: u64,
    },
    /// Revoke the minted token with itself; the driver answers with the status alone.
    Revoke,
    Done(Result<Observations, ReachRefusal>),
}

/// A sans-I/O reach exchange. The first `next` takes `None`; every later one takes the
/// reply to the last step, or `None` when no reply came. After `Done`, `next` repeats it.
pub trait Observer: Send {
    fn next(&mut self, last: Option<HttpReply>) -> Step;
    /// The most steps this observer asks for before it is `Done`.
    fn calls_max(&self) -> usize;
}

/// A forge's reach observers; only a forge that observes reach offers one.
pub trait ForgeReach: Sync {
    /// Observes what the tasker's credential reaches for each ask, resolving each change's head.
    fn tasker(&self, asks: &[RepoAsk]) -> Box<dyn Observer>;
    /// Observes what an App `installation` reaches for each ask's base and head.
    fn agent(&self, installation: u64, asks: &[RepoAsk]) -> Box<dyn Observer>;
}
