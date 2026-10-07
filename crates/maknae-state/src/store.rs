use crate::anchor::{assess, AnchorState, BootAction, Checkpoint, Refusal, StoreFacts};
use crate::envelope::{ciphertext_digest, open, seal, EnvelopeError, WrappingKey};
use maknae_graph::format;
use maknae_graph::graph::{Graph, GraphBuilder};
use maknae_graph::kernel::SCHEMA;
use maknae_graph::record::GraphSpace;
use maknae_graph::schema::CompiledSet;
use maknae_io::{
    open_anchor, Anchor, AnchorRequired, IoError, IoKind, Mode, StrategyPref, TargetRequired,
    Zeroizing,
};
use std::fmt;
use std::future::Future;
use std::path::Path;

pub use maknae_config::state::{MARKER_FILE, STATE_DIR, STORE_FILE};

pub const REJECTED_PREFIX: &str = "kernel.graph.rejected.";
pub const MAX_STORE_BYTES: u64 = 64 << 20;
pub const MARKER_MAX_BYTES: u64 = 4096;
pub const ANCHOR_SEEDED: &str = "seeded";
pub const ANCHOR_RESEEDED: &str = "reseeded";

const STORE_MODE: Mode = Mode(0o600);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    Io(String),
    Envelope(EnvelopeError),
    Format(String),
    Refused(Refusal),
    Audit(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(cause) => write!(f, "graph store I/O failed: {cause}"),
            Self::Envelope(e) => write!(f, "{e}"),
            Self::Format(cause) => write!(f, "graph store does not decode: {cause}"),
            Self::Refused(r) => write!(f, "{r}"),
            Self::Audit(cause) => write!(f, "graph store audit failed: {cause}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<EnvelopeError> for StoreError {
    fn from(e: EnvelopeError) -> Self {
        Self::Envelope(e)
    }
}

impl From<IoError> for StoreError {
    fn from(e: IoError) -> Self {
        Self::Io(e.to_string())
    }
}

#[derive(Debug)]
pub struct StateDir {
    anchor: Anchor,
    owner: u32,
    marker_owner: u32,
}

impl StateDir {
    pub fn open(path: &Path, owner: u32) -> Result<StateDir, StoreError> {
        Self::open_with_marker_owner(path, owner, 0)
    }

    /// Test seam: lets an unprivileged test play the marker's owner; production passes uid 0.
    #[doc(hidden)]
    pub fn open_with_marker_owner(
        path: &Path,
        owner: u32,
        marker_owner: u32,
    ) -> Result<StateDir, StoreError> {
        let anchor = open_anchor(
            path,
            AnchorRequired {
                owner: Some(owner),
                mode_mask: Some(0o077),
            },
            StrategyPref::Auto,
        )?;
        Ok(StateDir {
            anchor,
            owner,
            marker_owner,
        })
    }

    fn reseed_authorized(&self) -> bool {
        let marker = TargetRequired {
            owner: Some(self.marker_owner),
            mode_mask: Some(0o022),
            nlink_exactly_one: true,
            regular_file: true,
            max_bytes: Some(MARKER_MAX_BYTES),
        };
        self.anchor
            .read(Path::new(MARKER_FILE), None, marker)
            .is_ok()
    }

    fn read_store(&self) -> Result<Option<Zeroizing<Vec<u8>>>, IoError> {
        let store = TargetRequired {
            owner: Some(self.owner),
            mode_mask: Some(0o077),
            nlink_exactly_one: true,
            regular_file: true,
            max_bytes: Some(MAX_STORE_BYTES),
        };
        match self.anchor.read(Path::new(STORE_FILE), None, store) {
            Ok(outcome) => Ok(Some(outcome.value)),
            Err(IoError::Io {
                kind: IoKind::NotFound,
                ..
            }) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn publish(&self, name: &str, bytes: &[u8]) -> Result<(), StoreError> {
        self.anchor
            .publish(Path::new(name), None, bytes, STORE_MODE)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootOutcome {
    Seeded {
        authorized: bool,
        rejected: Option<String>,
    },
    Loaded(AnchorState),
}

#[derive(Debug)]
pub struct BootReport {
    pub revision: u64,
    pub digest: [u8; 32],
    pub outcome: BootOutcome,
    pub graph: Graph,
}

pub trait BootAudit {
    fn intent_seed(
        &mut self,
        revision: u64,
        authorized: bool,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
    fn checkpoint(
        &mut self,
        revision: u64,
        digest: [u8; 32],
        anchor: &str,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
}

fn decode_store(file: &[u8], key: &WrappingKey) -> Result<(Graph, StoreFacts), StoreError> {
    let plain = open(file, key)?;
    let graph = format::decode(&plain, GraphSpace::Kernel, &SCHEMA, &CompiledSet::default())
        .map_err(|e| StoreError::Format(e.to_string()))?;
    let facts = StoreFacts {
        revision: graph.revision(),
        digest: ciphertext_digest(file),
    };
    Ok((graph, facts))
}

pub async fn boot(
    dir: &StateDir,
    key: &WrappingKey,
    checkpoint: Option<Checkpoint>,
    audit: &mut impl BootAudit,
    now_unix: u64,
) -> Result<BootReport, StoreError> {
    let authorized = dir.reseed_authorized();
    let mut loaded = None;
    let prior = match dir.read_store() {
        Ok(None) => Prior::Absent,
        Ok(Some(file)) => {
            match decode_store(&file, key) {
                Ok(decoded) => loaded = Some(decoded),
                Err(e) if !authorized => return Err(e),
                Err(_) => {}
            }
            Prior::Readable(file)
        }
        Err(e) if !authorized => return Err(e.into()),
        Err(e) => Prior::Unreadable(format!("not preserved: {e}")),
    };

    match (
        assess(loaded.as_ref().map(|(_, f)| *f), checkpoint, authorized),
        loaded,
    ) {
        (BootAction::Refuse(r), _) => Err(StoreError::Refused(r)),
        (BootAction::Load(state), Some((graph, facts))) => {
            audit
                .checkpoint(facts.revision, facts.digest, state.as_str())
                .await?;
            Ok(BootReport {
                revision: facts.revision,
                digest: facts.digest,
                outcome: BootOutcome::Loaded(state),
                graph,
            })
        }
        (BootAction::Load(_), None) => Err(StoreError::Format(
            "assessed a store that was never decoded".into(),
        )),
        (BootAction::SeedFirstBoot, _) => {
            seed(dir, key, audit, 1, false, Prior::Absent, now_unix).await
        }
        (BootAction::SeedAuthorized { revision }, _) => {
            seed(dir, key, audit, revision, true, prior, now_unix).await
        }
    }
}

enum Prior {
    Absent,
    Readable(Zeroizing<Vec<u8>>),
    Unreadable(String),
}

async fn seed(
    dir: &StateDir,
    key: &WrappingKey,
    audit: &mut impl BootAudit,
    revision: u64,
    authorized: bool,
    prior: Prior,
    now_unix: u64,
) -> Result<BootReport, StoreError> {
    audit.intent_seed(revision, authorized).await?;
    let rejected = match prior {
        Prior::Absent => None,
        Prior::Readable(bytes) => {
            let name = format!("{REJECTED_PREFIX}{now_unix}");
            dir.publish(&name, &bytes)?;
            Some(name)
        }
        Prior::Unreadable(cause) => Some(cause),
    };
    let graph = GraphBuilder::new(GraphSpace::Kernel, revision)
        .build(&SCHEMA, &CompiledSet::default())
        .map_err(|e| StoreError::Format(e.to_string()))?;
    let file = seal(&format::encode(&graph), key)?;
    dir.publish(STORE_FILE, &file)?;
    if authorized {
        dir.anchor.remove(Path::new(MARKER_FILE), None)?;
    }
    let digest = ciphertext_digest(&file);
    let anchor = if authorized {
        ANCHOR_RESEEDED
    } else {
        ANCHOR_SEEDED
    };
    audit.checkpoint(revision, digest, anchor).await?;
    Ok(BootReport {
        revision,
        digest,
        outcome: BootOutcome::Seeded {
            authorized,
            rejected,
        },
        graph,
    })
}
