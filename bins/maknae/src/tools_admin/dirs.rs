use crate::cli::terminal_safe;
use crate::tools_admin::{Owners, Paths};
use maknae_config::{GRAMMARS_DIR, TOOLS_DROPIN_DIR};
use maknae_io::{
    open_anchor, Anchor, AnchorLock, AnchorRequired, Entry, EntryId, FileOwner, IoError, IoKind,
    Mode, StrategyPref, TargetRequired,
};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const LOCKED: &str = "another maknae tools command is running";

pub(crate) enum DirError {
    NotDone(String),
    DoneNotDurable(String),
}

pub(crate) enum WriteError {
    NotDone(String),
    DoneNotDurable(String),
}

pub(crate) trait DropinDir {
    fn publish_new(&self, name: &str, bytes: &[u8]) -> Result<bool, WriteError>;
    fn link(&self, name: &str, vendor: &Path) -> Result<bool, WriteError>;
    fn identity(&self, name: &str) -> Result<Option<EntryId>, String>;
    fn remove(&self, name: &str) -> Result<(), DirError>;
}

pub(super) struct AnchoredDir<'a> {
    pub(super) anchor: &'a Anchor,
    pub(super) owner: FileOwner,
}

fn write_error(e: IoError) -> WriteError {
    match &e {
        IoError::PublishedNotDurable { .. } => WriteError::DoneNotDurable(e.to_string()),
        _ => WriteError::NotDone(e.to_string()),
    }
}

fn dir_error(e: IoError) -> DirError {
    match &e {
        IoError::RemovedNotDurable { .. } => DirError::DoneNotDurable(e.to_string()),
        _ => DirError::NotDone(e.to_string()),
    }
}

impl DropinDir for AnchoredDir<'_> {
    fn publish_new(&self, name: &str, bytes: &[u8]) -> Result<bool, WriteError> {
        self.anchor
            .publish_owned_new(Path::new(name), None, bytes, Mode(0o640), self.owner)
            .map(|o| o.value)
            .map_err(write_error)
    }

    fn link(&self, name: &str, vendor: &Path) -> Result<bool, WriteError> {
        self.anchor
            .link_member(name, vendor)
            .map(|o| o.value)
            .map_err(write_error)
    }

    fn identity(&self, name: &str) -> Result<Option<EntryId>, String> {
        self.anchor
            .entry_identity(name.as_ref())
            .map_err(|e| e.to_string())
    }

    fn remove(&self, name: &str) -> Result<(), DirError> {
        self.anchor
            .remove_durable(Path::new(name), None)
            .map(|_| ())
            .map_err(dir_error)
    }
}

pub(super) struct Dirs {
    pub(super) config: Anchor,
    pub(super) grammars: Anchor,
    pub(super) tools: Anchor,
}

impl Dirs {
    pub(super) fn open(p: &Paths, o: &Owners) -> Result<Self, String> {
        Ok(Dirs {
            config: open(&p.config, o.dir, 0o027)?,
            grammars: open(&p.config.join(GRAMMARS_DIR), o.dir, 0o027)?,
            tools: open(&p.config.join(TOOLS_DROPIN_DIR), o.dir, 0o027)?,
        })
    }
}

pub(super) fn open(path: &Path, owner: u32, mask: u32) -> Result<Anchor, String> {
    let required = AnchorRequired {
        owner: Some(owner),
        mode_mask: Some(mask),
    };
    open_anchor(path, required, StrategyPref::Auto)
        .map_err(|e| terminal_safe(&format!("cannot use {}: {e}", path.display())))
}

pub(super) fn required(owner: u32, mask: u32) -> TargetRequired {
    TargetRequired {
        owner: Some(owner),
        mode_mask: Some(mask),
        nlink_exactly_one: false,
        regular_file: true,
        max_bytes: None,
    }
}

pub(super) fn read_text(
    anchor: &Anchor,
    rel: &Path,
    target: TargetRequired,
    shown: &Path,
) -> Result<Option<String>, String> {
    let bytes = match anchor.read(rel, None, target) {
        Ok(o) => o.value,
        Err(IoError::Io {
            kind: IoKind::NotFound,
            ..
        }) => return Ok(None),
        Err(e) => {
            return Err(terminal_safe(&format!(
                "cannot read {}: {e}",
                shown.display()
            )))
        }
    };
    std::str::from_utf8(&bytes)
        .map(|text| Some(text.to_string()))
        .map_err(|_| terminal_safe(&format!("{} is not UTF-8", shown.display())))
}

pub(super) fn yaml_stem(name: &str) -> Option<&str> {
    if name.starts_with('.') {
        None
    } else {
        name.strip_suffix(".yaml")
    }
}

pub(super) fn listing(anchor: &Anchor, path: &Path) -> Result<Vec<Entry>, String> {
    let mut entries = anchor
        .enumerate(Path::new(""), None)
        .map_err(|e| terminal_safe(&format!("cannot list {}: {e}", path.display())))?
        .value;
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(entries)
}

pub(super) fn stems(anchor: &Anchor, path: &Path) -> Result<BTreeSet<String>, String> {
    Ok(listing(anchor, path)?
        .iter()
        .filter_map(|e| yaml_stem(&e.name.to_string_lossy()).map(str::to_string))
        .collect())
}

pub(super) fn lock(tools: &Anchor) -> Result<AnchorLock, String> {
    tools.try_lock_exclusive().map_err(|e| match e {
        IoError::Locked { .. } => LOCKED.to_string(),
        e => terminal_safe(&format!("cannot lock the drop-in directory: {e}")),
    })
}

pub(super) fn dropin_path(p: &Paths, file: &str) -> PathBuf {
    p.config.join(TOOLS_DROPIN_DIR).join(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_errors_map_to_what_may_be_on_disk() {
        let path = PathBuf::from("/x");
        let kind = IoKind::Other { raw: 5 };
        let published = || IoError::PublishedNotDurable {
            path: path.clone(),
            kind: kind.clone(),
        };
        let removed = || IoError::RemovedNotDurable {
            path: path.clone(),
            kind: kind.clone(),
        };
        let other = || IoError::Io {
            kind: IoKind::NotFound,
            path: path.clone(),
        };
        assert!(matches!(
            write_error(published()),
            WriteError::DoneNotDurable(_)
        ));
        for e in [removed(), other()] {
            assert!(matches!(write_error(e), WriteError::NotDone(_)));
        }
        assert!(matches!(dir_error(removed()), DirError::DoneNotDurable(_)));
        for e in [published(), other()] {
            assert!(matches!(dir_error(e), DirError::NotDone(_)));
        }
    }
}
