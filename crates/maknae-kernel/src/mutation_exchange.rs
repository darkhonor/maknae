//! Pure validation of client-reported mutation progress; no authorization or I/O.
use maknae_proto::{
    MutationAck, MutationId, MutationLimits, MutationReport, MutationScope, ReportedEffect,
    ReportedFinish, MAX_MUTATION_BATCH, MAX_MUTATION_DEPTH, MAX_MUTATION_EFFECTS,
    MAX_MUTATION_PATH_BYTES,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportError {
    WrongId,
    WrongIndex,
    OutOfScope,
    WrongEffect,
    Limit,
    Terminal,
    MalformedPath,
    Outstanding,
    ForeignPending,
    /// Duplicate effects, impossible effect ordering, or an unsupported success claim.
    InconsistentClaim,
}

/// Opaque, single-use transition. It is bound to one live exchange even when
/// another connection reuses the same wire correlation ID.
#[derive(Debug)]
pub struct PendingReport {
    owner: std::sync::Arc<()>,
    next_index: u32,
    terminal: bool,
    paths: Vec<String>,
}

/// Checks report shape, correlation and internal claim consistency. The transport owns
/// deadlines, frame limits and durable audit; it must append the exact validated
/// report durably before calling `acknowledge`. No method attests client effects.
#[derive(Debug)]
pub struct MutationExchange {
    id: MutationId,
    scope: MutationScope,
    limits: MutationLimits,
    owner: std::sync::Arc<()>,
    next_index: u32,
    outstanding: bool,
    terminal: bool,
    seen: std::collections::BTreeSet<String>,
}

impl MutationExchange {
    pub fn begin(
        id: MutationId,
        scope: MutationScope,
        limits: MutationLimits,
    ) -> Result<Self, ReportError> {
        if limits.max_effects == 0
            || limits.max_effects > MAX_MUTATION_EFFECTS
            || limits.max_depth > MAX_MUTATION_DEPTH
            || limits.deadline_ms == 0
        {
            return Err(ReportError::Limit);
        }
        match &scope {
            MutationScope::Exact { path, .. } => {
                canonical_path(path)?;
            }
            MutationScope::RecursiveDelete { root } => {
                canonical_path(root)?;
            }
            MutationScope::Directories { paths } => {
                if paths.is_empty() {
                    return Err(ReportError::OutOfScope);
                }
                if paths.len() > usize::from(limits.max_depth) {
                    return Err(ReportError::Limit);
                }
                for path in paths {
                    canonical_path(path)?;
                }
                for pair in paths.windows(2) {
                    let suffix = if pair[0] == "/" {
                        &pair[1][1..]
                    } else {
                        pair[1]
                            .strip_prefix(&pair[0])
                            .and_then(|s| s.strip_prefix('/'))
                            .ok_or(ReportError::OutOfScope)?
                    };
                    if suffix.is_empty() || suffix.contains('/') {
                        return Err(ReportError::OutOfScope);
                    }
                }
            }
        }
        Ok(Self {
            id,
            scope,
            limits,
            owner: std::sync::Arc::new(()),
            next_index: 0,
            outstanding: false,
            terminal: false,
            seen: std::collections::BTreeSet::new(),
        })
    }

    /// Reserve a transition without advancing acknowledged progress. Dropping a
    /// pending transition leaves the exchange blocked; the connection must close
    /// after audit failure rather than retrying an uncertain report.
    pub fn validate_report(
        &mut self,
        report: &MutationReport,
    ) -> Result<PendingReport, ReportError> {
        if self.terminal {
            return Err(ReportError::Terminal);
        }
        if self.outstanding {
            return Err(ReportError::Outstanding);
        }
        let (id, index) = match report {
            MutationReport::Batch {
                id, first_index, ..
            } => (id, first_index),
            MutationReport::Finished { id, next_index, .. } => (id, next_index),
        };
        if *id != self.id {
            return Err(ReportError::WrongId);
        }
        if *index != self.next_index {
            return Err(ReportError::WrongIndex);
        }
        let mut paths = Vec::new();
        let (next_index, terminal) = match report {
            MutationReport::Batch { effects, .. } => {
                if effects.is_empty() || effects.len() > MAX_MUTATION_BATCH {
                    return Err(ReportError::Limit);
                }
                let count = u32::try_from(effects.len()).map_err(|_| ReportError::Limit)?;
                let next = self
                    .next_index
                    .checked_add(count)
                    .ok_or(ReportError::Limit)?;
                if next > self.limits.max_effects {
                    return Err(ReportError::Limit);
                }
                for entry in effects {
                    self.validate_path(&entry.path)?;
                    let expected = match &self.scope {
                        MutationScope::Exact { effect, .. } => *effect,
                        MutationScope::RecursiveDelete { .. } => ReportedEffect::DeletedEntry,
                        MutationScope::Directories { .. } => ReportedEffect::CreatedDirectory,
                    };
                    if entry.effect != expected {
                        return Err(ReportError::WrongEffect);
                    }
                }
                if let MutationScope::RecursiveDelete { root } = &self.scope {
                    if self.seen.contains(root) {
                        return Err(ReportError::InconsistentClaim);
                    }
                    if effects
                        .iter()
                        .take(effects.len() - 1)
                        .any(|entry| entry.path == *root)
                    {
                        return Err(ReportError::InconsistentClaim);
                    }
                }
                // Uniqueness also caps Exact scopes at their one permitted path.
                for entry in effects {
                    if self.seen.contains(&entry.path) || paths.contains(&entry.path) {
                        return Err(ReportError::InconsistentClaim);
                    }
                    paths.push(entry.path.clone());
                }
                (next, false)
            }
            MutationReport::Finished {
                stopped_at,
                outcome,
                ..
            } => {
                if let Some(path) = stopped_at {
                    self.validate_path(path)?;
                }
                if *outcome == ReportedFinish::Success {
                    let consistent = match &self.scope {
                        MutationScope::Exact { .. } => self.next_index == 1,
                        MutationScope::RecursiveDelete { root } => self.seen.contains(root),
                        MutationScope::Directories { .. } => true,
                    };
                    if !consistent {
                        return Err(ReportError::InconsistentClaim);
                    }
                }
                (self.next_index, true)
            }
        };
        self.outstanding = true;
        Ok(PendingReport {
            owner: self.owner.clone(),
            next_index,
            terminal,
            paths,
        })
    }

    /// Commit only after the caller's durable audit append succeeds.
    pub fn acknowledge(&mut self, pending: PendingReport) -> Result<MutationAck, ReportError> {
        if !std::sync::Arc::ptr_eq(&self.owner, &pending.owner) {
            return Err(ReportError::ForeignPending);
        }
        self.seen.extend(pending.paths);
        self.next_index = pending.next_index;
        self.terminal = pending.terminal;
        self.outstanding = false;
        Ok(MutationAck {
            id: self.id,
            next_index: self.next_index,
        })
    }

    fn validate_path(&self, path: &str) -> Result<(), ReportError> {
        canonical_path(path)?;
        match &self.scope {
            MutationScope::Exact { path: expected, .. } => {
                if path != expected {
                    return Err(ReportError::OutOfScope);
                }
            }
            MutationScope::RecursiveDelete { root } => {
                let suffix = if path == root {
                    ""
                } else if root == "/" {
                    &path[1..]
                } else {
                    path.strip_prefix(root)
                        .and_then(|s| s.strip_prefix('/'))
                        .ok_or(ReportError::OutOfScope)?
                };
                let relative_depth = if suffix.is_empty() {
                    0
                } else {
                    suffix.split('/').count()
                };
                if relative_depth > usize::from(self.limits.max_depth) {
                    return Err(ReportError::Limit);
                }
            }
            MutationScope::Directories { paths } => {
                if !paths.iter().any(|allowed| allowed == path) {
                    return Err(ReportError::OutOfScope);
                }
            }
        }
        Ok(())
    }
}

/// Validate before splitting: reject ambiguous byte spellings rather than
/// letting `Path::components` silently normalize duplicate slashes or dots.
fn canonical_path(path: &str) -> Result<(), ReportError> {
    if path.len() > MAX_MUTATION_PATH_BYTES {
        return Err(ReportError::Limit);
    }
    if !path.starts_with('/') || path.as_bytes().contains(&0) {
        return Err(ReportError::MalformedPath);
    }
    if path == "/" {
        return Ok(());
    }
    for component in path[1..].split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(ReportError::MalformedPath);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use maknae_proto::{EffectEntry, ReportedFinish};
    const ID: MutationId = MutationId {
        session_id: 7,
        intent_seq: 11,
    };
    fn limits() -> MutationLimits {
        MutationLimits {
            max_effects: 4096,
            max_depth: 128,
            deadline_ms: 5000,
        }
    }
    fn tree() -> MutationExchange {
        MutationExchange::begin(
            ID,
            MutationScope::RecursiveDelete {
                root: "/sentinel/tree".into(),
            },
            limits(),
        )
        .unwrap()
    }
    fn batch(index: u32, paths: &[&str], effect: ReportedEffect) -> MutationReport {
        MutationReport::Batch {
            id: ID,
            first_index: index,
            effects: paths
                .iter()
                .map(|p| EffectEntry {
                    path: (*p).into(),
                    effect,
                })
                .collect(),
        }
    }
    fn finish(index: u32, stopped_at: Option<&str>) -> MutationReport {
        MutationReport::Finished {
            id: ID,
            next_index: index,
            outcome: ReportedFinish::Success,
            stopped_at: stopped_at.map(str::to_string),
        }
    }
    fn incomplete(index: u32, outcome: ReportedFinish) -> MutationReport {
        MutationReport::Finished {
            id: ID,
            next_index: index,
            outcome,
            stopped_at: None,
        }
    }
    fn commit(exchange: &mut MutationExchange, report: &MutationReport) -> MutationAck {
        let pending = exchange.validate_report(report).unwrap();
        exchange.acknowledge(pending).unwrap()
    }

    #[test]
    fn durable_acknowledgment_is_the_only_progress_transition() {
        let mut exchange = tree();
        let report = batch(0, &["/sentinel/tree"], ReportedEffect::DeletedEntry);
        let pending = exchange.validate_report(&report).unwrap();
        assert_eq!(
            exchange.validate_report(&report).unwrap_err(),
            ReportError::Outstanding
        );
        assert_eq!(
            exchange.validate_report(&finish(1, None)).unwrap_err(),
            ReportError::Outstanding
        );
        assert_eq!(
            exchange.acknowledge(pending).unwrap(),
            MutationAck {
                id: ID,
                next_index: 1
            }
        );
        assert_eq!(
            exchange.validate_report(&report).unwrap_err(),
            ReportError::WrongIndex
        );
        assert_eq!(commit(&mut exchange, &finish(1, None)).next_index, 1);
        assert_eq!(
            exchange.validate_report(&finish(1, None)).unwrap_err(),
            ReportError::Terminal
        );
    }

    #[test]
    fn foreign_pending_cannot_commit_even_with_identical_correlation() {
        let mut one = tree();
        let mut two = tree();
        let pending = one
            .validate_report(&incomplete(0, ReportedFinish::OsRefused))
            .unwrap();
        assert_eq!(
            two.acknowledge(pending).unwrap_err(),
            ReportError::ForeignPending
        );
        assert_eq!(
            commit(&mut two, &incomplete(0, ReportedFinish::OsRefused)).next_index,
            0
        );
    }

    #[test]
    fn exact_scopes_allow_the_root_effect_but_no_other_effect_or_path() {
        for effect in [
            ReportedEffect::CreatedFile,
            ReportedEffect::ReplacedFile,
            ReportedEffect::CreatedDirectory,
            ReportedEffect::DeletedEntry,
        ] {
            let mut exchange = MutationExchange::begin(
                ID,
                MutationScope::Exact {
                    path: "/sentinel/exact".into(),
                    effect,
                },
                limits(),
            )
            .unwrap();
            assert_eq!(
                exchange
                    .validate_report(&batch(0, &["/sentinel/exact/child"], effect))
                    .unwrap_err(),
                ReportError::OutOfScope
            );
            let wrong = if effect == ReportedEffect::DeletedEntry {
                ReportedEffect::CreatedFile
            } else {
                ReportedEffect::DeletedEntry
            };
            assert_eq!(
                exchange
                    .validate_report(&batch(0, &["/sentinel/exact"], wrong))
                    .unwrap_err(),
                ReportError::WrongEffect
            );
            assert_eq!(
                commit(&mut exchange, &batch(0, &["/sentinel/exact"], effect)).next_index,
                1
            );
        }
    }

    #[test]
    fn recursive_delete_accepts_final_root_removal_and_refuses_sibling_prefixes() {
        let mut exchange = tree();
        assert_eq!(
            exchange
                .validate_report(&batch(
                    0,
                    &["/sentinel/treeish/x"],
                    ReportedEffect::DeletedEntry
                ))
                .unwrap_err(),
            ReportError::OutOfScope
        );
        assert_eq!(
            exchange
                .validate_report(&batch(
                    0,
                    &["/sentinel/tree/x"],
                    ReportedEffect::CreatedDirectory
                ))
                .unwrap_err(),
            ReportError::WrongEffect
        );
        assert_eq!(
            commit(
                &mut exchange,
                &batch(
                    0,
                    &["/sentinel/tree/x", "/sentinel/tree"],
                    ReportedEffect::DeletedEntry
                )
            )
            .next_index,
            2
        );
    }

    #[test]
    fn mkdir_reports_are_members_of_prepared_authorized_prefixes() {
        let mut exchange = MutationExchange::begin(
            ID,
            MutationScope::Directories {
                paths: vec!["/sentinel/a".into(), "/sentinel/a/b".into()],
            },
            limits(),
        )
        .unwrap();
        assert_eq!(
            exchange
                .validate_report(&batch(
                    0,
                    &["/sentinel/a/other"],
                    ReportedEffect::CreatedDirectory
                ))
                .unwrap_err(),
            ReportError::OutOfScope
        );
        assert_eq!(
            exchange
                .validate_report(&batch(0, &["/sentinel/a"], ReportedEffect::DeletedEntry))
                .unwrap_err(),
            ReportError::WrongEffect
        );
        assert_eq!(
            commit(
                &mut exchange,
                &batch(0, &["/sentinel/a/b"], ReportedEffect::CreatedDirectory)
            )
            .next_index,
            1
        );
        let mut noop = MutationExchange::begin(
            ID,
            MutationScope::Directories {
                paths: vec!["/sentinel/a".into()],
            },
            limits(),
        )
        .unwrap();
        assert_eq!(commit(&mut noop, &finish(0, None)).next_index, 0);
    }

    #[test]
    fn invalid_reports_leave_the_next_valid_report_at_the_same_index() {
        let mut exchange = tree();
        let mut wrong_id = batch(0, &["/sentinel/tree/x"], ReportedEffect::DeletedEntry);
        if let MutationReport::Batch { id, .. } = &mut wrong_id {
            id.session_id += 1;
        }
        let mut wrong_finish_id = finish(0, None);
        if let MutationReport::Finished { id, .. } = &mut wrong_finish_id {
            id.intent_seq += 1;
        }
        for (report, error) in [
            (wrong_id, ReportError::WrongId),
            (wrong_finish_id, ReportError::WrongId),
            (
                batch(1, &["/sentinel/tree/x"], ReportedEffect::DeletedEntry),
                ReportError::WrongIndex,
            ),
            (finish(1, None), ReportError::WrongIndex),
            (
                batch(0, &[], ReportedEffect::DeletedEntry),
                ReportError::Limit,
            ),
            (
                batch(0, &["/sentinel/tree/x"; 33], ReportedEffect::DeletedEntry),
                ReportError::Limit,
            ),
            (finish(0, Some("/outside")), ReportError::OutOfScope),
        ] {
            assert_eq!(exchange.validate_report(&report).unwrap_err(), error);
        }
        assert_eq!(
            commit(
                &mut exchange,
                &batch(0, &["/sentinel/tree/x"], ReportedEffect::DeletedEntry)
            )
            .next_index,
            1
        );
    }

    #[test]
    fn path_spelling_is_rejected_without_normalization_in_scope_batch_and_finish() {
        let too_long = format!("/{}", "x".repeat(4096));
        for path in [
            "",
            "relative",
            "//sentinel/tree",
            "/sentinel/tree/",
            "/sentinel//tree",
            "/sentinel/./tree",
            "/sentinel/a/../tree",
            "/sentinel/tree/\0",
            too_long.as_str(),
        ] {
            let expected = if path.len() > 4096 {
                ReportError::Limit
            } else {
                ReportError::MalformedPath
            };
            for scope in [
                MutationScope::RecursiveDelete { root: path.into() },
                MutationScope::Exact {
                    path: path.into(),
                    effect: ReportedEffect::CreatedFile,
                },
                MutationScope::Directories {
                    paths: vec![path.into()],
                },
            ] {
                assert_eq!(
                    MutationExchange::begin(ID, scope, limits()).unwrap_err(),
                    expected,
                    "{path:?}"
                );
            }
            let mut exchange = tree();
            assert_eq!(
                exchange
                    .validate_report(&batch(0, &[path], ReportedEffect::DeletedEntry))
                    .unwrap_err(),
                expected
            );
            assert_eq!(
                exchange
                    .validate_report(&finish(0, Some(path)))
                    .unwrap_err(),
                expected
            );
            assert_eq!(
                commit(&mut exchange, &incomplete(0, ReportedFinish::OsRefused)).next_index,
                0
            );
        }
    }

    #[test]
    fn effect_and_depth_limits_accept_boundary_and_refuse_next_effect() {
        let mut exchange = tree();
        for index in (0..4096).step_by(32) {
            let paths: Vec<String> = (index..index + 32)
                .map(|i| format!("/sentinel/tree/leaf{i}"))
                .collect();
            let paths: Vec<&str> = paths.iter().map(String::as_str).collect();
            assert_eq!(
                commit(
                    &mut exchange,
                    &batch(index, &paths, ReportedEffect::DeletedEntry)
                )
                .next_index,
                index + 32
            );
        }
        assert_eq!(
            exchange
                .validate_report(&batch(
                    4096,
                    &["/sentinel/tree/overflow"],
                    ReportedEffect::DeletedEntry
                ))
                .unwrap_err(),
            ReportError::Limit
        );
        assert_eq!(
            commit(
                &mut exchange,
                &incomplete(4096, ReportedFinish::LimitReached)
            )
            .next_index,
            4096
        );
        let mut exchange = tree();
        let boundary = format!("/sentinel/tree{}", "/a".repeat(128));
        let too_deep = format!("{boundary}/a");
        assert_eq!(
            exchange
                .validate_report(&batch(0, &[&too_deep], ReportedEffect::DeletedEntry))
                .unwrap_err(),
            ReportError::Limit
        );
        assert_eq!(
            exchange
                .validate_report(&finish(0, Some(&too_deep)))
                .unwrap_err(),
            ReportError::Limit
        );
        assert_eq!(
            commit(
                &mut exchange,
                &batch(0, &[&boundary], ReportedEffect::DeletedEntry)
            )
            .next_index,
            1
        );
    }

    #[test]
    fn directory_scope_is_a_consecutive_chain_with_first_prefix_at_depth_one() {
        for paths in [
            vec!["/sentinel/a", "/sentinel/b"],
            vec!["/sentinel/a", "/sentinel/a"],
            vec!["/sentinel/a", "/sentinel/a/b/c"],
            vec!["/sentinel/a/b", "/sentinel/a"],
        ] {
            let scope = MutationScope::Directories {
                paths: paths.into_iter().map(str::to_string).collect(),
            };
            assert_eq!(
                MutationExchange::begin(ID, scope, limits()).unwrap_err(),
                ReportError::OutOfScope
            );
        }
        let paths: Vec<String> = (0..128)
            .map(|depth| format!("/sentinel/home/deep/start{}", "/a".repeat(depth)))
            .collect();
        let deepest = paths.last().unwrap().clone();
        let mut exchange = MutationExchange::begin(
            ID,
            MutationScope::Directories {
                paths: paths.clone(),
            },
            limits(),
        )
        .unwrap();
        assert_eq!(
            commit(
                &mut exchange,
                &batch(0, &[&deepest], ReportedEffect::CreatedDirectory)
            )
            .next_index,
            1
        );
        let mut overflow = paths;
        overflow.push(format!("{deepest}/a"));
        assert_eq!(
            MutationExchange::begin(ID, MutationScope::Directories { paths: overflow }, limits())
                .unwrap_err(),
            ReportError::Limit
        );
    }

    #[test]
    fn invalid_later_batch_entry_does_not_reserve_partial_progress() {
        let mut exchange = tree();
        assert_eq!(
            exchange
                .validate_report(&batch(
                    0,
                    &["/sentinel/tree/valid", "/outside"],
                    ReportedEffect::DeletedEntry
                ))
                .unwrap_err(),
            ReportError::OutOfScope
        );
        assert_eq!(
            commit(
                &mut exchange,
                &batch(0, &["/sentinel/tree/valid"], ReportedEffect::DeletedEntry)
            )
            .next_index,
            1
        );
    }

    #[test]
    fn configured_lower_limits_are_enforced_and_root_spelling_is_canonical() {
        let mut exchange = MutationExchange::begin(
            ID,
            MutationScope::RecursiveDelete { root: "/".into() },
            MutationLimits {
                max_effects: 1,
                max_depth: 1,
                deadline_ms: 5000,
            },
        )
        .unwrap();
        assert_eq!(
            exchange
                .validate_report(&batch(0, &["/a/b"], ReportedEffect::DeletedEntry))
                .unwrap_err(),
            ReportError::Limit
        );
        assert_eq!(
            commit(
                &mut exchange,
                &batch(0, &["/a"], ReportedEffect::DeletedEntry)
            )
            .next_index,
            1
        );
        assert_eq!(
            exchange
                .validate_report(&batch(1, &["/b"], ReportedEffect::DeletedEntry))
                .unwrap_err(),
            ReportError::Limit
        );
        assert_eq!(
            commit(&mut exchange, &incomplete(1, ReportedFinish::LimitReached)).next_index,
            1
        );
        let path = format!("/{}", "x".repeat(4095));
        let mut exchange = MutationExchange::begin(
            ID,
            MutationScope::Exact {
                path: path.clone(),
                effect: ReportedEffect::CreatedFile,
            },
            limits(),
        )
        .unwrap();
        assert_eq!(
            commit(
                &mut exchange,
                &batch(0, &[&path], ReportedEffect::CreatedFile)
            )
            .next_index,
            1
        );
    }

    #[test]
    fn validated_paths_and_root_removal_enter_history_only_after_acknowledgment() {
        let mut exchange = tree();
        let pending = exchange
            .validate_report(&batch(
                0,
                &["/sentinel/tree/a", "/sentinel/tree"],
                ReportedEffect::DeletedEntry,
            ))
            .unwrap();
        assert_eq!(exchange.next_index, 0);
        assert!(
            exchange.seen.is_empty(),
            "unaudited claims must not enter acknowledged history"
        );
        assert_eq!(
            exchange.validate_report(&finish(2, None)).unwrap_err(),
            ReportError::Outstanding
        );
        assert_eq!(exchange.acknowledge(pending).unwrap().next_index, 2);
        assert!(exchange.seen.contains("/sentinel/tree/a"));
        assert!(exchange.seen.contains("/sentinel/tree"));
        assert_eq!(commit(&mut exchange, &finish(2, None)).next_index, 2);
    }

    #[test]
    fn exact_claims_require_one_effect_for_success_and_never_accept_two() {
        for effect in [
            ReportedEffect::CreatedFile,
            ReportedEffect::ReplacedFile,
            ReportedEffect::CreatedDirectory,
            ReportedEffect::DeletedEntry,
        ] {
            let mut exchange = MutationExchange::begin(
                ID,
                MutationScope::Exact {
                    path: "/sentinel/exact".into(),
                    effect,
                },
                limits(),
            )
            .unwrap();
            assert_eq!(
                exchange.validate_report(&finish(0, None)).unwrap_err(),
                ReportError::InconsistentClaim
            );
            assert_eq!(
                exchange
                    .validate_report(&batch(0, &["/sentinel/exact", "/sentinel/exact"], effect))
                    .unwrap_err(),
                ReportError::InconsistentClaim
            );
            assert_eq!(
                commit(&mut exchange, &batch(0, &["/sentinel/exact"], effect)).next_index,
                1
            );
            assert_eq!(
                exchange
                    .validate_report(&batch(1, &["/sentinel/exact"], effect))
                    .unwrap_err(),
                ReportError::InconsistentClaim
            );
            assert_eq!(commit(&mut exchange, &finish(1, None)).next_index, 1);
        }
    }

    #[test]
    fn exact_attempt_can_report_os_refusal_without_claiming_an_effect() {
        let mut exchange = MutationExchange::begin(
            ID,
            MutationScope::Exact {
                path: "/sentinel/refused".into(),
                effect: ReportedEffect::CreatedFile,
            },
            limits(),
        )
        .unwrap();
        assert_eq!(
            commit(&mut exchange, &incomplete(0, ReportedFinish::OsRefused)).next_index,
            0
        );
    }

    #[test]
    fn duplicate_directory_claims_are_refused_within_and_across_batches() {
        let mut exchange = MutationExchange::begin(
            ID,
            MutationScope::Directories {
                paths: vec!["/sentinel/a".into(), "/sentinel/a/b".into()],
            },
            limits(),
        )
        .unwrap();
        assert_eq!(
            exchange
                .validate_report(&batch(
                    0,
                    &["/sentinel/a", "/sentinel/a"],
                    ReportedEffect::CreatedDirectory
                ))
                .unwrap_err(),
            ReportError::InconsistentClaim
        );
        assert_eq!(
            commit(
                &mut exchange,
                &batch(0, &["/sentinel/a"], ReportedEffect::CreatedDirectory)
            )
            .next_index,
            1
        );
        assert_eq!(
            exchange
                .validate_report(&batch(
                    1,
                    &["/sentinel/a/b", "/sentinel/a"],
                    ReportedEffect::CreatedDirectory
                ))
                .unwrap_err(),
            ReportError::InconsistentClaim
        );
        assert_eq!(
            commit(
                &mut exchange,
                &batch(1, &["/sentinel/a/b"], ReportedEffect::CreatedDirectory)
            )
            .next_index,
            2
        );
        assert_eq!(commit(&mut exchange, &finish(2, None)).next_index, 2);
    }

    #[test]
    fn recursive_success_requires_root_and_root_is_the_last_reported_effect() {
        let mut exchange = tree();
        assert_eq!(
            exchange.validate_report(&finish(0, None)).unwrap_err(),
            ReportError::InconsistentClaim
        );
        assert_eq!(
            exchange
                .validate_report(&batch(
                    0,
                    &["/sentinel/tree", "/sentinel/tree/a"],
                    ReportedEffect::DeletedEntry
                ))
                .unwrap_err(),
            ReportError::InconsistentClaim
        );
        assert_eq!(
            exchange
                .validate_report(&batch(
                    0,
                    &["/sentinel/tree/a", "/sentinel/tree/a"],
                    ReportedEffect::DeletedEntry
                ))
                .unwrap_err(),
            ReportError::InconsistentClaim
        );
        assert_eq!(
            commit(
                &mut exchange,
                &batch(0, &["/sentinel/tree/a"], ReportedEffect::DeletedEntry)
            )
            .next_index,
            1
        );
        assert_eq!(
            exchange.validate_report(&finish(1, None)).unwrap_err(),
            ReportError::InconsistentClaim
        );
        assert_eq!(
            exchange
                .validate_report(&batch(
                    1,
                    &["/sentinel/tree/a"],
                    ReportedEffect::DeletedEntry
                ))
                .unwrap_err(),
            ReportError::InconsistentClaim
        );
        assert_eq!(
            commit(
                &mut exchange,
                &batch(
                    1,
                    &["/sentinel/tree/b", "/sentinel/tree"],
                    ReportedEffect::DeletedEntry
                )
            )
            .next_index,
            3
        );
        assert_eq!(
            exchange
                .validate_report(&batch(
                    3,
                    &["/sentinel/tree/c"],
                    ReportedEffect::DeletedEntry
                ))
                .unwrap_err(),
            ReportError::InconsistentClaim
        );
        assert_eq!(commit(&mut exchange, &finish(3, None)).next_index, 3);
    }

    #[test]
    fn malformed_limits_and_empty_directory_scope_never_begin() {
        for limits in [
            MutationLimits {
                max_effects: 4097,
                ..limits()
            },
            MutationLimits {
                max_effects: 0,
                ..limits()
            },
            MutationLimits {
                max_depth: 129,
                ..limits()
            },
            MutationLimits {
                deadline_ms: 0,
                ..limits()
            },
        ] {
            assert_eq!(
                MutationExchange::begin(
                    ID,
                    MutationScope::RecursiveDelete {
                        root: "/sentinel/tree".into()
                    },
                    limits
                )
                .unwrap_err(),
                ReportError::Limit
            );
        }
        assert_eq!(
            MutationExchange::begin(ID, MutationScope::Directories { paths: vec![] }, limits())
                .unwrap_err(),
            ReportError::OutOfScope
        );
    }
}
