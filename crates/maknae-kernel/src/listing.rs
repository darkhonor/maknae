//! `fs.list` after its grant (#161 M12, M14): every name the subject reports is decided
//! as `fs.read` on the kernel-reported directory, and only the permitted page is released.
use crate::conversation::facts::ConversationFacts;
use crate::handler::{discharge_plan, Stamp, TaskStamp};
use crate::mutation::{completion, incomplete, normal, path_request, Delivery, DurableIntent};
use maknae_audit_append::{AuditEmit, MutationStatus, Seq};
use maknae_config::TransportConfig;
use maknae_proto::{
    ListChunk, ListEntry, ListGrant, MutationGrant, MutationId, MutationLimits, MutationScope,
    Payload, ProtoErrCode, ProtoError, ReportedEffect, RespResult, Response, Verb,
    LIST_RECEIVE_MAX, LIST_RELEASE_MAX, PROTOCOL_VERSION,
};
use maknae_security::{AttrValue, Authorizer, Decision, FsOperation};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::io::{AsyncRead, AsyncWrite};

pub(crate) const ORDER_VIOLATED: &str = "listing order violated";
pub(crate) const BOUND_REACHED: &str = "listing bound reached before a full page was permitted";
const EMPTY_CHUNK: &str = "listing chunk empty before the last";
pub(crate) const SUBJECT_UNLISTED: &str =
    "the subject reports it could not list the directory (unverified)";

/// What one entry is decided by: the request's own facts, owned for a blocking worker.
pub(crate) struct Decider<P> {
    pub(crate) authorizer: Arc<P>,
    pub(crate) verb: Verb,
    pub(crate) uid: u32,
    pub(crate) home: PathBuf,
    pub(crate) facts: Option<ConversationFacts>,
    pub(crate) personal: Option<AttrValue>,
    pub(crate) stamped: Option<(maknae_config::AgentId, Option<TaskStamp>)>,
}

impl<P: Authorizer> Decider<P> {
    fn permits(&self, path: &str) -> bool {
        let stamp = match &self.stamped {
            None => Stamp::Client,
            Some((agent, task)) => Stamp::Agent {
                agent,
                task: task.as_ref(),
            },
        };
        let request = path_request(
            &self.verb,
            self.uid,
            Some(&self.home),
            self.facts.as_ref(),
            self.personal.as_ref(),
            &stamp,
            path,
            FsOperation::Read,
        );
        let decided = maknae_security::guarded_decide_cited_all(&*self.authorizer, &[request]);
        decided.into_iter().next().is_some_and(|d| {
            matches!(
                maknae_security::finalize(maknae_security::combine(vec![d.verdict])),
                Decision::Permit { obligations } if discharge_plan(&obligations).is_ok()
            )
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum End {
    Complete,
    Truncated,
    Refused(&'static str),
}

/// One listing's state across its chunks.
#[derive(Debug)]
pub(crate) struct Lister {
    directory: String,
    after: Option<String>,
    previous: Option<String>,
    received: usize,
    skipped: usize,
    invalid: usize,
    withheld: usize,
    dropped: u64,
    vanished: u64,
    decided_permits: usize,
    permitted: Vec<ListEntry>,
    budget: usize,
    bytes: usize,
    full: bool,
}

/// Room left in a page's response for its envelope, beyond its entries.
const PAGE_HEADROOM: usize = 256;

/// One entry's CBOR size as a `ListGrant` element: a two-key map, the keys, the name
/// with its text header, and the bool.
fn entry_bytes(name: &str) -> usize {
    let header = match name.len() {
        0..=23 => 1,
        24..=255 => 2,
        256..=65_535 => 3,
        _ => 5,
    };
    11 + header + name.len()
}

impl Lister {
    /// `response_cap` bounds the page's encoded answer: the page closes, truncated, before
    /// a permitted entry that would not fit.
    pub(crate) fn new(directory: String, after: Option<String>, response_cap: usize) -> Self {
        Self {
            directory,
            after,
            previous: None,
            received: 0,
            skipped: 0,
            invalid: 0,
            withheld: 0,
            dropped: 0,
            vanished: 0,
            decided_permits: 0,
            permitted: Vec::new(),
            budget: response_cap.saturating_sub(PAGE_HEADROOM),
            bytes: 0,
            full: false,
        }
    }

    fn child(&self, name: &str) -> String {
        if self.directory == "/" {
            format!("/{name}")
        } else {
            format!("{}/{name}", self.directory)
        }
    }

    /// Decides the chunk's names in order until the listing ends; `None` asks for more.
    pub(crate) fn take(
        &mut self,
        chunk: &ListChunk,
        mut permits: impl FnMut(&str) -> bool,
    ) -> Option<End> {
        if chunk.unlisted {
            return Some(End::Refused(SUBJECT_UNLISTED));
        }
        if chunk.entries.is_empty() && !chunk.last {
            return Some(End::Refused(EMPTY_CHUNK));
        }
        self.dropped = self.dropped.saturating_add(u64::from(chunk.dropped));
        self.vanished = self.vanished.saturating_add(u64::from(chunk.vanished));
        for entry in &chunk.entries {
            if self
                .previous
                .as_ref()
                .is_some_and(|p| entry.name.as_bytes() <= p.as_bytes())
            {
                return Some(End::Refused(ORDER_VIOLATED));
            }
            self.previous = Some(entry.name.clone());
            self.received += 1;
            self.decide(entry, &mut permits);
            if self.full || self.permitted.len() > LIST_RELEASE_MAX {
                return Some(End::Truncated);
            }
            if self.received == LIST_RECEIVE_MAX {
                return Some(End::Refused(BOUND_REACHED));
            }
        }
        chunk.last.then_some(End::Complete)
    }

    fn decide(&mut self, entry: &ListEntry, permits: &mut impl FnMut(&str) -> bool) {
        if !normal(&entry.name) || entry.name.len() > maknae_proto::LIST_CURSOR_MAX_BYTES {
            self.invalid += 1;
            return;
        }
        if self
            .after
            .as_ref()
            .is_some_and(|a| entry.name.as_bytes() <= a.as_bytes())
        {
            self.skipped += 1;
            return;
        }
        let path = self.child(&entry.name);
        if crate::mutation::checked(&path).is_err() {
            self.invalid += 1;
        } else if permits(&path) {
            self.decided_permits += 1;
            let size = entry_bytes(&entry.name);
            if !self.permitted.is_empty() && self.bytes + size > self.budget {
                self.full = true;
            } else {
                self.bytes += size;
                self.permitted.push(entry.clone());
            }
        } else {
            self.withheld += 1;
        }
    }

    /// `permitted` counts every `Permit`, the one that closed a page included; the
    /// released figure follows the page's delivery, and is 0 when nothing was sent.
    pub(crate) fn trail(&self, end: &End, delivery: Delivery) -> String {
        let page = self.permitted.len().min(LIST_RELEASE_MAX);
        let released = match (end, delivery) {
            (End::Refused(_), _) | (_, Delivery::Withheld) => "0 released".to_string(),
            (_, Delivery::Pending) => format!("{page} in the page"),
            (_, Delivery::Released) => format!("{page} released"),
            (_, Delivery::Unknown) => format!("{page} in the page, delivery unknown"),
        };
        format!(
            "listing: {} received, {} skipped by the cursor, {} invalid, {} withheld, {} permitted, {released}; the subject reports {} non-UTF-8 names dropped and {} vanished (unverified)",
            self.received,
            self.skipped,
            self.invalid,
            self.withheld,
            self.decided_permits,
            self.dropped,
            self.vanished
        )
    }

    pub(crate) fn page(&self) -> ListGrant {
        ListGrant {
            entries: self
                .permitted
                .iter()
                .take(LIST_RELEASE_MAX)
                .cloned()
                .collect(),
            truncated: self.full || self.permitted.len() > LIST_RELEASE_MAX,
        }
    }
}

async fn answer<S: AsyncWrite + Unpin>(
    stream: &mut S,
    deadline: tokio::time::Instant,
    caps: crate::mutation::AttemptCaps,
    result: RespResult,
) -> bool {
    let Ok(bytes) = maknae_proto::encode_response(&Response {
        protocol_version: PROTOCOL_VERSION,
        result,
    }) else {
        return false;
    };
    bytes.len() <= caps.response
        && tokio::time::Instant::now() < deadline
        && matches!(
            tokio::time::timeout_at(
                deadline,
                maknae_proto::write_frame(stream, maknae_proto::FrameClass::Attempt, &bytes)
            )
            .await,
            Ok(Ok(()))
        )
}

/// The listing exchange: the grant, then chunk by chunk until the listing ends. The page
/// is sent only after its record lands.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run<S, E, P>(
    stream: &mut S,
    cfg: &TransportConfig,
    caps: crate::mutation::AttemptCaps,
    emit: &E,
    intent: DurableIntent,
    label: maknae_proto::ObjectLabel,
    seq: &Seq,
    mut lister: Lister,
    decider: Arc<Decider<P>>,
    authz_timeout: Duration,
    deadline: tokio::time::Instant,
    mut permit: tokio::sync::OwnedSemaphorePermit,
) where
    S: AsyncRead + AsyncWrite + Unpin,
    E: AuditEmit,
    P: Authorizer + Send + Sync + 'static,
{
    let grant = MutationGrant {
        id: MutationId {
            session_id: intent.record.session_id,
            intent_seq: intent.record.seq,
        },
        scope: MutationScope::Exact {
            path: lister.directory.clone(),
            effect: ReportedEffect::ReadFile,
        },
        limits: MutationLimits {
            max_effects: 1,
            max_depth: 1,
            deadline_ms: cfg.read_timeout_ms,
            max_bytes: 0,
        },
        label,
    };
    if !answer(
        stream,
        deadline,
        caps,
        RespResult::Ok(Payload::MutationAttempt(grant)),
    )
    .await
    {
        incomplete(cfg, emit, &intent, seq, "listing grant not delivered").await;
        return;
    }
    let end = loop {
        let frame = tokio::time::timeout_at(
            deadline,
            maknae_proto::read_frame_of_class(
                stream,
                maknae_proto::FrameClass::Attempt,
                &maknae_proto::FrameCaps {
                    control: 0,
                    attempt: caps.request,
                    prompt: 0,
                },
            ),
        )
        .await;
        let chunk = match frame {
            Ok(Ok(bytes)) => maknae_proto::decode_list_chunk(&bytes).ok(),
            _ => None,
        };
        let Some(chunk) = chunk else {
            incomplete(
                cfg,
                emit,
                &intent,
                seq,
                "listing chunk missing or malformed; nothing released",
            )
            .await;
            return;
        };
        let Some(claim) = crate::mutation::mutating().try_claim(decider.uid) else {
            incomplete(
                cfg,
                emit,
                &intent,
                seq,
                crate::mutation::busy_reason(crate::uid_gate::Busy::Requester),
            )
            .await;
            return;
        };
        let deciding = Arc::clone(&decider);
        let decided = tokio::time::timeout(
            authz_timeout,
            tokio::task::spawn_blocking(move || {
                let _claim = claim;
                let end = lister.take(&chunk, |path| deciding.permits(path));
                (lister, end, permit)
            }),
        )
        .await;
        let Ok(Ok((back, end, held))) = decided else {
            incomplete(
                cfg,
                emit,
                &intent,
                seq,
                "listing decision timed out/failed; nothing released",
            )
            .await;
            return;
        };
        lister = back;
        permit = held;
        match end {
            Some(end) => break end,
            None => {
                if !answer(
                    stream,
                    deadline,
                    caps,
                    RespResult::Ok(Payload::ListContinue),
                )
                .await
                {
                    incomplete(
                        cfg,
                        emit,
                        &intent,
                        seq,
                        "listing continuation not delivered; nothing released",
                    )
                    .await;
                    return;
                }
            }
        }
    };
    if let End::Refused(why) = end {
        let record = completion(&intent, seq.next(), MutationStatus::Incomplete);
        let answer = ProtoError {
            code: ProtoErrCode::Unauthorized,
            message: why.into(),
        };
        let reason = format!("{why}; {}", lister.trail(&end, Delivery::Withheld));
        crate::mutation::refuse_with(stream, cfg, emit, record, reason, answer).await;
        return;
    }
    let page = lister.page();
    crate::mutation::disclose(
        stream,
        cfg,
        emit,
        seq,
        &intent,
        &|delivery| lister.trail(&end, delivery),
        true,
        Payload::ListGrant(page),
        caps.response,
        deadline,
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries(names: &[&str]) -> Vec<ListEntry> {
        names
            .iter()
            .map(|n| ListEntry {
                name: (*n).into(),
                dir: false,
            })
            .collect()
    }
    fn chunk(names: &[&str], last: bool) -> ListChunk {
        ListChunk {
            entries: entries(names),
            last,
            dropped: 0,
            unlisted: false,
            vanished: 0,
        }
    }
    fn numbered(from: usize, count: usize) -> Vec<String> {
        (from..from + count).map(|i| format!("n{i:06}")).collect()
    }
    fn chunk_of(names: &[String], last: bool) -> ListChunk {
        let names: Vec<&str> = names.iter().map(String::as_str).collect();
        chunk(&names, last)
    }

    #[test]
    fn n_reported_names_produce_n_decisions_up_to_the_stop() {
        let mut lister = Lister::new("/d161".into(), None, maknae_proto::ATTEMPT_RESPONSE_MAX);
        let mut asked = Vec::new();
        let end = lister.take(&chunk(&["a", "b", "c", "d", "e"], true), |p| {
            asked.push(p.to_owned());
            p != "/d161/b" && p != "/d161/d"
        });
        assert_eq!(end, Some(End::Complete));
        assert_eq!(
            asked,
            ["/d161/a", "/d161/b", "/d161/c", "/d161/d", "/d161/e"]
        );
        assert_eq!(
            lister.page().entries,
            entries(&["a", "c", "e"]),
            "only the permitted subset, in order"
        );

        let mut lister = Lister::new("/".into(), None, maknae_proto::ATTEMPT_RESPONSE_MAX);
        let mut calls = 0;
        let names = numbered(0, LIST_RELEASE_MAX + 10);
        let end = lister.take(&chunk_of(&names, true), |_| {
            calls += 1;
            true
        });
        assert_eq!(end, Some(End::Truncated));
        assert_eq!(calls, LIST_RELEASE_MAX + 1, "no decision after the stop");
    }

    #[test]
    fn a_1025th_permitted_entry_sets_truncated_and_releases_1024() {
        let names = numbered(0, LIST_RELEASE_MAX + 1);
        let mut lister = Lister::new("/d".into(), None, maknae_proto::ATTEMPT_RESPONSE_MAX);
        assert_eq!(
            lister.take(&chunk_of(&names, true), |_| true),
            Some(End::Truncated)
        );
        let grant = lister.page();
        assert!(grant.truncated);
        assert_eq!(grant.entries.len(), LIST_RELEASE_MAX);
        assert_eq!(
            grant.entries.last().unwrap().name,
            names[LIST_RELEASE_MAX - 1]
        );

        let names = numbered(0, LIST_RELEASE_MAX);
        let mut lister = Lister::new("/d".into(), None, maknae_proto::ATTEMPT_RESPONSE_MAX);
        assert_eq!(
            lister.take(&chunk_of(&names, true), |_| true),
            Some(End::Complete)
        );
        let grant = lister.page();
        assert!(!grant.truncated, "exactly 1024 permitted is a whole page");
        assert_eq!(grant.entries.len(), LIST_RELEASE_MAX);

        let mut names = numbered(0, LIST_RELEASE_MAX);
        names.push("z-denied".into());
        let mut lister = Lister::new("/d".into(), None, maknae_proto::ATTEMPT_RESPONSE_MAX);
        lister.take(&chunk_of(&names, true), |p| !p.ends_with("z-denied"));
        assert!(
            !lister.page().truncated,
            "a denied 1025th name does not set truncated"
        );
    }

    #[test]
    fn a_page_of_long_names_closes_under_the_response_cap_and_the_cursor_continues_it() {
        let long = "x".repeat(700);
        let names: Vec<String> = (0..1000).map(|i| format!("{i:04}{long}")).collect();
        let cap = maknae_proto::ATTEMPT_RESPONSE_MAX;
        let mut lister = Lister::new("/d".into(), None, cap);
        assert_eq!(
            lister.take(&chunk_of(&names, true), |_| true),
            Some(End::Truncated)
        );
        let page = lister.page();
        assert!(page.truncated, "the next permitted entry exists");
        assert!(page.entries.len() < LIST_RELEASE_MAX);
        let encoded = maknae_proto::encode_response(&Response {
            protocol_version: PROTOCOL_VERSION,
            result: RespResult::Ok(Payload::ListGrant(page.clone())),
        })
        .unwrap();
        assert!(encoded.len() <= cap, "{} bytes", encoded.len());
        let last = page.entries.last().unwrap().name.clone();
        let mut next = Lister::new("/d".into(), Some(last), cap);
        next.take(&chunk_of(&names, true), |_| true);
        assert_eq!(
            next.page().entries[0].name,
            names[page.entries.len()],
            "the cursor resumes at the entry that did not fit"
        );
    }

    #[test]
    fn a_name_longer_than_a_cursor_is_withheld_as_invalid() {
        let usable = "u".repeat(maknae_proto::LIST_CURSOR_MAX_BYTES);
        let too_long = "v".repeat(maknae_proto::LIST_CURSOR_MAX_BYTES + 1);
        let mut lister = Lister::new("/d".into(), None, maknae_proto::ATTEMPT_RESPONSE_MAX);
        let mut asked = Vec::new();
        lister.take(&chunk(&[&usable, &too_long], true), |p| {
            asked.push(p.to_owned());
            true
        });
        assert_eq!(
            asked,
            [format!("/d/{usable}")],
            "every released name is a usable cursor"
        );
        assert_eq!(lister.invalid, 1);
    }

    #[test]
    fn a_page_always_holds_its_first_permitted_entry() {
        let long = "y".repeat(400);
        let names: Vec<String> = (0..2).map(|i| format!("{i}{long}")).collect();
        let mut lister = Lister::new("/d".into(), None, 300);
        assert_eq!(
            lister.take(&chunk_of(&names[..1], true), |_| true),
            Some(End::Complete)
        );
        let page = lister.page();
        assert_eq!((page.entries.len(), page.truncated), (1, false));
        let mut lister = Lister::new("/d".into(), None, 300);
        assert_eq!(
            lister.take(&chunk_of(&names, true), |_| true),
            Some(End::Truncated)
        );
        let page = lister.page();
        assert_eq!(
            (page.entries.len(), page.truncated),
            (1, true),
            "never an empty truncated page the cursor cannot move past"
        );
    }

    #[test]
    fn an_entrys_size_is_its_exact_cbor_size() {
        for len in [1, 23, 24, 255, 256, 765, 65_535, 65_536] {
            let entry = ListEntry {
                name: "n".repeat(len),
                dir: true,
            };
            let page = |entries: Vec<ListEntry>| {
                maknae_proto::encode_response(&Response {
                    protocol_version: PROTOCOL_VERSION,
                    result: RespResult::Ok(Payload::ListGrant(ListGrant {
                        entries,
                        truncated: false,
                    })),
                })
                .unwrap()
                .len()
            };
            assert_eq!(
                page(vec![entry.clone(), entry.clone()]) - page(vec![entry.clone()]),
                entry_bytes(&entry.name),
                "{len}"
            );
        }
        assert!(page_envelope() <= PAGE_HEADROOM);
    }

    fn page_envelope() -> usize {
        let entries: Vec<ListEntry> = (0..LIST_RELEASE_MAX + 1)
            .map(|_| ListEntry {
                name: "e".into(),
                dir: false,
            })
            .collect();
        let size = maknae_proto::encode_response(&Response {
            protocol_version: PROTOCOL_VERSION,
            result: RespResult::Ok(Payload::ListGrant(ListGrant {
                entries,
                truncated: true,
            })),
        })
        .unwrap()
        .len();
        size - (LIST_RELEASE_MAX + 1) * entry_bytes("e")
    }

    #[test]
    fn the_after_cursor_returns_the_next_page() {
        let mut lister = Lister::new(
            "/d".into(),
            Some("b".into()),
            maknae_proto::ATTEMPT_RESPONSE_MAX,
        );
        let mut asked = Vec::new();
        let end = lister.take(&chunk(&["a", "b", "ba", "c"], true), |p| {
            asked.push(p.to_owned());
            true
        });
        assert_eq!(end, Some(End::Complete));
        assert_eq!(asked, ["/d/ba", "/d/c"]);
        assert_eq!(lister.skipped, 2);
        assert_eq!(lister.page().entries, entries(&["ba", "c"]));
    }

    #[test]
    fn a_65536th_name_received_without_1025_permitted_refuses() {
        let names = numbered(0, LIST_RECEIVE_MAX);
        let mut lister = Lister::new("/d".into(), None, maknae_proto::ATTEMPT_RESPONSE_MAX);
        let mut calls = 0;
        let end = lister.take(&chunk_of(&names[..LIST_RECEIVE_MAX - 1], false), |_| {
            calls += 1;
            false
        });
        assert_eq!(end, None);
        let end = lister.take(&chunk_of(&names[LIST_RECEIVE_MAX - 1..], true), |_| {
            calls += 1;
            false
        });
        assert_eq!(end, Some(End::Refused(BOUND_REACHED)));
        assert_eq!(calls, LIST_RECEIVE_MAX);
        assert!(
            lister
                .trail(&End::Refused(BOUND_REACHED), Delivery::Withheld)
                .contains("65536 received"),
            "{}",
            lister.trail(&End::Refused(BOUND_REACHED), Delivery::Withheld)
        );

        let mut lister = Lister::new("/d".into(), None, maknae_proto::ATTEMPT_RESPONSE_MAX);
        let mut permitted = names[..LIST_RECEIVE_MAX - LIST_RELEASE_MAX - 1].to_vec();
        permitted.extend(numbered(LIST_RECEIVE_MAX, LIST_RELEASE_MAX + 1));
        let end = lister.take(&chunk_of(&permitted, true), |p| {
            p.as_bytes() >= format!("/d/n{LIST_RECEIVE_MAX:06}").as_bytes()
        });
        assert_eq!(
            end,
            Some(End::Truncated),
            "the 1025th permitted at the 65536th name is a full page"
        );
    }

    #[test]
    fn names_skipped_by_after_count_toward_the_bound() {
        let names = numbered(0, LIST_RECEIVE_MAX);
        let mut lister = Lister::new(
            "/d".into(),
            Some("z".into()),
            maknae_proto::ATTEMPT_RESPONSE_MAX,
        );
        let mut calls = 0;
        let end = lister.take(&chunk_of(&names, true), |_| {
            calls += 1;
            true
        });
        assert_eq!(end, Some(End::Refused(BOUND_REACHED)));
        assert_eq!((calls, lister.skipped), (0, LIST_RECEIVE_MAX));
    }

    #[test]
    fn an_unsorted_or_duplicated_chunk_refuses_the_listing() {
        for (first, second) in [
            (chunk(&["b", "a"], true), None),
            (chunk(&["a", "a"], true), None),
            (chunk(&["a", "c"], false), Some(chunk(&["b"], true))),
            (chunk(&["a", "c"], false), Some(chunk(&["c"], true))),
            (chunk(&["a"], false), Some(chunk(&["B"], true))),
        ] {
            let mut lister = Lister::new("/d".into(), None, maknae_proto::ATTEMPT_RESPONSE_MAX);
            let end = match lister.take(&first, |_| true) {
                None => lister.take(&second.clone().unwrap(), |_| true),
                end => end,
            };
            assert_eq!(
                end,
                Some(End::Refused(ORDER_VIOLATED)),
                "{first:?} {second:?}"
            );
        }
        let mut lister = Lister::new("/d".into(), None, maknae_proto::ATTEMPT_RESPONSE_MAX);
        assert_eq!(
            lister.take(&chunk(&["B", "a", "b"], true), |_| true),
            Some(End::Complete)
        );
    }

    #[test]
    fn invalid_names_are_withheld_and_counted_and_an_empty_chunk_before_the_last_refuses() {
        let long = "x".repeat(maknae_proto::MAX_MUTATION_PATH_BYTES);
        let mut lister = Lister::new("/d".into(), None, maknae_proto::ATTEMPT_RESPONSE_MAX);
        let mut asked = Vec::new();
        let end = lister.take(
            &chunk(&["", ".", "..", "a\0", "a/b", "ok", &long], true),
            |p| {
                asked.push(p.to_owned());
                true
            },
        );
        assert_eq!(end, Some(End::Complete));
        assert_eq!(asked, ["/d/ok"]);
        assert_eq!(lister.invalid, 6);
        assert_eq!(lister.page().entries, entries(&["ok"]));

        let mut lister = Lister::new("/d".into(), None, maknae_proto::ATTEMPT_RESPONSE_MAX);
        assert_eq!(
            lister.take(&chunk(&[], false), |_| true),
            Some(End::Refused(EMPTY_CHUNK))
        );
        let mut lister = Lister::new("/d".into(), None, maknae_proto::ATTEMPT_RESPONSE_MAX);
        assert_eq!(
            lister.take(&chunk(&[], true), |_| true),
            Some(End::Complete)
        );
    }

    #[test]
    fn a_subject_that_cannot_list_ends_the_listing_as_its_own_refusal() {
        let mut lister = Lister::new("/d".into(), None, maknae_proto::ATTEMPT_RESPONSE_MAX);
        let mut unlisted = chunk(&[], true);
        unlisted.unlisted = true;
        assert_eq!(
            lister.take(&unlisted, |_| panic!("nothing to decide")),
            Some(End::Refused(SUBJECT_UNLISTED))
        );
        assert!(SUBJECT_UNLISTED.contains("(unverified)"));
    }

    #[test]
    fn the_trail_records_every_count_and_the_subjects_dropped_claim() {
        let mut lister = Lister::new(
            "/d".into(),
            Some("a".into()),
            maknae_proto::ATTEMPT_RESPONSE_MAX,
        );
        let mut first = chunk(&["a", "b", "c"], false);
        first.dropped = 2;
        assert_eq!(lister.take(&first, |p| p != "/d/c"), None);
        let mut second = chunk(&["d", "e/"], true);
        second.dropped = 1;
        second.vanished = 4;
        assert_eq!(lister.take(&second, |_| false), Some(End::Complete));
        assert_eq!(
            lister.trail(&End::Complete, Delivery::Released),
            "listing: 5 received, 1 skipped by the cursor, 1 invalid, 2 withheld, 1 permitted, 1 released; the subject reports 3 non-UTF-8 names dropped and 4 vanished (unverified)"
        );
        assert!(lister
            .trail(&End::Refused(ORDER_VIOLATED), Delivery::Withheld)
            .contains("1 permitted, 0 released"));
    }

    #[test]
    fn the_trail_counts_the_entry_that_closed_a_page_as_permitted_but_not_released() {
        let names: Vec<String> = (0..3).map(|i| format!("{i}{}", "z".repeat(300))).collect();
        let mut lister = Lister::new("/d".into(), None, 900);
        assert_eq!(
            lister.take(&chunk_of(&names, true), |_| true),
            Some(End::Truncated)
        );
        assert!(
            lister
                .trail(&End::Truncated, Delivery::Released)
                .contains("3 permitted, 2 released"),
            "{}",
            lister.trail(&End::Truncated, Delivery::Released)
        );
        let names = numbered(0, LIST_RELEASE_MAX + 1);
        let mut lister = Lister::new("/d".into(), None, maknae_proto::ATTEMPT_RESPONSE_MAX);
        lister.take(&chunk_of(&names, true), |_| true);
        assert!(lister
            .trail(&End::Truncated, Delivery::Released)
            .contains("1025 permitted, 1024 released"));
    }
}
