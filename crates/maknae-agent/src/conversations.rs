//! `maknae session list`: all pages, then the client-side `--cwd` filter.
use crate::wire::WireOutcome;
use maknae_proto::{ConversationId, ConversationPage, ConversationView, Payload, Verb};
use std::future::Future;
use std::path::Path;

pub const MAX_LIST_PAGES: usize = 64;

pub async fn list_all<F, Fut>(mut send: F) -> Result<Vec<ConversationView>, String>
where
    F: FnMut(Verb) -> Fut,
    Fut: Future<Output = Result<WireOutcome, String>>,
{
    let mut entries = Vec::new();
    let mut cursor: Option<ConversationId> = None;
    for _ in 0..MAX_LIST_PAGES {
        let page = list_page(
            send(Verb::SessionList {
                cursor: cursor.clone(),
            })
            .await,
        )?;
        entries.extend(page.entries);
        match page.next {
            None => return Ok(entries),
            Some(next) if cursor.as_ref().is_some_and(|c| next <= *c) => {
                return Err(
                    "protocol error: the daemon's session.list cursor did not advance".into(),
                )
            }
            Some(next) => cursor = Some(next),
        }
    }
    Err(format!(
        "protocol error: the daemon's session.list exceeded {MAX_LIST_PAGES} pages"
    ))
}

fn list_page(sent: Result<WireOutcome, String>) -> Result<ConversationPage, String> {
    match sent {
        Ok(WireOutcome::Payload(Payload::ConversationList(page))) => Ok(page),
        Ok(WireOutcome::Refused { code, message, .. }) => {
            Err(format!("daemon refused: {code:?}: {message}"))
        }
        Ok(other) => Err(format!(
            "protocol error: unexpected reply to session.list: {other:?}"
        )),
        Err(m) => Err(m),
    }
}

pub fn in_cwd(entries: Vec<ConversationView>, cwd: Option<&Path>) -> Vec<ConversationView> {
    match cwd {
        None => entries,
        Some(cwd) => entries
            .into_iter()
            .filter(|v| Path::new(&v.cwd) == cwd)
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    fn id(n: u8) -> ConversationId {
        ConversationId::parse(&format!("{n:032x}")).unwrap()
    }

    fn view(n: u8, cwd: &str) -> ConversationView {
        ConversationView {
            conversation: id(n),
            cwd: cwd.into(),
            opened_at: 1,
            last_active: 2,
            turns: 3,
            bytes: 4,
            chain_head: "h".into(),
        }
    }

    fn page(entries: Vec<ConversationView>, next: Option<u8>) -> Result<WireOutcome, String> {
        Ok(WireOutcome::Payload(Payload::ConversationList(
            ConversationPage {
                entries,
                next: next.map(id),
            },
        )))
    }

    async fn scripted(
        replies: Vec<Result<WireOutcome, String>>,
    ) -> (Result<Vec<ConversationView>, String>, Vec<Verb>) {
        let mut replies: VecDeque<_> = replies.into();
        let mut sent = vec![];
        let listed = list_all(|v| {
            sent.push(v);
            let r = replies.pop_front().expect("script exhausted");
            async move { r }
        })
        .await;
        (listed, sent)
    }

    #[tokio::test]
    async fn session_list_filters_by_cwd_client_side() {
        let (listed, sent) = scripted(vec![
            page(
                vec![view(1, "/home/a/w"), view(2, "/home/a/other")],
                Some(2),
            ),
            page(vec![view(3, "/home/a/w/sub"), view(4, "/home/a/w/")], None),
        ])
        .await;
        assert_eq!(
            sent,
            vec![
                Verb::SessionList { cursor: None },
                Verb::SessionList {
                    cursor: Some(id(2))
                },
            ]
        );
        let all = listed.unwrap();
        assert_eq!(all.len(), 4);
        let here: Vec<_> = in_cwd(all.clone(), Some(Path::new("/home/a/w")))
            .into_iter()
            .map(|v| v.conversation)
            .collect();
        assert_eq!(here, vec![id(1), id(4)]);
        assert_eq!(in_cwd(all.clone(), None), all);
        assert!(in_cwd(all, Some(Path::new("/home/a"))).is_empty());
    }

    #[tokio::test]
    async fn a_cursor_that_does_not_advance_is_a_protocol_error() {
        let (listed, sent) = scripted(vec![
            page(vec![view(5, "/w")], Some(5)),
            page(vec![view(6, "/w")], Some(5)),
        ])
        .await;
        assert_eq!(
            listed,
            Err("protocol error: the daemon's session.list cursor did not advance".into())
        );
        assert_eq!(sent.len(), 2);
        let (listed, _) = scripted(vec![page(vec![], Some(5)), page(vec![], Some(4))]).await;
        assert!(listed.unwrap_err().contains("did not advance"));
        let (listed, sent) = scripted(vec![
            page(vec![], Some(5)),
            page(vec![], Some(6)),
            page(vec![], None),
        ])
        .await;
        assert_eq!(listed, Ok(vec![]));
        assert_eq!(sent.len(), 3);
    }

    #[tokio::test]
    async fn an_endless_advancing_cursor_stops_at_the_page_cap_with_an_error() {
        let mut sent = 0usize;
        let listed = list_all(|_| {
            sent += 1;
            let n = u8::try_from(sent).unwrap();
            async move { page(vec![], Some(n)) }
        })
        .await;
        assert_eq!(
            listed,
            Err(format!(
                "protocol error: the daemon's session.list exceeded {MAX_LIST_PAGES} pages"
            ))
        );
        assert_eq!(sent, MAX_LIST_PAGES);
    }

    #[tokio::test]
    async fn the_last_allowed_page_may_end_the_listing() {
        let mut sent = 0usize;
        let listed = list_all(|_| {
            sent += 1;
            let next = (sent < MAX_LIST_PAGES).then(|| u8::try_from(sent).unwrap());
            async move { page(vec![], next) }
        })
        .await;
        assert_eq!(listed, Ok(vec![]));
        assert_eq!(sent, MAX_LIST_PAGES);
    }

    #[tokio::test]
    async fn a_refused_or_unexpected_page_ends_the_listing() {
        let (listed, sent) = scripted(vec![
            page(vec![view(1, "/w")], Some(1)),
            Ok(WireOutcome::Refused {
                code: maknae_proto::ProtoErrCode::Unauthorized,
                message: "not authorized".into(),
                armed: true,
            }),
        ])
        .await;
        assert_eq!(
            listed,
            Err("daemon refused: Unauthorized: not authorized".into())
        );
        assert_eq!(sent.len(), 2);
        let (listed, _) = scripted(vec![Ok(WireOutcome::Payload(Payload::Pong))]).await;
        assert_eq!(
            listed,
            Err("protocol error: unexpected reply to session.list: Payload(Pong)".into())
        );
        let (listed, _) = scripted(vec![Err("connection reset".into())]).await;
        assert_eq!(listed, Err("connection reset".into()));
    }
}
