mod common;
use common::{Fixture, Records};
use maknae_kernel::{ConversationRecord, ConversationStore, ConversationStoreError as StoreError};
use maknae_proto::{
    ContentBlock, ConversationId, Payload, PromptReply, ProtoErrCode, RespResult, Response,
    SecretText, Turn, Verb,
};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const GRANTS: &str = "roles:\n  user:\n    allow: [\"session.prompt\", \"session.new\", \"session.close\", \"session.list\", \"session.delete\"]\ndestinations:\n  user:\n    allow: [\"provider:openai\"]\n";
const SHIPPED_POLICY: &str = include_str!("../../../packaging/common/authz.yaml");
const FOREIGN_UID: u32 = 4_170_999;
const FOREIGN_ID: &str = "f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0";
const MAX_BYTES: u64 = 256 << 20;
const OWNER_MAX: usize = 32;

fn text(s: &str) -> ContentBlock {
    ContentBlock::Text {
        text: SecretText(maknae_io::Zeroizing::new(s.into())),
    }
}
fn user(s: &str) -> Turn {
    Turn::User {
        content: vec![text(s)],
    }
}
fn said(r: &PromptReply) -> Turn {
    Turn::Assistant {
        content: r.blocks.clone(),
        tool_calls: r.tool_calls.clone(),
        reasoning: None,
    }
}
fn reply(s: &str) -> PromptReply {
    PromptReply {
        blocks: vec![text(s)],
        tool_calls: vec![],
        usage: None,
        reasoning: None,
    }
}
fn prompt(id: &str, turns: Vec<Turn>) -> Verb {
    Verb::SessionPrompt {
        conversation: id.into(),
        turns,
        output_tokens: None,
        choice: Some(common::test_choice()),
    }
}
fn id(s: &str) -> ConversationId {
    ConversationId::parse(s).unwrap()
}

#[derive(Default)]
struct Script {
    replies: Mutex<VecDeque<Result<PromptReply, maknae_kernel::EgressFailure>>>,
    sends: AtomicUsize,
    sleep: Option<Duration>,
}
impl Script {
    fn of(
        items: impl IntoIterator<Item = Result<PromptReply, maknae_kernel::EgressFailure>>,
    ) -> Arc<Self> {
        let s = Self::default();
        s.replies.lock().unwrap().extend(items);
        Arc::new(s)
    }
    fn sends(&self) -> usize {
        self.sends.load(Ordering::SeqCst)
    }
}
impl maknae_kernel::Egress for Script {
    fn ready(&self) -> Result<(), maknae_kernel::EgressFailure> {
        Ok(())
    }
    fn deadline(&self) -> Duration {
        Duration::from_secs(5)
    }
    fn send(
        &self,
        _: &maknae_kernel::DurableEgressIntent,
        _: maknae_kernel::EgressRequest,
    ) -> Result<maknae_kernel::EgressReply, maknae_kernel::EgressFailure> {
        self.sends.fetch_add(1, Ordering::SeqCst);
        if let Some(d) = self.sleep {
            std::thread::sleep(d);
        }
        let next = self.replies.lock().unwrap().pop_front();
        next.unwrap_or(Err(maknae_kernel::EgressFailure::Transport(
            "script exhausted".into(),
        )))
        .map(|reply| maknae_kernel::EgressReply { reply })
    }
}

enum Kind {
    Mem,
    Dir,
}

struct Rig {
    fx: Fixture,
    dir: Option<tempfile::TempDir>,
}

fn dir_store(dir: &std::path::Path) -> Arc<dyn ConversationStore> {
    let key = maknae_state::envelope::WrappingKey::new(maknae_io::Zeroizing::new(
        [0x17u8; maknae_state::envelope::KEY_LEN],
    ));
    Arc::new(maknae_kernel::DirStore::open(dir, nix::unistd::geteuid().as_raw(), key).unwrap())
}

impl Rig {
    fn new(tag: &str, kind: Kind) -> Self {
        Self::with_rules(tag, kind, &[], GRANTS)
    }
    fn with_rules(tag: &str, kind: Kind, denies: &[&str], tail: &str) -> Self {
        let mut fx = Fixture::with_rules(&format!("conv-{tag}"), &["Read"], denies, tail);
        let dir = match kind {
            Kind::Mem => {
                fx.conversations = common::conversations();
                None
            }
            Kind::Dir => {
                let dir = tempfile::tempdir().unwrap();
                std::fs::set_permissions(
                    dir.path(),
                    std::os::unix::fs::PermissionsExt::from_mode(0o700),
                )
                .unwrap();
                fx.conversations = dir_store(dir.path());
                Some(dir)
            }
        };
        Self { fx, dir }
    }
    fn reopen(&mut self) {
        let dir = self.dir.as_ref().expect("a directory store");
        self.fx.conversations = common::conversations();
        self.fx.conversations = dir_store(dir.path());
    }
    fn under_shipped(self, role: &str) -> Self {
        let paths = self.fx.paths();
        common::write_0640(&paths.authz, SHIPPED_POLICY);
        let name = self.fx.peer_user.clone().unwrap();
        common::write_0640(
            &paths.bindings,
            &format!("schema_version: 1\nbindings:\n  {role}: [\"{name}\"]\n"),
        );
        self
    }
    fn store(&self) -> &dyn ConversationStore {
        &*self.fx.conversations
    }
    fn uid(&self) -> u32 {
        self.fx.peer_uid
    }
    fn cwd(&self) -> std::path::PathBuf {
        let cwd = self.fx.root.join("work");
        std::fs::create_dir_all(&cwd).unwrap();
        cwd
    }
    fn seed(&self, rec: ConversationRecord) {
        self.store().create(rec, usize::MAX).unwrap();
    }
    fn held(&self) -> Vec<ConversationRecord> {
        self.store()
            .list_by_owner(self.uid(), None, usize::MAX)
            .unwrap()
            .value
            .0
    }
    async fn send(
        &self,
        verb: Verb,
        fd: Option<std::os::fd::OwnedFd>,
        records: &Arc<Records>,
        egress: Arc<dyn maknae_kernel::Egress>,
    ) -> Option<Response> {
        let (client, task, body) = self.fx.start_egress(
            verb,
            fd,
            Arc::clone(records),
            maknae_config::transport_from_section(None).unwrap(),
            Some("openai"),
            egress,
        );
        Fixture::exchange(client, task, &body).await
    }
    async fn control(&self, verb: Verb, records: &Arc<Records>) -> Option<Response> {
        self.send(verb, None, records, maknae_kernel::unavailable_egress())
            .await
    }
    async fn new_at(
        &self,
        cwd: &std::path::Path,
        fd: Option<std::os::fd::OwnedFd>,
        records: &Arc<Records>,
    ) -> Option<Response> {
        self.new_listing(cwd, fd, vec![], records).await
    }
    async fn new_listing(
        &self,
        cwd: &std::path::Path,
        fd: Option<std::os::fd::OwnedFd>,
        sensitive: Vec<String>,
        records: &Arc<Records>,
    ) -> Option<Response> {
        self.send(
            Verb::SessionNew {
                cwd: cwd.to_str().unwrap().into(),
                sensitive,
            },
            fd,
            records,
            maknae_kernel::unavailable_egress(),
        )
        .await
    }
    async fn open(&self) -> String {
        self.open_listing(vec![]).await
    }
    async fn open_listing(&self, sensitive: Vec<String>) -> String {
        let cwd = self.cwd();
        let fd = maknae_io::open_directory_for_delegation(&cwd).unwrap();
        match self
            .new_listing(&cwd, Some(fd), sensitive, &Records::new(0))
            .await
            .unwrap()
            .result
        {
            RespResult::Ok(Payload::ConversationOpened(v)) => v.conversation.as_str().to_owned(),
            other => panic!("session.new refused: {other:?}"),
        }
    }
    async fn read_runs(
        &self,
        target: &std::path::Path,
        conversation: Option<&str>,
    ) -> Option<maknae_proto::ReportedFinish> {
        let held = maknae_io::open_path_for_delegation(target).unwrap();
        let (mut client, task, body) = self.fx.start(
            Verb::Read {
                path: target.to_str().unwrap().into(),
                conversation: conversation.map(str::to_owned),
                page: None,
            },
            Some(held.try_clone().unwrap()),
            Records::new(0),
        );
        common::write_frame(&mut client, &body).await.unwrap();
        let run = common::read_as_subject(&mut client, Some(&held)).await;
        drop(client);
        task.await.unwrap();
        run.finish
    }
    async fn read_refused(
        &self,
        target: &std::path::Path,
        conversation: &str,
    ) -> (Response, maknae_audit_append::AuditRecord) {
        let records = Records::new(0);
        let fd = maknae_io::open_path_for_delegation(target).unwrap();
        let resp = self
            .send(
                Verb::Read {
                    path: target.to_str().unwrap().into(),
                    conversation: Some(conversation.into()),
                    page: None,
                },
                Some(fd),
                &records,
                maknae_kernel::unavailable_egress(),
            )
            .await
            .unwrap();
        refused_with(&resp, ProtoErrCode::Unauthorized);
        let rec = last_of(&records, "fs.read");
        assert!(rec.mutation.is_none(), "{rec:?}");
        (resp, rec)
    }
    async fn ask(&self, id: &str, turns: Vec<Turn>, egress: &Arc<Script>) -> Response {
        self.send(prompt(id, turns), None, &Records::new(0), egress.clone())
            .await
            .expect("a prompt frame")
    }
}

fn delivered(resp: &Response) -> PromptReply {
    match &resp.result {
        RespResult::Ok(Payload::PromptReply(r)) => r.clone(),
        other => panic!("expected a reply: {other:?}"),
    }
}
fn refused_with(resp: &Response, code: ProtoErrCode) {
    match &resp.result {
        RespResult::Err(e) => assert_eq!(e.code, code, "{e:?}"),
        other => panic!("expected {code:?}: {other:?}"),
    }
}
fn last_of(records: &Records, action: &str) -> maknae_audit_append::AuditRecord {
    records
        .snapshot()
        .into_iter()
        .rev()
        .find(|r| r.action == action)
        .unwrap_or_else(|| panic!("a {action} record"))
}
fn of_action(records: &Records, action: &str) -> Vec<maknae_audit_append::AuditRecord> {
    records
        .snapshot()
        .into_iter()
        .filter(|r| r.action == action)
        .collect()
}

#[tokio::test]
async fn new_then_prompt_then_close_round_trip() {
    for kind in [Kind::Mem, Kind::Dir] {
        let rig = Rig::new("round-trip", kind);
        let conv = rig.open().await;
        let eg = Script::of([Ok(reply("one")), Ok(reply("two"))]);
        let first = delivered(&rig.ask(&conv, vec![user("a")], &eg).await);
        let second = rig
            .ask(&conv, vec![user("a"), said(&first), user("b")], &eg)
            .await;
        assert_eq!(delivered(&second).blocks.len(), 1);
        let records = Records::new(0);
        let closed = rig
            .control(
                Verb::SessionClose {
                    conversation: id(&conv),
                },
                &records,
            )
            .await
            .unwrap();
        match closed.result {
            RespResult::Ok(Payload::ConversationClosed(v)) => {
                assert_eq!(v.conversation.as_str(), conv);
                assert_eq!(v.turns, 3);
                assert!(v.bytes > 0);
            }
            other => panic!("{other:?}"),
        }
        assert!(rig.held().is_empty());
        assert_eq!(eg.sends(), 2);
    }
}

#[tokio::test]
async fn a_cwd_outside_the_home_opens_and_is_recorded_as_the_kernel_reports_it() {
    let rig = Rig::with_rules("outside-cwd", Kind::Mem, &["Read(~/secret/**)"], GRANTS);
    let outside = tempfile::tempdir().unwrap();
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
    let outside_kernel = maknae_io::resolve_dir(outside.path()).unwrap();
    assert!(!outside_kernel.starts_with(&rig.fx.root));
    if let Some(home) = home.and_then(|h| maknae_io::resolve_dir(&h).ok()) {
        assert!(!outside_kernel.starts_with(home), "{outside_kernel:?}");
    }
    let secret = rig.fx.root.join("secret/x");
    std::fs::create_dir_all(&secret).unwrap();
    for asked in [outside.path().to_path_buf(), secret] {
        let records = Records::new(0);
        let fd = maknae_io::open_directory_for_delegation(&asked).unwrap();
        let resp = rig.new_at(&asked, Some(fd), &records).await.unwrap();
        let RespResult::Ok(Payload::ConversationOpened(view)) = resp.result else {
            panic!("{asked:?}: {resp:?}")
        };
        let kernel = maknae_io::resolve_dir(&asked).unwrap();
        assert_eq!(view.cwd, kernel.to_str().unwrap());
        assert_eq!(
            rig.store().get(&view.conversation).unwrap().cwd,
            kernel.to_str().unwrap()
        );
        let intent = &of_action(&records, "session.new")[0];
        assert_eq!(intent.outcome.result, "permit");
        assert_eq!(intent.object.as_deref(), kernel.to_str());
    }
    assert_eq!(rig.held().len(), 2);
}

#[tokio::test]
async fn a_non_directory_cwd_descriptor_is_refused() {
    let rig = Rig::new("non-dir-cwd", Kind::Mem);
    let file = rig.fx.root.join("a-file");
    std::fs::write(&file, b"f").unwrap();
    let cases: Vec<(std::path::PathBuf, Option<std::os::fd::OwnedFd>, &str)> = vec![
        (
            file.clone(),
            Some(maknae_io::open_path_for_delegation(&file).unwrap()),
            "cwd evidence refused",
        ),
        (rig.cwd(), None, "cwd descriptor missing"),
    ];
    for (cwd, fd, why) in cases {
        let records = Records::new(0);
        let resp = rig.new_at(&cwd, fd, &records).await.unwrap();
        refused_with(&resp, ProtoErrCode::Unauthorized);
        let rec = last_of(&records, "session.new");
        assert_eq!(rec.outcome.result, "deny");
        assert!(rec.outcome.reason.contains(why), "{why}: {rec:?}");
        assert!(rig.held().is_empty(), "{why}");
    }
}

#[tokio::test]
async fn a_subject_without_the_grant_never_has_its_cwd_verified() {
    let rig = Rig::with_rules(
        "ungranted-cwd",
        Kind::Mem,
        &[],
        "roles:\n  user:\n    allow: [\"session.list\"]\n",
    );
    let file = rig.fx.root.join("a-file");
    std::fs::write(&file, b"f").unwrap();
    let cases: Vec<(std::path::PathBuf, Option<std::os::fd::OwnedFd>)> = vec![
        (
            file.clone(),
            Some(maknae_io::open_path_for_delegation(&file).unwrap()),
        ),
        (rig.cwd(), None),
        (std::path::PathBuf::from("relative"), None),
    ];
    for (cwd, fd) in cases {
        let records = Records::new(0);
        let resp = rig.new_at(&cwd, fd, &records).await.unwrap();
        refused_with(&resp, ProtoErrCode::Unauthorized);
        let rec = last_of(&records, "session.new");
        assert_eq!(rec.outcome.result, "deny");
        assert_eq!(
            rec.outcome.reason, "role user: no rule for session.new",
            "{cwd:?}"
        );
        assert!(rec.object.is_none(), "{rec:?}");
    }
    assert!(rig.held().is_empty());
}

#[tokio::test]
async fn a_symlinked_cwd_is_recorded_as_its_target() {
    let rig = Rig::new("symlink-cwd", Kind::Mem);
    let real = rig.fx.root.join("real");
    std::fs::create_dir_all(&real).unwrap();
    let link = rig.fx.root.join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let records = Records::new(0);
    let fd = maknae_io::open_directory_for_delegation(&link).unwrap();
    let resp = rig.new_at(&link, Some(fd), &records).await.unwrap();
    let RespResult::Ok(Payload::ConversationOpened(view)) = resp.result else {
        panic!("{resp:?}")
    };
    assert_eq!(view.cwd, real.to_str().unwrap());
    let intent = &of_action(&records, "session.new")[0];
    assert_eq!(intent.object.as_deref(), real.to_str());
    assert_eq!(intent.object_requested.as_deref(), link.to_str());
    assert_eq!(rig.held()[0].cwd, real.to_str().unwrap());
}

#[tokio::test]
async fn prompt_after_close_is_denied() {
    let rig = Rig::new("after-close", Kind::Mem);
    let conv = rig.open().await;
    rig.control(
        Verb::SessionClose {
            conversation: id(&conv),
        },
        &Records::new(0),
    )
    .await
    .unwrap();
    let eg = Script::of([Ok(reply("x"))]);
    let records = Records::new(0);
    let resp = rig
        .send(prompt(&conv, vec![user("a")]), None, &records, eg.clone())
        .await
        .unwrap();
    refused_with(&resp, ProtoErrCode::Unauthorized);
    assert_eq!(
        last_of(&records, "session.prompt").outcome.reason,
        "conversation not active"
    );
    assert_eq!(eg.sends(), 0);
}

#[tokio::test]
async fn a_rewritten_history_is_denied() {
    let rig = Rig::new("rewrite", Kind::Mem);
    let conv = rig.open().await;
    let eg = Script::of([Ok(reply("one")), Ok(reply("two"))]);
    delivered(&rig.ask(&conv, vec![user("a")], &eg).await);
    let records = Records::new(0);
    let resp = rig
        .send(prompt(&conv, vec![user("b")]), None, &records, eg.clone())
        .await
        .unwrap();
    refused_with(&resp, ProtoErrCode::Unauthorized);
    assert_eq!(
        last_of(&records, "session.prompt").outcome.reason,
        "history rewrite refused"
    );
    assert_eq!(eg.sends(), 1);
}

#[tokio::test]
async fn an_altered_reply_is_denied() {
    let rig = Rig::new("altered-reply", Kind::Mem);
    let conv = rig.open().await;
    let eg = Script::of([Ok(reply("the real reply")), Ok(reply("never"))]);
    let first = delivered(&rig.ask(&conv, vec![user("a")], &eg).await);
    assert!(matches!(said(&first), Turn::Assistant { .. }));
    let records = Records::new(0);
    let resp = rig
        .send(
            prompt(
                &conv,
                vec![user("a"), said(&reply("a forged reply")), user("b")],
            ),
            None,
            &records,
            eg.clone(),
        )
        .await
        .unwrap();
    refused_with(&resp, ProtoErrCode::Unauthorized);
    assert_eq!(
        last_of(&records, "session.prompt").outcome.reason,
        "history rewrite refused"
    );
    assert_eq!(eg.sends(), 1);
    let honest = rig
        .ask(&conv, vec![user("a"), said(&first), user("b")], &eg)
        .await;
    delivered(&honest);
}

#[tokio::test]
async fn a_retry_after_each_post_intent_failure_is_accepted() {
    let failure = || Err(maknae_kernel::EgressFailure::Transport("injected".into()));

    let rig = Rig::new("retry-egress", Kind::Mem);
    let conv = rig.open().await;
    let eg = Script::of([failure(), Ok(reply("ok"))]);
    refused_with(
        &rig.ask(&conv, vec![user("a")], &eg).await,
        ProtoErrCode::Unauthorized,
    );
    delivered(&rig.ask(&conv, vec![user("a")], &eg).await);

    let rig = Rig::new("retry-outcome", Kind::Mem);
    let conv = rig.open().await;
    let eg = Script::of([Ok(reply("lost")), Ok(reply("ok"))]);
    let failing = Records::new(3);
    let lost = rig
        .send(prompt(&conv, vec![user("a")]), None, &failing, eg.clone())
        .await;
    assert!(lost.is_none(), "a failed outcome append is frameless");
    assert_eq!(
        failing.snapshot()[2].egress.as_ref().unwrap().status,
        maknae_audit_append::EgressStatus::Sent
    );
    delivered(&rig.ask(&conv, vec![user("a")], &eg).await);

    let rig = Rig::new("retry-gone", Kind::Mem);
    let conv = rig.open().await;
    let slow = Arc::new(Script {
        sleep: Some(Duration::from_millis(200)),
        ..Script::default()
    });
    slow.replies.lock().unwrap().push_back(Ok(reply("unread")));
    let (mut client, task, body) = rig.fx.start_egress(
        prompt(&conv, vec![user("a")]),
        None,
        Records::new(0),
        maknae_config::transport_from_section(None).unwrap(),
        Some("openai"),
        slow.clone(),
    );
    common::write_frame(&mut client, &body).await.unwrap();
    drop(client);
    task.await.unwrap();
    assert_eq!(slow.sends(), 1);
    let eg = Script::of([Ok(reply("ok"))]);
    delivered(&rig.ask(&conv, vec![user("a")], &eg).await);

    let mut rig = Rig::new("retry-reopen", Kind::Dir);
    let conv = rig.open().await;
    let eg = Script::of([failure(), Ok(reply("ok"))]);
    refused_with(
        &rig.ask(&conv, vec![user("a")], &eg).await,
        ProtoErrCode::Unauthorized,
    );
    rig.reopen();
    assert_eq!(rig.held()[0].turns, 1);
    delivered(&rig.ask(&conv, vec![user("a")], &eg).await);
}

#[tokio::test]
async fn a_foreign_owner_cannot_prompt_close_or_delete() {
    let rig = Rig::new("foreign", Kind::Mem);
    rig.seed(common::open_record(FOREIGN_ID, FOREIGN_UID, "/home/other"));
    let eg = Script::of([Ok(reply("never"))]);
    for (verb, action) in [
        (prompt(FOREIGN_ID, vec![user("a")]), "session.prompt"),
        (
            Verb::SessionClose {
                conversation: id(FOREIGN_ID),
            },
            "session.close",
        ),
        (
            Verb::SessionDelete {
                conversation: id(FOREIGN_ID),
            },
            "session.delete",
        ),
    ] {
        let records = Records::new(0);
        let resp = rig.send(verb, None, &records, eg.clone()).await.unwrap();
        refused_with(&resp, ProtoErrCode::Unauthorized);
        assert_eq!(
            last_of(&records, action).outcome.reason,
            "conversation belongs to another subject"
        );
    }
    assert_eq!(eg.sends(), 0);
    assert!(rig.store().get(&id(FOREIGN_ID)).is_ok());
}

#[tokio::test]
async fn list_shows_only_the_callers_conversations_and_audits_the_count_only() {
    let rig = Rig::new("list", Kind::Mem);
    let mine = rig.open().await;
    rig.seed(common::open_record(FOREIGN_ID, FOREIGN_UID, "/home/other"));
    let records = Records::new(0);
    let resp = rig
        .control(Verb::SessionList { cursor: None }, &records)
        .await
        .unwrap();
    let RespResult::Ok(Payload::ConversationList(page)) = resp.result else {
        panic!("{resp:?}")
    };
    assert_eq!(
        page.entries
            .iter()
            .map(|v| v.conversation.as_str())
            .collect::<Vec<_>>(),
        vec![mine.as_str()]
    );
    assert_eq!(page.next, None);
    let rec = last_of(&records, "session.list");
    assert_eq!(rec.outcome.reason, "listed 1 conversations");
    assert_eq!(
        (rec.object.as_deref(), rec.conversation.as_deref()),
        (None, None)
    );
    let trail = serde_json::to_string(&records.snapshot()).unwrap();
    assert!(
        !trail.contains(&mine) && !trail.contains(FOREIGN_ID),
        "{trail}"
    );
}

#[tokio::test]
async fn new_close_and_delete_are_written_ahead() {
    let rig = Rig::new("write-ahead", Kind::Mem);
    let records = Records::new(0);
    let cwd = rig.cwd();
    let fd = maknae_io::open_directory_for_delegation(&cwd).unwrap();
    let RespResult::Ok(Payload::ConversationOpened(view)) =
        rig.new_at(&cwd, Some(fd), &records).await.unwrap().result
    else {
        panic!()
    };
    let conv = view.conversation.as_str().to_owned();
    let pair = |action: &str, records: &Records| {
        let recs = of_action(records, action);
        assert_eq!(recs.len(), 2, "{recs:?}");
        assert_eq!(
            recs[0].outcome.reason.split(';').next(),
            Some("intent recorded")
        );
        assert!(recs[0].seq < recs[1].seq);
        for r in &recs {
            assert_eq!(r.outcome.result, "permit");
            assert_eq!(r.conversation.as_deref(), Some(conv.as_str()));
        }
        recs
    };
    let opened = pair("session.new", &records);
    assert_eq!(opened[1].outcome.reason, "conversation opened");

    let records = Records::new(0);
    rig.control(
        Verb::SessionClose {
            conversation: id(&conv),
        },
        &records,
    )
    .await
    .unwrap();
    let closed = pair("session.close", &records);
    assert_eq!(
        closed[0].outcome.reason,
        format!(
            "intent recorded; head={} turns=0 bytes=0",
            maknae_kernel::ChainHead::genesis(&id(&conv)).to_hex()
        )
    );
    assert_eq!(closed[1].outcome.reason, "conversation closed");

    let records = Records::new(0);
    let resp = rig
        .control(
            Verb::SessionDelete {
                conversation: id(&conv),
            },
            &records,
        )
        .await
        .unwrap();
    assert!(matches!(
        resp.result,
        RespResult::Ok(Payload::ConversationDeleted { ref conversation }) if conversation.as_str() == conv
    ));
    let deleted = pair("session.delete", &records);
    assert_eq!(deleted[0].source.uid, rig.uid());
    assert_eq!(
        deleted[1].outcome.reason,
        "conversation deleted; the kernel held no record"
    );
}

#[tokio::test]
async fn a_failed_append_changes_nothing() {
    let rig = Rig::new("failed-append", Kind::Mem);
    let cwd = rig.cwd();
    let fd = maknae_io::open_directory_for_delegation(&cwd).unwrap();
    assert!(rig.new_at(&cwd, Some(fd), &Records::new(2)).await.is_none());
    assert!(rig.held().is_empty(), "no record without its intent");

    let conv = rig.open().await;
    for verb in [
        Verb::SessionClose {
            conversation: id(&conv),
        },
        Verb::SessionDelete {
            conversation: id(&conv),
        },
    ] {
        assert!(rig.control(verb, &Records::new(2)).await.is_none());
        assert!(rig.store().get(&id(&conv)).is_ok(), "the record survives");
    }
}

#[tokio::test]
async fn the_new_record_names_owner_cwd_and_id() {
    for kind in [Kind::Mem, Kind::Dir] {
        let rig = Rig::new("new-record", kind);
        let conv = rig.open().await;
        let rec = rig.store().get(&id(&conv)).unwrap();
        assert_eq!(rec.id.as_str(), conv);
        assert_eq!(rec.owner, rig.uid());
        assert_eq!(rec.cwd, rig.cwd().to_str().unwrap());
        assert_eq!(rec.chain, maknae_kernel::ChainHead::genesis(&rec.id));
        assert_eq!(
            (rec.turns, rec.bytes, rec.fence, rec.full),
            (0, 0, 0, false)
        );
        assert_eq!(rec.last_reply, None);
        assert_eq!(
            rec.provenance,
            maknae_kernel::Provenance::new("UNCLASSIFIED")
        );
    }
}

struct Racing {
    inner: Arc<dyn ConversationStore>,
    lose_at: usize,
    updates: AtomicUsize,
    remove_stall: Duration,
}
impl Racing {
    fn over(inner: &Arc<dyn ConversationStore>, lose_at: usize) -> Arc<Self> {
        Arc::new(Self {
            inner: Arc::clone(inner),
            lose_at,
            updates: AtomicUsize::new(0),
            remove_stall: Duration::ZERO,
        })
    }
}
impl ConversationStore for Racing {
    fn create(
        &self,
        rec: ConversationRecord,
        max: usize,
    ) -> Result<maknae_kernel::Scan<()>, StoreError> {
        self.inner.create(rec, max)
    }
    fn get(&self, id: &ConversationId) -> Result<ConversationRecord, StoreError> {
        self.inner.get(id)
    }
    fn update(
        &self,
        id: &ConversationId,
        fence: u64,
        f: &mut dyn FnMut(&mut ConversationRecord),
    ) -> Result<ConversationRecord, StoreError> {
        if self.updates.fetch_add(1, Ordering::SeqCst) + 1 == self.lose_at {
            let winner = self.inner.get(id)?;
            self.inner
                .update(id, winner.fence, &mut |r| r.last_active += 1)?;
        }
        self.inner.update(id, fence, f)
    }
    fn remove(&self, id: &ConversationId, fence: u64) -> Result<ConversationRecord, StoreError> {
        std::thread::sleep(self.remove_stall);
        self.inner.remove(id, fence)
    }
    fn list_by_owner(
        &self,
        owner: u32,
        after: Option<&ConversationId>,
        limit: usize,
    ) -> Result<maknae_kernel::Scan<maknae_kernel::Page>, StoreError> {
        self.inner.list_by_owner(owner, after, limit)
    }
    fn idle_for_owner(
        &self,
        owner: u32,
        older_than: u64,
    ) -> Result<maknae_kernel::Scan<Vec<ConversationRecord>>, StoreError> {
        self.inner.idle_for_owner(owner, older_than)
    }
}

#[tokio::test]
async fn a_racing_second_loop_is_refused_before_egress() {
    let mut rig = Rig::new("race", Kind::Mem);
    let conv = rig.open().await;
    rig.fx.conversations = Racing::over(&rig.fx.conversations, 1);
    let eg = Script::of([Ok(reply("never"))]);
    let records = Records::new(0);
    let resp = rig
        .send(prompt(&conv, vec![user("a")]), None, &records, eg.clone())
        .await
        .unwrap();
    refused_with(&resp, ProtoErrCode::Unauthorized);
    let rec = last_of(&records, "session.prompt");
    assert_eq!(
        rec.outcome.reason,
        "conversation changed before the send: conversation changed since it was read"
    );
    assert!(rec.egress.is_none(), "no egress intent: {rec:?}");
    assert_eq!(eg.sends(), 0);
}

#[tokio::test]
async fn over_the_byte_cap_and_the_owner_count_are_typed_refusals() {
    let too_large = |resp: &Response, message: &str| match &resp.result {
        RespResult::Err(e) => assert_eq!(
            (e.code.clone(), e.message.as_str()),
            (ProtoErrCode::TooLarge, message)
        ),
        other => panic!("{other:?}"),
    };

    let rig = Rig::new("cap-request", Kind::Mem);
    let mut nearly = common::open_record(common::CONV, rig.uid(), "/w");
    nearly.bytes = MAX_BYTES - 1;
    rig.seed(nearly);
    let eg = Script::of([Ok(reply("never"))]);
    too_large(
        &rig.ask(common::CONV, vec![user("a")], &eg).await,
        "conversation is full",
    );
    assert_eq!(eg.sends(), 0);

    let rig = Rig::new("cap-reply", Kind::Mem);
    let mut nearly = common::open_record(common::CONV, rig.uid(), "/w");
    nearly.bytes = MAX_BYTES - 200;
    rig.seed(nearly);
    let eg = Script::of([Ok(reply(&"r".repeat(1000))), Ok(reply("never"))]);
    let records = Records::new(0);
    let resp = rig
        .send(
            prompt(common::CONV, vec![user("a")]),
            None,
            &records,
            eg.clone(),
        )
        .await
        .unwrap();
    too_large(&resp, "conversation is full");
    let outcome = last_of(&records, "session.prompt");
    assert_eq!(outcome.outcome.reason, "reply refused: conversation full");
    assert_eq!(
        outcome.egress.unwrap().status,
        maknae_audit_append::EgressStatus::LandedUndelivered
    );
    assert!(rig.store().get(&id(common::CONV)).unwrap().full);
    too_large(
        &rig.ask(common::CONV, vec![user("a")], &eg).await,
        "conversation is full",
    );
    assert_eq!(
        eg.sends(),
        1,
        "a retry on a full conversation never re-bills the provider"
    );

    let rig = Rig::new("owner-count", Kind::Mem);
    for n in 0..OWNER_MAX {
        rig.seed(common::open_record(&format!("{n:032x}"), rig.uid(), "/w"));
    }
    let records = Records::new(0);
    let cwd = rig.cwd();
    let fd = maknae_io::open_directory_for_delegation(&cwd).unwrap();
    too_large(
        &rig.new_at(&cwd, Some(fd), &records).await.unwrap(),
        "too many active conversations",
    );
    let recs = of_action(&records, "session.new");
    assert_eq!(recs.len(), 2, "intent and its corrective outcome: {recs:?}");
    assert_eq!(recs[1].outcome.reason, "too many active conversations");
    assert_eq!(rig.held().len(), OWNER_MAX);
}

#[tokio::test]
async fn an_idle_conversation_is_closed_with_reason_idle_and_frees_the_count() {
    for kind in [Kind::Mem, Kind::Dir] {
        let rig = Rig::new("idle", kind);
        let mut stale = common::open_record(common::CONV, rig.uid(), "/w");
        stale.last_active = common::now() - 24 * 60 * 60 - 1;
        rig.seed(stale);
        for n in 1..OWNER_MAX {
            rig.seed(common::open_record(&format!("{n:032x}"), rig.uid(), "/w"));
        }
        let records = Records::new(0);
        let cwd = rig.cwd();
        let fd = maknae_io::open_directory_for_delegation(&cwd).unwrap();
        let resp = rig.new_at(&cwd, Some(fd), &records).await.unwrap();
        assert!(
            matches!(resp.result, RespResult::Ok(Payload::ConversationOpened(_))),
            "{resp:?}"
        );
        let idle = of_action(&records, "session.close");
        assert_eq!(idle.len(), 2, "{idle:?}");
        assert!(idle[0].outcome.reason.starts_with("idle; intent recorded"));
        assert_eq!(idle[1].outcome.reason, "idle; conversation closed");
        assert_eq!(idle[0].conversation.as_deref(), Some(common::CONV));
        assert!(rig.store().get(&id(common::CONV)).is_err());
        assert_eq!(rig.held().len(), OWNER_MAX);
    }
}

#[tokio::test]
async fn session_close_does_not_drop_the_connection() {
    let rig = Rig::new("close-keeps", Kind::Mem);
    let conv = rig.open().await;
    let session = Arc::new(rig.fx.session());
    let (client, task, body) = rig.fx.start_in_session(
        Arc::clone(&session),
        Verb::SessionClose {
            conversation: id(&conv),
        },
        None,
        Records::new(0),
    );
    let resp = Fixture::exchange(client, task, &body).await.unwrap();
    assert!(matches!(
        resp.result,
        RespResult::Ok(Payload::ConversationClosed(_))
    ));
    assert_eq!(session.ending(), maknae_kernel::Ending::Disconnect);
}

#[tokio::test]
async fn a_conversation_id_is_not_a_connection_id() {
    let rig = Rig::new("not-a-session", Kind::Mem);
    let conv = rig.open().await;
    let session_id = rig.fx.session().session_id;
    assert_eq!(ConversationId::parse(&session_id.to_string()), None);
    assert_ne!(conv, format!("{session_id:032x}"));
    assert_eq!(
        ConversationId::parse(&conv).map(|c| c.as_str().len()),
        Some(32)
    );
}

#[tokio::test]
async fn an_unknown_verb_still_fails_closed_as_decode() {
    let mut raw = vec![0xa2];
    for (k, v) in [
        ("protocol_version", None),
        ("verb", Some("SessionFrobnicate")),
    ] {
        raw.push(0x60 | k.len() as u8);
        raw.extend_from_slice(k.as_bytes());
        match v {
            None => raw.push(0x01),
            Some(v) => {
                raw.push(0x60 | v.len() as u8);
                raw.extend_from_slice(v.as_bytes());
            }
        }
    }
    assert!(maknae_proto::decode_request(&raw).is_err());
    let rig = Rig::new("unknown-verb", Kind::Mem);
    let records = Records::new(0);
    let resp = rig
        .fx
        .roundtrip_raw(
            &raw,
            Arc::clone(&records),
            Some("openai"),
            maknae_kernel::unavailable_egress(),
        )
        .await;
    assert!(resp.is_none());
    let deny = last_of(&records, "decode");
    assert!(
        deny.outcome.reason.starts_with("malformed request"),
        "{deny:?}"
    );
}

#[tokio::test]
async fn fs_read_citing_a_foreign_conversation_is_denied_end_to_end() {
    let rig = Rig::new("fs-foreign", Kind::Mem);
    rig.seed(common::open_record(FOREIGN_ID, FOREIGN_UID, "/home/other"));
    let target = rig.fx.root.join("readable");
    std::fs::write(&target, b"content").unwrap();
    for (cited, want) in [
        (FOREIGN_ID, "conversation belongs to another subject"),
        (
            "ababababababababababababababab00",
            "conversation not active",
        ),
    ] {
        let records = Records::new(0);
        let fd = maknae_io::open_path_for_delegation(&target).unwrap();
        let resp = rig
            .send(
                Verb::Read {
                    path: target.to_str().unwrap().into(),
                    conversation: Some(cited.into()),
                    page: None,
                },
                Some(fd),
                &records,
                maknae_kernel::unavailable_egress(),
            )
            .await
            .unwrap();
        refused_with(&resp, ProtoErrCode::Unauthorized);
        let rec = last_of(&records, "fs.read");
        assert_eq!(rec.outcome.reason, want);
        assert!(rec.mutation.is_none());
    }
}

#[tokio::test]
async fn an_fs_read_citing_the_callers_conversation_touches_it_and_leaves_the_chain() {
    let rig = Rig::new("fs-own", Kind::Mem);
    let conv = rig.open().await;
    let mut before = rig.store().get(&id(&conv)).unwrap();
    rig.store()
        .update(&before.id, before.fence, &mut |r| r.last_active = 7)
        .unwrap();
    before = rig.store().get(&id(&conv)).unwrap();
    let target = rig.fx.root.join("readable");
    std::fs::write(&target, b"content").unwrap();
    let held = maknae_io::open_path_for_delegation(&target).unwrap();
    let (mut client, task, body) = rig.fx.start(
        Verb::Read {
            path: target.to_str().unwrap().into(),
            conversation: Some(conv.clone()),
            page: None,
        },
        Some(held.try_clone().unwrap()),
        Records::new(0),
    );
    common::write_frame(&mut client, &body).await.unwrap();
    let run = common::read_as_subject(&mut client, Some(&held)).await;
    drop(client);
    task.await.unwrap();
    assert_eq!(
        run.finish,
        Some(maknae_proto::ReportedFinish::Success),
        "the read is granted and runs"
    );
    let after = rig.store().get(&id(&conv)).unwrap();
    assert!(after.last_active > 7);
    assert_eq!(
        (after.chain, after.turns, after.bytes),
        (before.chain, before.turns, before.bytes)
    );
}

#[tokio::test]
async fn a_failed_activity_touch_is_recorded_and_the_read_still_runs() {
    let mut rig = Rig::new("fs-touch-fails", Kind::Mem);
    let conv = rig.open().await;
    rig.fx.conversations = Racing::over(&rig.fx.conversations, 1);
    let target = rig.fx.root.join("readable");
    std::fs::write(&target, b"content").unwrap();
    let held = maknae_io::open_path_for_delegation(&target).unwrap();
    let records = Records::new(0);
    let (mut client, task, body) = rig.fx.start(
        Verb::Read {
            path: target.to_str().unwrap().into(),
            conversation: Some(conv.clone()),
            page: None,
        },
        Some(held.try_clone().unwrap()),
        Arc::clone(&records),
    );
    common::write_frame(&mut client, &body).await.unwrap();
    let run = common::read_as_subject(&mut client, Some(&held)).await;
    drop(client);
    task.await.unwrap();
    assert_eq!(run.finish, Some(maknae_proto::ReportedFinish::Success));
    let noted: Vec<_> = of_action(&records, "fs.read")
        .into_iter()
        .filter(|r| {
            r.outcome
                .reason
                .starts_with("conversation activity not recorded: ")
        })
        .collect();
    assert_eq!(noted.len(), 1, "{:?}", records.snapshot());
    assert_eq!(noted[0].outcome.result, "permit");
}

#[tokio::test]
async fn a_non_local_lane_session_new_is_denied() {
    let rig = Rig::new("remote-lane", Kind::Mem);
    let mut session = rig.fx.session();
    session.lane = maknae_security::Lane::Remote;
    let records = Records::new(0);
    let cwd = rig.cwd();
    let (client, task, body) = rig.fx.start_in_session(
        Arc::new(session),
        Verb::SessionNew {
            cwd: cwd.to_str().unwrap().into(),
            sensitive: vec![],
        },
        Some(maknae_io::open_directory_for_delegation(&cwd).unwrap()),
        Arc::clone(&records),
    );
    let resp = Fixture::exchange(client, task, &body).await.unwrap();
    refused_with(&resp, ProtoErrCode::Unauthorized);
    assert_eq!(
        last_of(&records, "session.new").outcome.reason,
        "session.new requires a local subject"
    );
    assert!(rig.held().is_empty());
}

#[tokio::test]
async fn a_racing_update_after_the_send_withholds_the_reply() {
    let mut rig = Rig::new("race-reply", Kind::Mem);
    let conv = rig.open().await;
    let plain = Arc::clone(&rig.fx.conversations);
    rig.fx.conversations = Racing::over(&plain, 2);
    let eg = Script::of([Ok(reply("withheld"))]);
    let records = Records::new(0);
    let resp = rig
        .send(prompt(&conv, vec![user("a")]), None, &records, eg.clone())
        .await
        .unwrap();
    refused_with(&resp, ProtoErrCode::Unauthorized);
    let outcome = last_of(&records, "session.prompt");
    assert_eq!(
        outcome.outcome.reason,
        "reply refused: conversation changed"
    );
    assert_eq!(
        outcome.egress.unwrap().status,
        maknae_audit_append::EgressStatus::LandedUndelivered
    );
    assert_eq!(eg.sends(), 1);
    let rec = plain.get(&id(&conv)).unwrap();
    assert_eq!((rec.turns, rec.last_reply), (1, None));
}

#[tokio::test]
async fn deleting_an_active_conversation_removes_its_record() {
    let rig = Rig::new("delete-own", Kind::Dir);
    let conv = rig.open().await;
    let records = Records::new(0);
    let resp = rig
        .control(
            Verb::SessionDelete {
                conversation: id(&conv),
            },
            &records,
        )
        .await
        .unwrap();
    assert!(matches!(
        resp.result,
        RespResult::Ok(Payload::ConversationDeleted { ref conversation }) if conversation.as_str() == conv
    ));
    assert_eq!(rig.store().get(&id(&conv)), Err(StoreError::NotFound));
    let recs = of_action(&records, "session.delete");
    assert_eq!(recs.len(), 2, "{recs:?}");
    assert_eq!(recs[1].outcome.reason, "conversation deleted");
    assert_eq!(recs[1].object.as_deref(), rig.cwd().to_str());
}

async fn shipped_session_lifecycle(role: &str) {
    let rig = Rig::new(&format!("shipped-{role}"), Kind::Mem).under_shipped(role);
    let conv = rig.open().await;
    let list = rig
        .control(Verb::SessionList { cursor: None }, &Records::new(0))
        .await
        .unwrap();
    let RespResult::Ok(Payload::ConversationList(page)) = list.result else {
        panic!("{list:?}")
    };
    assert_eq!(page.entries.len(), 1);

    let eg = Script::of([]);
    let records = Records::new(0);
    let resp = rig
        .send(prompt(&conv, vec![user("a")]), None, &records, eg.clone())
        .await
        .unwrap();
    refused_with(&resp, ProtoErrCode::Unauthorized);
    assert_eq!(eg.sends(), 0);
    let denied = last_of(&records, "session.prompt");
    assert_eq!(denied.outcome.result, "deny");
    assert!(
        denied
            .outcome
            .reason
            .contains("destination not allowlisted"),
        "{denied:?}"
    );

    let closed = rig
        .control(
            Verb::SessionClose {
                conversation: id(&conv),
            },
            &Records::new(0),
        )
        .await
        .unwrap();
    assert!(matches!(
        closed.result,
        RespResult::Ok(Payload::ConversationClosed(_))
    ));
    let other = rig.open().await;
    let deleted = rig
        .control(
            Verb::SessionDelete {
                conversation: id(&other),
            },
            &Records::new(0),
        )
        .await
        .unwrap();
    assert!(matches!(
        deleted.result,
        RespResult::Ok(Payload::ConversationDeleted { .. })
    ));
}

#[tokio::test]
async fn the_shipped_policy_lets_admin_run_the_session_verbs_and_stops_a_prompt_at_the_destination_check(
) {
    shipped_session_lifecycle("admin").await;
}

#[tokio::test]
async fn the_shipped_policy_lets_a_user_run_the_session_verbs_and_stops_a_prompt_at_the_destination_check(
) {
    shipped_session_lifecycle("user").await;
}

struct Unflushed(Arc<dyn ConversationStore>);
impl Unflushed {
    fn unflushed() -> StoreError {
        StoreError::NotDurable("sentinel-170-unflushed".into())
    }
}
impl ConversationStore for Unflushed {
    fn create(
        &self,
        rec: ConversationRecord,
        max: usize,
    ) -> Result<maknae_kernel::Scan<()>, StoreError> {
        self.0.create(rec, max)?;
        Err(Self::unflushed())
    }
    fn get(&self, id: &ConversationId) -> Result<ConversationRecord, StoreError> {
        self.0.get(id)
    }
    fn update(
        &self,
        id: &ConversationId,
        fence: u64,
        f: &mut dyn FnMut(&mut ConversationRecord),
    ) -> Result<ConversationRecord, StoreError> {
        self.0.update(id, fence, f)
    }
    fn remove(&self, id: &ConversationId, fence: u64) -> Result<ConversationRecord, StoreError> {
        self.0.remove(id, fence)?;
        Err(Self::unflushed())
    }
    fn list_by_owner(
        &self,
        owner: u32,
        after: Option<&ConversationId>,
        limit: usize,
    ) -> Result<maknae_kernel::Scan<maknae_kernel::Page>, StoreError> {
        self.0.list_by_owner(owner, after, limit)
    }
    fn idle_for_owner(
        &self,
        owner: u32,
        older_than: u64,
    ) -> Result<maknae_kernel::Scan<Vec<ConversationRecord>>, StoreError> {
        self.0.idle_for_owner(owner, older_than)
    }
}

const UNFLUSHED: &str = "outcome unknown: conversation store not flushed: sentinel-170-unflushed";

#[tokio::test]
async fn a_create_that_was_not_flushed_is_refused_as_outcome_unknown() {
    let mut rig = Rig::new("unflushed-new", Kind::Mem);
    let plain = Arc::clone(&rig.fx.conversations);
    rig.fx.conversations = Arc::new(Unflushed(Arc::clone(&plain)));
    let cwd = rig.cwd();
    let records = Records::new(0);
    let fd = maknae_io::open_directory_for_delegation(&cwd).unwrap();
    let resp = rig.new_at(&cwd, Some(fd), &records).await.unwrap();
    refused_with(&resp, ProtoErrCode::Unauthorized);
    let rec = last_of(&records, "session.new");
    assert_eq!(rec.outcome.reason, UNFLUSHED);
    assert_eq!(rec.outcome.posture, "unavailable");
    assert_eq!(
        plain
            .list_by_owner(rig.uid(), None, usize::MAX)
            .unwrap()
            .value
            .0
            .len(),
        1,
        "the record landed, which is why the trail says unknown"
    );
}

#[tokio::test]
async fn a_close_that_was_not_flushed_is_refused_as_outcome_unknown() {
    let mut rig = Rig::new("unflushed-close", Kind::Mem);
    let conv = rig.open().await;
    let plain = Arc::clone(&rig.fx.conversations);
    rig.fx.conversations = Arc::new(Unflushed(Arc::clone(&plain)));
    let records = Records::new(0);
    let resp = rig
        .control(
            Verb::SessionClose {
                conversation: id(&conv),
            },
            &records,
        )
        .await
        .unwrap();
    refused_with(&resp, ProtoErrCode::Unauthorized);
    let rec = last_of(&records, "session.close");
    assert_eq!(rec.outcome.reason, UNFLUSHED);
    assert_eq!(rec.outcome.posture, "unavailable");
}

fn kernel_path(p: &std::path::Path) -> String {
    std::fs::canonicalize(p)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn a_personal_entry_refuses_in_its_conversation() {
    let rig = Rig::new("personal-own", Kind::Mem);
    let a_key = rig.fx.root.join("a-key");
    std::fs::write(&a_key, b"sentinel-617-a").unwrap();
    let entry = kernel_path(&a_key);
    let own = rig.open_listing(vec![entry.clone()]).await;
    let plain = rig.open().await;

    let (resp, rec) = rig.read_refused(&a_key, &own).await;
    assert_eq!(rec.outcome.reason, format!("sensitive: personal {entry}"));
    let RespResult::Err(e) = &resp.result else {
        unreachable!()
    };
    assert!(!e.message.contains(&entry), "{e:?}");

    let ran = Some(maknae_proto::ReportedFinish::Success);
    assert_eq!(rig.read_runs(&a_key, Some(&plain)).await, ran);
    assert_eq!(rig.read_runs(&a_key, None).await, ran);
}

#[tokio::test]
async fn another_subjects_personal_entry_never_reaches_the_requester() {
    let rig = Rig::new("personal-foreign", Kind::Mem);
    let b_key = rig.fx.root.join("b-key");
    std::fs::write(&b_key, b"sentinel-617-b").unwrap();
    let entry = kernel_path(&b_key);
    let mut foreign = common::open_record(FOREIGN_ID, FOREIGN_UID, "/home/other");
    foreign.sensitive = vec![entry.clone()];
    rig.seed(foreign);
    let own = rig.open().await;

    assert_eq!(
        rig.read_runs(&b_key, Some(&own)).await,
        Some(maknae_proto::ReportedFinish::Success)
    );
    let (resp, rec) = rig.read_refused(&b_key, FOREIGN_ID).await;
    assert_eq!(
        rec.outcome.reason,
        "conversation belongs to another subject"
    );
    let RespResult::Err(e) = &resp.result else {
        unreachable!()
    };
    assert!(!e.message.contains(&entry), "{e:?}");
}

#[tokio::test]
async fn a_malformed_personal_entry_refuses_session_new_unauthorized() {
    let rig = Rig::new("personal-malformed", Kind::Mem);
    let cwd = rig.cwd();
    let records = Records::new(0);
    let resp = rig
        .new_listing(
            &cwd,
            Some(maknae_io::open_directory_for_delegation(&cwd).unwrap()),
            vec!["/srv/sentinel-617".into(), "~bob/x".into()],
            &records,
        )
        .await
        .unwrap();
    refused_with(&resp, ProtoErrCode::Unauthorized);
    let rec = last_of(&records, "session.new");
    assert_eq!(rec.outcome.result, "deny");
    assert!(rec.outcome.reason.contains("'~bob/x'"), "{rec:?}");
    assert!(rig.held().is_empty());
}

#[tokio::test]
async fn the_personal_list_is_a_snapshot() {
    let mut rig = Rig::new("personal-snapshot", Kind::Dir);
    let entries = vec!["~/sentinel-617/**".to_string(), "/srv/sentinel-617".into()];
    let conv = rig.open_listing(entries.clone()).await;
    rig.reopen();
    assert_eq!(rig.store().get(&id(&conv)).unwrap().sensitive, entries);
}

#[tokio::test]
async fn the_largest_personal_list_one_frame_carries_is_stored_and_read_back() {
    let mut rig = Rig::new("personal-largest", Kind::Dir);
    let cwd = rig.cwd();
    let entry = |n: usize| {
        format!(
            "/s{n:02}/{}",
            "a".repeat(maknae_proto::MAX_MUTATION_PATH_BYTES - 5)
        )
    };
    let size = |entries: &[String]| {
        maknae_proto::encode_request(&maknae_proto::Request {
            protocol_version: maknae_proto::PROTOCOL_VERSION,
            task: None,
            verb: Verb::SessionNew {
                cwd: cwd.to_str().unwrap().into(),
                sensitive: entries.to_vec(),
            },
        })
        .unwrap()
        .len()
    };
    let mut entries: Vec<String> = Vec::new();
    while size(&[entries.clone(), vec![entry(entries.len())]].concat())
        <= maknae_proto::ATTEMPT_REQUEST_MAX
    {
        entries.push(entry(entries.len()));
    }
    let room = maknae_proto::ATTEMPT_REQUEST_MAX - size(&entries);
    let pad = room.saturating_sub(16);
    if pad > 8 {
        entries.push(format!("/t/{}", "b".repeat(pad - 3)));
        while size(&entries) > maknae_proto::ATTEMPT_REQUEST_MAX {
            let last = entries.last_mut().unwrap();
            last.pop();
        }
    }
    assert!(
        size(&entries) > maknae_proto::ATTEMPT_REQUEST_MAX - 32,
        "{}",
        size(&entries)
    );
    let conv = rig.open_listing(entries.clone()).await;
    rig.reopen();
    assert_eq!(rig.store().get(&id(&conv)).unwrap().sensitive, entries);
}
