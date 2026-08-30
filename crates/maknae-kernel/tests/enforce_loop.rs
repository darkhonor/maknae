//! The enforcement e2e suite (#77, spec test obligations): `handle()` driven
//! with the REAL PDP — `HermeticAuthorizer` over real policy files through
//! the requirement-parameterized seam (the PR #139/#141 pattern; nothing
//! stubbed, the loader differs from production by exactly the declared
//! requirement). Fixture identities are host-independent: the reserved
//! `root` (uid 0) plus the defaults branch keyed on the fixture principal's
//! own euid. THE point of this file: the shipped deny list actually denying,
//! on the wire and in the trail (operator ruling 1, 2026-08-28).
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use std::time::Duration;

use maknae_authz_basic::HermeticAuthorizer;
use maknae_proto::{Payload, ProtoErrCode, RespResult};

mod common;
use common::{AlwaysPermit, FailNthEmit, HostileObligation, SleepAuthorizer};

// Reuse run_loop's recording emitter shape locally (each tests/*.rs is its
// own crate; RecEmit is tiny and its semantics — record synchronously, then
// optionally fail — are load-bearing for ordering assertions).
use maknae_audit_append::{AuditEmit, AuditError, AuditRecord};
use std::sync::Mutex;

struct RecEmit {
    recs: Mutex<Vec<AuditRecord>>,
}

impl RecEmit {
    fn new() -> Arc<Self> {
        Arc::new(RecEmit {
            recs: Mutex::new(Vec::new()),
        })
    }
    fn records(&self) -> Vec<AuditRecord> {
        self.recs.lock().unwrap().clone()
    }
}

impl AuditEmit for RecEmit {
    fn emit(
        &self,
        rec: &AuditRecord,
    ) -> impl std::future::Future<Output = Result<(), AuditError>> + Send {
        self.recs.lock().unwrap().push(rec.clone());
        async move { Ok(()) }
    }
}

/// The seam requirement every fixture uses: the checks are REAL (mode,
/// regular-file), only root-ownership is relaxed to what a test can build.
fn seam_req() -> maknae_config::TargetRequired {
    maknae_config::TargetRequired {
        owner: None,
        mode_mask: Some(0o022),
        nlink_exactly_one: false,
        regular_file: true,
        max_bytes: None,
    }
}

struct Fixture {
    dir: std::path::PathBuf,
    principal: maknae_config::Principal,
}

impl Fixture {
    /// A fixture home dir (0700, euid-owned) that doubles as the enrolled
    /// principal's home: the anchor's owner requirement is the principal's
    /// uid, so the principal here IS the test euid.
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("enforce_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let principal = maknae_config::Principal {
            name: "operator".into(),
            uid: nix::unistd::geteuid().as_raw(),
            home: dir.clone(),
        };
        Fixture { dir, principal }
    }

    fn write_policy(&self, body: &str) {
        let p = self.dir.join("authz.yaml");
        std::fs::write(&p, body).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
    }

    fn authorizer(&self) -> Arc<HermeticAuthorizer> {
        Arc::new(
            HermeticAuthorizer::new(
                self.dir.join("authz.yaml"),
                self.principal.clone(),
                seam_req(),
            )
            .expect("fixture policy constructs"),
        )
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

const BINDINGS_ROOT_ADMIN: &str =
    "schema_version: 1\npermissions:\n  allow: []\n  deny: []\nbindings:\n  admin: [\"root\"]\n";
const BINDINGS_ROOT_USER: &str =
    "schema_version: 1\npermissions:\n  allow: []\n  deny: []\nbindings:\n  user: [\"root\"]\n";
const BINDINGS_ROOT_ADVERSARY: &str =
    "schema_version: 1\npermissions:\n  allow: []\n  deny: []\nbindings:\n  adversary: [\"root\"]\n";

fn request_frame(verb: maknae_proto::Verb) -> Vec<u8> {
    maknae_proto::encode_request(&maknae_proto::Request {
        protocol_version: maknae_proto::PROTOCOL_VERSION,
        verb,
    })
    .unwrap()
}

/// Drive one request through `handle()` with the given authorizer; return
/// (raw response frame if any, audit records).
async fn drive<P>(
    fx_principal: &maknae_config::Principal,
    authorizer: Arc<P>,
    emit: Arc<impl AuditEmit + Send + Sync + 'static>,
    peer_uid: u32,
    verb: maknae_proto::Verb,
    timeout: Duration,
) -> Option<Vec<u8>>
where
    P: maknae_security::Authorizer + Send + Sync + 'static,
{
    let (mut client, server) = tokio::io::duplex(256 * 1024);
    maknae_proto::write_frame(&mut client, &request_frame(verb))
        .await
        .unwrap();
    maknae_kernel::handle(
        server,
        "maknae://d/plane/cli".to_string(),
        peer_uid,
        true,
        emit,
        1,
        maknae_config::transport_from_section(None).unwrap(),
        serde_json::json!({}),
        authorizer,
        Arc::new(fx_principal.clone()),
        timeout,
        maknae_security::Lane::Local,
    )
    .await;
    match tokio::time::timeout(
        Duration::from_millis(300),
        maknae_proto::read_frame(&mut client, 1024 * 1024),
    )
    .await
    {
        Ok(Ok(body)) => Some(body),
        _ => None,
    }
}

fn request_record(recs: &[AuditRecord]) -> &AuditRecord {
    recs.iter()
        .find(|r| r.event == "request")
        .expect("a request record must exist")
}

// ---------------------------------------------------------------------------
// 1-2. Permit + discharge proof; containment flip (the unique-sentinel proof).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn admin_whoami_permits_with_both_records() {
    let fx = Fixture::new("permit");
    fx.write_policy(BINDINGS_ROOT_ADMIN);
    let emit = RecEmit::new();
    let frame = drive(
        &fx.principal,
        fx.authorizer(),
        emit.clone(),
        0,
        maknae_proto::Verb::Whoami,
        Duration::from_secs(5),
    )
    .await
    .expect("a permitted whoami must answer");
    let resp = maknae_proto::decode_response(&frame).unwrap();
    assert!(
        matches!(resp.result, RespResult::Ok(Payload::Whoami(_))),
        "{resp:?}"
    );

    let recs = emit.records();
    assert_eq!(recs[0].event, "connection");
    assert_eq!(recs[0].seq, 1);
    let req = request_record(&recs);
    assert_eq!(req.seq, 2);
    assert_eq!(req.action, "admin.whoami");
    assert_eq!(req.outcome.result, "permit");
    assert!(req.object.is_none(), "whoami is resource-free");
}

#[tokio::test]
async fn containment_flips_on_file_edit_and_reason_stays_off_the_wire() {
    // The unique-sentinel enforcement proof: the SAME authorizer instance
    // permits, the file is rewritten, the very next request denies — only the
    // real per-request re-read can produce the flip. The deny reason reaches
    // the trail and NEVER the frame bytes.
    let fx = Fixture::new("flip");
    fx.write_policy(BINDINGS_ROOT_ADMIN);
    let authorizer = fx.authorizer();

    let emit1 = RecEmit::new();
    let first = drive(
        &fx.principal,
        authorizer.clone(),
        emit1,
        0,
        maknae_proto::Verb::Whoami,
        Duration::from_secs(5),
    )
    .await
    .expect("first call permits");
    assert!(matches!(
        maknae_proto::decode_response(&first).unwrap().result,
        RespResult::Ok(_)
    ));

    fx.write_policy(BINDINGS_ROOT_ADVERSARY);

    let emit2 = RecEmit::new();
    let second = drive(
        &fx.principal,
        authorizer,
        emit2.clone(),
        0,
        maknae_proto::Verb::Whoami,
        Duration::from_secs(5),
    )
    .await
    .expect("deny gets a frame too (Unauthorized)");
    let resp = maknae_proto::decode_response(&second).unwrap();
    match resp.result {
        RespResult::Err(e) => {
            assert_eq!(e.code, ProtoErrCode::Unauthorized);
            assert_eq!(
                e.message, "not authorized",
                "wire message is the fixed generic string"
            );
        }
        other => panic!("expected Unauthorized, got {other:?}"),
    }
    let needle = b"role=adversary";
    assert!(
        !second.windows(needle.len()).any(|w| w == needle),
        "the deny reason must NEVER appear in the frame bytes"
    );
    let req = request_record(&emit2.records()).clone();
    assert_eq!(req.outcome.result, "deny");
    assert!(
        req.outcome.reason.contains("role=adversary"),
        "the trail carries the real reason: {}",
        req.outcome.reason
    );
}

// ---------------------------------------------------------------------------
// 3-5. No-role deny; the whoami narrowing; the defaults branch.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn unbound_uid_is_denied_everything_including_ping() {
    let fx = Fixture::new("norole");
    fx.write_policy(BINDINGS_ROOT_ADMIN); // bindings PRESENT, uid 42424 unbound
    let emit = RecEmit::new();
    let frame = drive(
        &fx.principal,
        fx.authorizer(),
        emit.clone(),
        42424,
        maknae_proto::Verb::Ping,
        Duration::from_secs(5),
    )
    .await
    .expect("deny frame");
    match maknae_proto::decode_response(&frame).unwrap().result {
        RespResult::Err(e) => assert_eq!(e.code, ProtoErrCode::Unauthorized),
        other => panic!("expected Unauthorized, got {other:?}"),
    }
    let req = request_record(&emit.records()).clone();
    assert_eq!(req.outcome.result, "deny");
    assert!(
        req.outcome.reason.contains("no applicable authorizer"),
        "fail-closed NotApplicable→Deny: {}",
        req.outcome.reason
    );
}

#[tokio::test]
async fn user_role_pings_but_cannot_whoami() {
    let fx = Fixture::new("narrow");
    fx.write_policy(BINDINGS_ROOT_USER);
    let authorizer = fx.authorizer();

    let emit = RecEmit::new();
    let ping = drive(
        &fx.principal,
        authorizer.clone(),
        emit.clone(),
        0,
        maknae_proto::Verb::Ping,
        Duration::from_secs(5),
    )
    .await
    .expect("user ping permits");
    assert!(matches!(
        maknae_proto::decode_response(&ping).unwrap().result,
        RespResult::Ok(Payload::Pong)
    ));
    assert_eq!(request_record(&emit.records()).action, "liveness.ping");

    let emit2 = RecEmit::new();
    let whoami = drive(
        &fx.principal,
        authorizer,
        emit2.clone(),
        0,
        maknae_proto::Verb::Whoami,
        Duration::from_secs(5),
    )
    .await
    .expect("deny frame");
    match maknae_proto::decode_response(&whoami).unwrap().result {
        RespResult::Err(e) => assert_eq!(e.code, ProtoErrCode::Unauthorized),
        other => panic!("whoami narrows to admin: {other:?}"),
    }
}

#[tokio::test]
async fn defaults_branch_enrolled_uid_is_admin_with_zero_nss() {
    // The shipped deployment shape: NO bindings key → enrolled uid → admin.
    let fx = Fixture::new("defaults");
    fx.write_policy("schema_version: 1\npermissions:\n  allow: []\n  deny: []\n");
    let emit = RecEmit::new();
    let me = nix::unistd::geteuid().as_raw();
    let frame = drive(
        &fx.principal,
        fx.authorizer(),
        emit.clone(),
        me,
        maknae_proto::Verb::Whoami,
        Duration::from_secs(5),
    )
    .await
    .expect("enrolled uid whoami permits via defaults");
    assert!(matches!(
        maknae_proto::decode_response(&frame).unwrap().result,
        RespResult::Ok(Payload::Whoami(_))
    ));
    assert_eq!(request_record(&emit.records()).outcome.result, "permit");
}

// ---------------------------------------------------------------------------
// 6-7. THE DENY LIST DENIES (ruling 1); a permitted read returns content.
// ---------------------------------------------------------------------------

/// The shipped policy, byte-identical (the same include the #85 defaults
/// proof uses): `Read(~/**)` allow, `Read(~/.ssh/**)`-class denies.
const SHIPPED_POLICY: &str = include_str!("../../../packaging/common/authz.yaml");

#[tokio::test]
async fn the_shipped_deny_list_actually_denies_a_read_of_ssh_keys() {
    let fx = Fixture::new("denylist");
    fx.write_policy(SHIPPED_POLICY);
    std::fs::create_dir_all(fx.dir.join(".ssh")).unwrap();
    std::fs::write(fx.dir.join(".ssh/id_rsa"), b"SECRETKEYMATERIAL").unwrap();
    let target = fx.dir.join(".ssh/id_rsa").to_string_lossy().into_owned();

    let emit = RecEmit::new();
    let me = nix::unistd::geteuid().as_raw();
    let frame = drive(
        &fx.principal,
        fx.authorizer(),
        emit.clone(),
        me,
        maknae_proto::Verb::Read {
            path: target.clone(),
        },
        Duration::from_secs(5),
    )
    .await
    .expect("deny frame");
    match maknae_proto::decode_response(&frame).unwrap().result {
        RespResult::Err(e) => {
            assert_eq!(e.code, ProtoErrCode::Unauthorized);
            assert_eq!(e.message, "not authorized");
        }
        other => panic!("the deny list MUST deny: {other:?}"),
    }
    // Content must never cross the wire.
    let needle = b"SECRETKEYMATERIAL";
    assert!(!frame.windows(needle.len()).any(|w| w == needle));

    let req = request_record(&emit.records()).clone();
    assert_eq!(req.action, "fs.read");
    assert_eq!(req.outcome.result, "deny");
    assert_eq!(req.object.as_deref(), Some(target.as_str()), "AU-3 object");
    assert!(
        req.outcome
            .reason
            .contains("denied by policy entry Read(~/.ssh/**)"),
        "only a real DenyMatch renders the policy-entry source (and proves the ~ expansion round-trip): {}",
        req.outcome.reason
    );
    // And the pattern source never leaks onto the wire either.
    let pat = b".ssh";
    assert!(!frame.windows(pat.len()).any(|w| w == pat));
}

#[tokio::test]
async fn a_permitted_read_returns_the_file_bytes() {
    let fx = Fixture::new("readok");
    fx.write_policy(SHIPPED_POLICY);
    let content: &[u8] = &[0x4d, 0x41, 0x4b, 0xff, 0x00, 0x4e]; // non-UTF-8 is legal
    std::fs::write(fx.dir.join("notes.bin"), content).unwrap();
    std::fs::set_permissions(
        fx.dir.join("notes.bin"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let target = fx.dir.join("notes.bin").to_string_lossy().into_owned();

    let emit = RecEmit::new();
    let me = nix::unistd::geteuid().as_raw();
    let frame = drive(
        &fx.principal,
        fx.authorizer(),
        emit.clone(),
        me,
        maknae_proto::Verb::Read {
            path: target.clone(),
        },
        Duration::from_secs(5),
    )
    .await
    .expect("permitted read answers");
    match maknae_proto::decode_response(&frame).unwrap().result {
        RespResult::Ok(Payload::ReadContent(b)) => assert_eq!(&*b.0, content),
        other => panic!("expected content, got {other:?}"),
    }
    // Wire-level byte-string proof (spec test obligation): the raw frame must
    // contain the CBOR definite-length BYTE STRING header (0x40 | len for
    // len<24) followed by the content verbatim — the derive's ARRAY form
    // encodes each byte >= 0x18 as two wire bytes and cannot contain this
    // sequence.
    let mut expected = vec![0x40u8 | content.len() as u8];
    expected.extend_from_slice(content);
    assert!(
        frame.windows(expected.len()).any(|w| w == expected),
        "read content must ride as a CBOR byte string on the wire"
    );
    let req = request_record(&emit.records()).clone();
    assert_eq!(req.outcome.result, "permit");
    assert_eq!(req.object.as_deref(), Some(target.as_str()));
}

// ---------------------------------------------------------------------------
// 8-11. Aliases refused; the anchor boundary; oversize.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_symlink_alias_of_a_denied_file_is_refused() {
    let fx = Fixture::new("symlink");
    fx.write_policy(SHIPPED_POLICY);
    std::fs::create_dir_all(fx.dir.join(".ssh")).unwrap();
    std::fs::write(fx.dir.join(".ssh/id_rsa"), b"SECRET").unwrap();
    std::os::unix::fs::symlink(fx.dir.join(".ssh/id_rsa"), fx.dir.join("innocent")).unwrap();
    let target = fx.dir.join("innocent").to_string_lossy().into_owned();

    let emit = RecEmit::new();
    let me = nix::unistd::geteuid().as_raw();
    let frame = drive(
        &fx.principal,
        fx.authorizer(),
        emit.clone(),
        me,
        maknae_proto::Verb::Read { path: target },
        Duration::from_secs(5),
    )
    .await
    .expect("refusal frame");
    match maknae_proto::decode_response(&frame).unwrap().result {
        RespResult::Err(e) => assert_eq!(e.code, ProtoErrCode::Unauthorized),
        other => panic!("symlink alias must refuse: {other:?}"),
    }
    let needle = b"SECRET";
    assert!(!frame.windows(needle.len()).any(|w| w == needle));
    let req = request_record(&emit.records()).clone();
    assert_eq!(req.outcome.result, "deny");
    assert!(
        req.outcome.reason.to_lowercase().contains("symlink"),
        "the STRUCTURAL symlink refusal is the reason, not e.g. ENOENT: {}",
        req.outcome.reason
    );
}

#[tokio::test]
async fn a_hardlink_alias_of_a_denied_file_is_refused() {
    let fx = Fixture::new("hardlink");
    fx.write_policy(SHIPPED_POLICY);
    std::fs::create_dir_all(fx.dir.join(".ssh")).unwrap();
    std::fs::write(fx.dir.join(".ssh/id_rsa"), b"SECRET").unwrap();
    std::fs::set_permissions(
        fx.dir.join(".ssh/id_rsa"),
        std::fs::Permissions::from_mode(0o644), // other-readable so ONLY nlink refuses
    )
    .unwrap();
    std::fs::hard_link(fx.dir.join(".ssh/id_rsa"), fx.dir.join("innocent")).unwrap();
    let target = fx.dir.join("innocent").to_string_lossy().into_owned();

    let emit = RecEmit::new();
    let me = nix::unistd::geteuid().as_raw();
    let frame = drive(
        &fx.principal,
        fx.authorizer(),
        emit.clone(),
        me,
        maknae_proto::Verb::Read { path: target },
        Duration::from_secs(5),
    )
    .await
    .expect("refusal frame");
    match maknae_proto::decode_response(&frame).unwrap().result {
        RespResult::Err(e) => assert_eq!(e.code, ProtoErrCode::Unauthorized),
        other => panic!("hardlink alias must refuse (nlink_exactly_one): {other:?}"),
    }
    let req = request_record(&emit.records()).clone();
    assert!(
        req.outcome.reason.contains("hard-linked"),
        "the nlink refusal is the audit reason: {}",
        req.outcome.reason
    );
}

#[tokio::test]
async fn a_group_writable_home_disables_reads_at_the_anchor_boundary() {
    let fx = Fixture::new("grpwrite");
    fx.write_policy(SHIPPED_POLICY);
    std::fs::write(fx.dir.join("notes.txt"), b"x").unwrap();
    let target = fx.dir.join("notes.txt").to_string_lossy().into_owned();
    // 2770-style home: a maknae-group member could plant aliases — refused.
    std::fs::set_permissions(&fx.dir, std::fs::Permissions::from_mode(0o770)).unwrap();

    let emit = RecEmit::new();
    let me = nix::unistd::geteuid().as_raw();
    let frame = drive(
        &fx.principal,
        fx.authorizer(),
        emit.clone(),
        me,
        maknae_proto::Verb::Read { path: target },
        Duration::from_secs(5),
    )
    .await
    .expect("unavailable frame");
    // Restore so Drop can clean up.
    std::fs::set_permissions(&fx.dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    match maknae_proto::decode_response(&frame).unwrap().result {
        RespResult::Err(e) => {
            assert_eq!(e.code, ProtoErrCode::Internal);
            assert_eq!(e.message, "read unavailable");
        }
        other => panic!("group-writable home must refuse at the anchor: {other:?}"),
    }
    let req = request_record(&emit.records()).clone();
    assert_eq!(req.outcome.posture, "unavailable");
}

#[tokio::test]
async fn an_oversize_file_is_refused_too_large_after_a_real_permit() {
    let fx = Fixture::new("oversize");
    fx.write_policy(SHIPPED_POLICY);
    // Default frame_max_bytes 65536; budget = 65536-512. 70000 > budget.
    std::fs::write(fx.dir.join("big.bin"), vec![0u8; 70_000]).unwrap();
    std::fs::set_permissions(
        fx.dir.join("big.bin"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let target = fx.dir.join("big.bin").to_string_lossy().into_owned();

    let emit = RecEmit::new();
    let me = nix::unistd::geteuid().as_raw();
    let frame = drive(
        &fx.principal,
        fx.authorizer(),
        emit.clone(),
        me,
        maknae_proto::Verb::Read { path: target },
        Duration::from_secs(5),
    )
    .await
    .expect("TooLarge frame");
    match maknae_proto::decode_response(&frame).unwrap().result {
        RespResult::Err(e) => {
            assert_eq!(e.code, ProtoErrCode::TooLarge);
            assert_eq!(e.message, "resource too large");
        }
        other => panic!("oversize must refuse TooLarge, never truncate: {other:?}"),
    }
    let req = request_record(&emit.records()).clone();
    assert_eq!(
        req.outcome.result, "permit",
        "a Permit was rendered; delivery was refused"
    );
    assert_eq!(req.outcome.posture, "refused-oversize");
}

// ---------------------------------------------------------------------------
// 12 (proto-owned), 13-16: withheld frame; timeout two-sided; outside-root;
// hostile obligation. Plus the pre-gate.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_failed_deny_record_append_withholds_the_error_frame() {
    let fx = Fixture::new("withhold");
    fx.write_policy(BINDINGS_ROOT_USER); // whoami under user → deny path
    let emit = FailNthEmit::new(2); // admission (1) succeeds; the deny record (2) fails
    let frame = drive(
        &fx.principal,
        fx.authorizer(),
        emit.clone(),
        0,
        maknae_proto::Verb::Whoami,
        Duration::from_secs(5),
    )
    .await;
    assert!(
        frame.is_none(),
        "no frame may leave without a durable record of the decision"
    );
    let recs = emit.records();
    assert_eq!(
        recs.len(),
        2,
        "admission + the offered-but-failed deny record"
    );
    assert_eq!(recs[1].event, "request");
}

#[tokio::test]
async fn decide_timeout_denies_and_a_fast_decide_is_served() {
    let fx = Fixture::new("timeout");
    // (a) sleeps past the bound → deny with the timeout reason.
    let emit = RecEmit::new();
    let frame = drive(
        &fx.principal,
        Arc::new(SleepAuthorizer(Duration::from_millis(300))),
        emit.clone(),
        0,
        maknae_proto::Verb::Ping,
        Duration::from_millis(100),
    )
    .await
    .expect("timeout deny frame");
    match maknae_proto::decode_response(&frame).unwrap().result {
        RespResult::Err(e) => assert_eq!(e.code, ProtoErrCode::Unauthorized),
        other => panic!("elapsed decide must deny: {other:?}"),
    }
    assert!(
        request_record(&emit.records())
            .outcome
            .reason
            .contains("timed out"),
        "the timeout reason is in the trail"
    );

    // (b) sleeps UNDER a generous bound → permitted and served (proves the
    // parameter is honored — a zero/too-small binding would fail this side).
    let emit2 = RecEmit::new();
    let frame = drive(
        &fx.principal,
        Arc::new(SleepAuthorizer(Duration::from_millis(100))),
        emit2,
        0,
        maknae_proto::Verb::Ping,
        Duration::from_millis(500),
    )
    .await
    .expect("fast decide is served");
    assert!(matches!(
        maknae_proto::decode_response(&frame).unwrap().result,
        RespResult::Ok(Payload::Pong)
    ));
}

#[tokio::test]
async fn four_concurrent_healthy_decisions_do_not_trip_the_breaker() {
    let fx = Fixture::new("healthy_concurrent");
    let authorizer = Arc::new(SleepAuthorizer(Duration::from_millis(100)));
    let timeout = Duration::from_secs(5);

    let emit1 = RecEmit::new();
    let emit2 = RecEmit::new();
    let emit3 = RecEmit::new();
    let emit4 = RecEmit::new();

    let (one, two, three, four) = tokio::join!(
        drive(
            &fx.principal,
            authorizer.clone(),
            emit1.clone(),
            0,
            maknae_proto::Verb::Ping,
            timeout
        ),
        drive(
            &fx.principal,
            authorizer.clone(),
            emit2.clone(),
            0,
            maknae_proto::Verb::Ping,
            timeout
        ),
        drive(
            &fx.principal,
            authorizer.clone(),
            emit3.clone(),
            0,
            maknae_proto::Verb::Ping,
            timeout
        ),
        drive(
            &fx.principal,
            authorizer,
            emit4.clone(),
            0,
            maknae_proto::Verb::Ping,
            timeout
        ),
    );

    for (frame, emit) in [
        (one, emit1.as_ref()),
        (two, emit2.as_ref()),
        (three, emit3.as_ref()),
        (four, emit4.as_ref()),
    ] {
        let frame = frame.expect("healthy concurrent decide should be served");
        assert!(matches!(
            maknae_proto::decode_response(&frame).unwrap().result,
            RespResult::Ok(Payload::Pong)
        ));
        assert_eq!(request_record(&emit.records()).outcome.result, "permit");
    }
}

#[tokio::test]
async fn a_permit_outside_the_anchored_root_is_refused_distinctly() {
    let fx = Fixture::new("outside");
    // Operator-added absolute grant outside home: PDP permits, PEP refuses.
    fx.write_policy(
        "schema_version: 1\npermissions:\n  allow:\n    - \"Read(/etc/**)\"\n  deny: []\n",
    );
    let emit = RecEmit::new();
    let me = nix::unistd::geteuid().as_raw();
    let frame = drive(
        &fx.principal,
        fx.authorizer(),
        emit.clone(),
        me,
        maknae_proto::Verb::Read {
            path: "/etc/hostname".into(),
        },
        Duration::from_secs(5),
    )
    .await
    .expect("outside-root frame");
    match maknae_proto::decode_response(&frame).unwrap().result {
        RespResult::Err(e) => {
            assert_eq!(e.code, ProtoErrCode::Internal);
            assert_eq!(e.message, "read outside supported root");
            assert_ne!(e.code, ProtoErrCode::Unauthorized, "a Permit was rendered");
        }
        other => panic!("outside-root must refuse distinctly: {other:?}"),
    }
    let req = request_record(&emit.records()).clone();
    assert_eq!(req.outcome.result, "permit");
    assert_eq!(req.outcome.posture, "refused-outside-root");
}

#[tokio::test]
async fn an_unhonorable_obligation_fails_closed() {
    let fx = Fixture::new("oblig");
    let emit = RecEmit::new();
    let frame = drive(
        &fx.principal,
        Arc::new(HostileObligation),
        emit.clone(),
        0,
        maknae_proto::Verb::Ping,
        Duration::from_secs(5),
    )
    .await
    .expect("deny frame");
    match maknae_proto::decode_response(&frame).unwrap().result {
        RespResult::Err(e) => assert_eq!(e.code, ProtoErrCode::Unauthorized),
        other => panic!("unknown obligation must deny: {other:?}"),
    }
    assert!(
        request_record(&emit.records())
            .outcome
            .reason
            .contains("unhonorable obligation: exfil"),
        "the obligation id is in the trail"
    );
}

#[tokio::test]
async fn a_malformed_read_path_is_bad_request_before_the_pdp() {
    let fx = Fixture::new("pregate");
    fx.write_policy(SHIPPED_POLICY);
    let emit = RecEmit::new();
    let me = nix::unistd::geteuid().as_raw();
    let evasive = format!("{}/../{}", fx.dir.display(), ".ssh/id_rsa");
    let frame = drive(
        &fx.principal,
        fx.authorizer(),
        emit.clone(),
        me,
        maknae_proto::Verb::Read { path: evasive },
        Duration::from_secs(5),
    )
    .await
    .expect("BadRequest frame");
    match maknae_proto::decode_response(&frame).unwrap().result {
        RespResult::Err(e) => {
            assert_eq!(e.code, ProtoErrCode::BadRequest);
            assert_eq!(e.message, "malformed path");
        }
        other => panic!("dot segments are the malformed-request class: {other:?}"),
    }
    let req = request_record(&emit.records()).clone();
    assert_eq!(req.outcome.result, "deny");
    assert!(req.outcome.reason.contains("pre-gate"));
}

// ---- #67: the NOOP contract, end to end ----------------------------------
// The path this PR exists to introduce. `run.rs` is T3 and mutation-excluded,
// so without these three tests the ordering claim cannot go red at all.

/// THE security property of the NOOP contract: a subject not entitled to a term
/// must receive `Unauthorized` and learn NOTHING about whether it is built.
/// Short-circuiting to `NotImplemented` ahead of the decision would let any
/// caller enumerate the whole verb surface for free.
#[tokio::test]
async fn an_unentitled_caller_gets_unauthorized_never_notimplemented() {
    let fx = Fixture::new("noop-unauth");
    fx.write_policy(BINDINGS_ROOT_USER); // root -> user: liveness only
    for verb in [
        maknae_proto::Verb::AdminStatus,
        maknae_proto::Verb::SessionNew,
        maknae_proto::Verb::FsWrite,
    ] {
        let emit = RecEmit::new();
        let frame = drive(
            &fx.principal,
            fx.authorizer(),
            emit,
            0,
            verb.clone(),
            Duration::from_secs(5),
        )
        .await
        .expect("a frame");
        match maknae_proto::decode_response(&frame).unwrap().result {
            RespResult::Err(e) => assert_eq!(
                e.code,
                ProtoErrCode::Unauthorized,
                "{verb:?} must deny without leaking implementation state"
            ),
            other => panic!("expected Unauthorized for {verb:?}, got {other:?}"),
        }
    }
}

/// A PERMITTED but unbuilt term is decided, audited as decided-and-NOT-performed,
/// and only then refused. Driven with a permissive authorizer because the real
/// PDP grants no `[N]` term (see the suite above) — this exercises the PEP's
/// ordering, not a decision.
#[tokio::test]
async fn a_permitted_unbuilt_term_is_audited_then_refused() {
    let fx = Fixture::new("noop-permit");
    let emit = RecEmit::new();
    let frame = drive(
        &fx.principal,
        Arc::new(AlwaysPermit),
        emit.clone(),
        0,
        maknae_proto::Verb::AdminStatus,
        Duration::from_secs(5),
    )
    .await
    .expect("a frame");
    match maknae_proto::decode_response(&frame).unwrap().result {
        RespResult::Err(e) => assert_eq!(e.code, ProtoErrCode::NotImplemented),
        other => panic!("expected NotImplemented, got {other:?}"),
    }
    let req = request_record(&emit.records()).clone();
    assert_eq!(req.action, "admin.status");
    assert_eq!(req.outcome.result, "permit");
    assert_eq!(
        req.outcome.posture, "not-implemented",
        "a Permit-then-NOOP must never read as a completed action"
    );
}

/// The audit-then-respond invariant holds on the NOOP path too: no frame leaves
/// without a durable record. n=2 fails the REQUEST record while the admission
/// record succeeds — n=1 would trip the connection-admission gate before the
/// NOOP path is ever reached, and the test would pass for the wrong reason.
#[tokio::test]
async fn a_noop_withholds_its_frame_when_the_record_cannot_append() {
    let fx = Fixture::new("noop-withhold");
    let emit = FailNthEmit::new(2);
    let out = drive(
        &fx.principal,
        Arc::new(AlwaysPermit),
        emit.clone(),
        0,
        maknae_proto::Verb::AdminStatus,
        Duration::from_secs(5),
    )
    .await;
    assert!(
        out.is_none(),
        "no frame may be released when its record could not append"
    );
    assert!(
        emit.records().iter().any(|r| r.action == "admin.status"),
        "the record must have been OFFERED before the frame was withheld"
    );
}
