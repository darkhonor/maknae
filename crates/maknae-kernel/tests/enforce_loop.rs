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
use common::{AlwaysPermit, FailNthEmit, HostileObligation, PanickingName, SleepAuthorizer};

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
        // CANONICAL, or the delegated lane never matches (#216). `verify_delegated`
        // prefix-checks the KERNEL-reported path of the subject's descriptor against
        // this directory as `confined_beneath`, and the kernel reports the resolved
        // form: on macOS `temp_dir()` is `$TMPDIR` under `/var`, a symlink to
        // `/private/var`, so an unresolved home here fails `strip_prefix`, the OS
        // answer is never established, and every delegated read denies with
        // `os accessibility unknown` -- four tests red on darwin since PR #199,
        // five as of #215, unseen because `maknae-kernel` is outside the macOS CI lane.
        // The blast radius was larger than the reds. Two deny-asserting tests that
        // delegate a descriptor were passing VACUOUSLY on darwin:
        // `a_hardlink_alias_of_a_denied_file_is_refused` was denied at confinement
        // before the nlink check it exists to prove -- `verify_delegated` runs
        // `strip_prefix` BEFORE `check_target`, where nlink lives, and the test's
        // `contains("os dac")` cannot tell the two apart. (ADR-0009 §5 said the
        // reverse, "refused before confinement is even consulted"; corrected in
        // place, dated, in this same change.)
        // `a_permit_outside_the_anchored_root_is_refused_distinctly`
        // was doubly masked -- the `/var` mismatch AND its
        // unresolved absolute allow glob -- so deleting the confinement check
        // outright would have left it green under its then `result == deny`-only
        // assertion. NOT vacuous, for the record: the symlink-alias case was
        // outright red (it asserts the resolved `.ssh` path), and the
        // group-writable-home case fails at root soundness, which precedes
        // confinement -- it reached its own check unaffected. Same remedy as `maknae-io`'s own
        // `confinement_root()` fixture. A fixture that only works where the temp dir
        // is a real directory is testing the host, not the code.
        let dir = dir.canonicalize().expect("canonicalize the fixture home");
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

/// Drive a request whose subject DELEGATES a descriptor for `delegate`, the way a
/// real client does: the client process opens the object itself, so the kernel has
/// already run the whole permission check for that subject, and the descriptor it
/// hands over IS the OS's answer (ADR-0009 decision 1).
#[allow(clippy::too_many_arguments)]
async fn drive_read<P>(
    fx_principal: &maknae_config::Principal,
    authorizer: Arc<P>,
    emit: Arc<impl AuditEmit + Send + Sync + 'static>,
    peer_uid: u32,
    verb: maknae_proto::Verb,
    timeout: Duration,
    delegate: &std::path::Path,
) -> Option<Vec<u8>>
where
    P: maknae_security::Authorizer + Send + Sync + 'static,
{
    let fds = maknae_io::DelegatedFds::new(4);
    // `open` here is the SUBJECT's open. If it fails, the subject genuinely cannot
    // read the object and no descriptor is delegated -- which is itself the case
    // ADR-0009 decision 2 turns into a Deny, so the test still exercises a real path.
    if let Ok(f) = std::fs::File::open(delegate) {
        fds.push(std::os::fd::OwnedFd::from(f));
    }
    drive_with(
        fx_principal,
        authorizer,
        emit,
        peer_uid,
        verb,
        timeout,
        fds,
        Arc::new(Default::default()),
        maknae_config::transport_from_section(None).unwrap(),
        Arc::new("US".to_string()),
    )
    .await
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
    drive_with(
        fx_principal,
        authorizer,
        emit,
        peer_uid,
        verb,
        timeout,
        maknae_io::DelegatedFds::new(0),
        Arc::new(Default::default()),
        maknae_config::transport_from_section(None).unwrap(),
        Arc::new("US".to_string()),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn drive_with<P>(
    fx_principal: &maknae_config::Principal,
    authorizer: Arc<P>,
    emit: Arc<impl AuditEmit + Send + Sync + 'static>,
    peer_uid: u32,
    verb: maknae_proto::Verb,
    timeout: Duration,
    delegated: maknae_io::DelegatedFds,
    // The already-redacted effective config the daemon would hold. Default
    // (empty) for every verb that is not `admin.config.show`.
    config_view: Arc<maknae_kernel::ConfigView>,
    transport: maknae_config::TransportConfig,
    // The classification SYSTEM name the daemon would hold (ADR-0022). Production
    // captures it once in run_inner from `boot()`; a status test derives it from a
    // real `boot()` of a fixture for the same reason `backend_name` below is
    // derived from the authorizer -- a literal here would make the assertion
    // tautological.
    classification_policy: Arc<String>,
) -> Option<Vec<u8>>
where
    P: maknae_security::Authorizer + Send + Sync + 'static,
{
    let (mut client, server) = tokio::io::duplex(256 * 1024);
    maknae_proto::write_frame(&mut client, &request_frame(verb))
        .await
        .unwrap();
    // The harness plays the BOOT role: production captures this once in
    // run_inner from the same authorizer it serves with, so the test captures
    // from the authorizer it drives with -- before handle() takes it by value.
    let backend_name = Arc::new(maknae_security::guarded_backend_name(&*authorizer));
    maknae_kernel::handle(
        server,
        "maknae://d/plane/cli".to_string(),
        peer_uid,
        true,
        emit,
        1,
        transport,
        serde_json::json!({}),
        authorizer,
        Arc::new(fx_principal.clone()),
        Arc::clone(&config_view),
        backend_name,
        classification_policy,
        std::sync::Arc::new(None),
        maknae_kernel::production_egress(),
        timeout,
        maknae_security::Lane::Local,
        delegated,
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
            assert_eq!(e.message, "not authorized", "no note may reach the wire");
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
        RespResult::Err(e) => {
            assert_eq!(e.code, ProtoErrCode::Unauthorized);
            assert_eq!(e.message, "not authorized", "no note may reach the wire");
        }
        other => panic!("expected Unauthorized, got {other:?}"),
    }
    let req = request_record(&emit.records()).clone();
    assert_eq!(req.outcome.result, "deny");
    // Retargeted (#181): the trail now names the FACT — the subject resolves
    // to no role — rather than the mechanism ("no applicable authorizer").
    // This was the only byte-level pin of the historical string; the fallback
    // is pinned at its own unit test in verdict.rs now.
    assert!(
        req.outcome.reason.contains("subject resolves to no role"),
        "case-1 note (was the collapsed historical string): {}",
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
        RespResult::Err(e) => {
            assert_eq!(e.code, ProtoErrCode::Unauthorized);
            assert_eq!(e.message, "not authorized", "no note may reach the wire");
        }
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
    let frame = drive_read(
        &fx.principal,
        fx.authorizer(),
        emit.clone(),
        me,
        maknae_proto::Verb::Read {
            path: target.clone(),
        },
        Duration::from_secs(5),
        std::path::Path::new(&target),
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

/// #216-TRIPWIRE -- PINS CURRENT BEHAVIOUR, not a desired property. The enrolled home
/// (`principal.home`) is written by `maknae enroll` VERBATIM from `getpwuid` --
/// the directory service's value, not an operator's choice, and re-derived on every
/// enroll -- and the daemon feeds that one value to at least THREE consumers: the
/// delegated lane's confinement root (`handler::delegated_plan`, reached at decision
/// time AND again inside the read PEP), which is prefix-checked against the
/// KERNEL-reported path of the subject's descriptor; the `~` referent of every
/// policy glob (`PathGlob::parse`); and the boot-time anchor probe in `run.rs`.
/// (Enroll consumes it too, for the CLI dir and the `_maknae` read-ACL grant -- the
/// surface the production ruling must cover.) Here the home is a SYMLINK to the real
/// directory. The kernel reports the resolved form, the configured form never
/// prefix-matches, the OS's answer is never established, and a read of the enrolled
/// home -- one the operator's `Read(~/**)` grant was written to cover, and which the
/// positive control below proves IS permitted under the canonical home -- is refused
/// fail-closed with `os accessibility unknown`: the same fail-closed form mismatch
/// ADR-0009 decision 4's macOS bullet names for firmlinks, and what a
/// `/home -> /export/home` layout does to a real deployment whose passwd entry says
/// `/home/alex`. (Once a descriptor verifies and the RESOLVED path is stamped, the
/// symlinked home's `~` globs do not match it either -- see the next paragraph --
/// which is why the name does not say "the policy permits".)
///
/// Canonicalizing ONLY `confined_beneath` does not make this read succeed: the `~`
/// globs -- allow and deny alike -- still expand from the configured string, so the
/// resolved path matches nothing and the deny merely changes reason
/// (`no capability entry`). It becomes a genuine deny-turned-permit only where an
/// operator wrote an ABSOLUTE allow glob covering the resolved path beside
/// `~`-form denies: the allow matches, the denies never do. Either way the fix must
/// establish one canonical form for every consumer; when it lands, this test is
/// flipped DELIBERATELY. Until then: a spurious Deny, never a bypass -- and the
/// authorizer here is built from the SAME symlinked principal the PEP sees, so a
/// ROOT-only partial fix changes the asserted reason (to `no capability entry`)
/// rather than silently satisfying it. A GLOB-only partial fix (canonical `~`
/// referent, unresolved confinement root) still fails confinement and is
/// invisible here -- one more reason the ruling must land at or above
/// `Principal`, where neither half can be fixed alone.
#[tokio::test]
async fn a_symlinked_principal_home_denies_a_read_beneath_the_enrolled_home() {
    let fx = Fixture::new("symroot");
    fx.write_policy(SHIPPED_POLICY);
    let content: &[u8] = b"reachable only via the link";
    std::fs::write(fx.dir.join("notes.txt"), content).unwrap();
    let me = nix::unistd::geteuid().as_raw();

    // POSITIVE CONTROL: the identical object through the identical policy with the
    // REAL (canonical) home is permitted and returns the bytes. This establishes
    // that the object, the policy and the fixture are sound -- so the deny below
    // is attributable to the home's FORM. (It does not by itself prove a descriptor
    // was delegated through the link; the `std::fs::read` check before the second
    // drive does that, because `drive_read` swallows a failed subject open and an
    // undelivered descriptor yields the identical `os accessibility unknown`.)
    let real_target = fx.dir.join("notes.txt").to_string_lossy().into_owned();
    let ctl = RecEmit::new();
    let frame = drive_read(
        &fx.principal,
        fx.authorizer(),
        ctl.clone(),
        me,
        maknae_proto::Verb::Read {
            path: real_target.clone(),
        },
        Duration::from_secs(5),
        std::path::Path::new(&real_target),
    )
    .await
    .expect("positive control answers");
    match maknae_proto::decode_response(&frame).unwrap().result {
        RespResult::Ok(Payload::ReadContent(b)) => assert_eq!(&*b.0, content),
        other => panic!("positive control must PERMIT through the real home, got {other:?}"),
    }
    assert_eq!(request_record(&ctl.records()).outcome.result, "permit");

    // The link lives BESIDE the canonical real dir -- same parent, so on both
    // platforms the link-vs-real component is the ONLY form difference; anchored
    // under the unresolved `temp_dir()` the darwin deny would be over-determined
    // by the `/var -> /private/var` mismatch as well. It sits OUTSIDE `fx.dir`
    // because it is about to BE the confinement root, not an object beneath one
    // -- which also means `Fixture::drop` will not clean it, hence the explicit
    // `remove_file` after the drive. `stat` of the root follows it to the real,
    // 0700, euid-owned directory and the root-soundness check passes.
    let link = fx
        .dir
        .parent()
        .expect("canonical fixture dir has a parent")
        .join(format!("enforce_symroot_link_{}", std::process::id()));
    if std::fs::symlink_metadata(&link).is_ok() {
        std::fs::remove_file(&link).expect("clear a stale entry at the fixture link path");
    }
    std::os::unix::fs::symlink(&fx.dir, &link).unwrap();
    let via_link = maknae_config::Principal {
        home: link.clone(),
        ..fx.principal.clone()
    };
    // ONE principal for both consumers, as production wires it: the PDP expands
    // `~` against the link, and the PEP confines beneath the link.
    let pdp_via_link = Arc::new(
        HermeticAuthorizer::new(fx.dir.join("authz.yaml"), via_link.clone(), seam_req())
            .expect("policy constructs against the symlinked home"),
    );
    // The subject opens THROUGH the link, as a real client would with a home it
    // was told about; the kernel still reports the resolved form.
    let target = link.join("notes.txt").to_string_lossy().into_owned();
    // The subject CAN open through the link -- so a descriptor IS delegated below,
    // and the deny that follows is confinement's, not "no descriptor arrived".
    assert_eq!(
        std::fs::read(&target).expect("the subject can open the object through the link"),
        content
    );

    let emit = RecEmit::new();
    let frame = drive_read(
        &via_link,
        pdp_via_link,
        emit.clone(),
        me,
        maknae_proto::Verb::Read {
            path: target.clone(),
        },
        Duration::from_secs(5),
        std::path::Path::new(&target),
    )
    .await
    .expect("a deny frame");
    let _ = std::fs::remove_file(&link);
    match maknae_proto::decode_response(&frame).unwrap().result {
        RespResult::Err(e) => {
            assert_eq!(e.code, ProtoErrCode::Unauthorized);
            assert_eq!(e.message, "not authorized", "no reason may reach the wire");
        }
        other => panic!(
            "a symlinked principal.home is expected to DENY today (#216); if this \
             read succeeded, the canonical-form fix landed for BOTH consumers -- \
             flip this test deliberately. Got {other:?}"
        ),
    }
    let req = request_record(&emit.records()).clone();
    assert_eq!(req.outcome.result, "deny");
    assert_eq!(
        req.outcome.reason, "os dac: os accessibility unknown",
        "the OS answer is never established through a mismatched confinement root; \
         a partial fix that canonicalizes only the root would surface here as \
         `no capability entry` instead"
    );
    // No verified object, so the trail records what was ASKED (the link form) and
    // nothing to diverge from it: `run.rs`'s `object_path` falls back to the
    // client's string when `verified_read` is `None`, and `object_asked` is
    // `Some` only when the decided path differs from it.
    assert_eq!(req.object.as_deref(), Some(target.as_str()));
    assert!(req.object_requested.is_none());
}

#[tokio::test]
async fn ordinary_user_reads_approved_content_through_the_composed_pdp() {
    let fx = Fixture::new("ordinary-user-development");
    let me = nix::unistd::geteuid();
    let user = nix::unistd::User::from_uid(me).unwrap().unwrap();
    fx.write_policy(&format!(
        "schema_version: 1\npermissions:\n  allow: [\"Read(~/**)\"]\n  deny: []\nbindings:\n  user: [{:?}]\n",
        user.name
    ));
    let target = fx.dir.join("development-sentinel.txt");
    let sentinel = b"ordinary-user-development-158: genuine composed read";
    std::fs::write(&target, sentinel).unwrap();
    let emit = RecEmit::new();
    let authorizer = composed(&fx, "UNCLASSIFIED");
    let frame = drive_read(
        &fx.principal,
        authorizer.clone(),
        emit.clone(),
        me.as_raw(),
        maknae_proto::Verb::Read {
            path: target.to_str().unwrap().into(),
        },
        Duration::from_secs(5),
        &target,
    )
    .await
    .expect("authorized user receives a response");
    match maknae_proto::decode_response(&frame).unwrap().result {
        RespResult::Ok(Payload::ReadContent(bytes)) => assert_eq!(&*bytes.0, sentinel),
        other => panic!("ordinary development requires a real read, got {other:?}"),
    }
    let records = emit.records();
    let rec = request_record(&records);
    assert_eq!(rec.outcome.result, "permit");
    assert_eq!(rec.source.uid, me.as_raw());
    assert_eq!(rec.object.as_deref(), target.to_str());

    // Filesystem access grants no management authority to this same user.
    let management = drive(
        &fx.principal,
        authorizer.clone(),
        RecEmit::new(),
        me.as_raw(),
        maknae_proto::Verb::Whoami,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert!(
        matches!(maknae_proto::decode_response(&management).unwrap().result,
        RespResult::Err(ref e) if e.code == ProtoErrCode::Unauthorized)
    );

    // Reuse the same PDP: a containment edit must bite on the next read,
    // even though the subject can still open and delegate the same object.
    fx.write_policy(&format!(
        "schema_version: 1\npermissions:\n  allow: [\"Read(~/**)\"]\n  deny: []\nbindings:\n  adversary: [{:?}]\n",
        user.name,
    ));
    let emit = RecEmit::new();
    let contained = drive_read(
        &fx.principal,
        authorizer,
        emit.clone(),
        me.as_raw(),
        maknae_proto::Verb::Read {
            path: target.to_str().unwrap().into(),
        },
        Duration::from_secs(5),
        &target,
    )
    .await
    .unwrap();
    assert!(
        matches!(maknae_proto::decode_response(&contained).unwrap().result,
        RespResult::Err(ref e) if e.code == ProtoErrCode::Unauthorized)
    );
    let records = emit.records();
    assert!(request_record(&records)
        .outcome
        .reason
        .contains("subject contained"));
}

#[tokio::test]
async fn filesystem_access_for_users_and_admins_keeps_os_and_path_refusals() {
    let fx = Fixture::new("shared-filesystem-refusals");
    let me = nix::unistd::geteuid();
    let user = nix::unistd::User::from_uid(me).unwrap().unwrap();
    let target = fx.dir.join("denied-development-sentinel.txt");
    let sentinel = b"158: never disclose this denied development file";
    std::fs::write(&target, sentinel).unwrap();
    for role in ["user", "admin"] {
        fx.write_policy(&format!(
            "schema_version: 1\npermissions:\n  allow: [\"Read(~/**)\"]\n  deny: [\"Read(~/denied-development-sentinel.txt)\"]\nbindings:\n  {role}: [{:?}]\n",
            user.name,
        ));
        // The descriptor really arrives: this must reach the path deny,
        // not pass vacuously because the OS proof was missing.
        let emit = RecEmit::new();
        let frame = drive_read(
            &fx.principal,
            composed(&fx, "UNCLASSIFIED"),
            emit.clone(),
            me.as_raw(),
            maknae_proto::Verb::Read {
                path: target.to_str().unwrap().into(),
            },
            Duration::from_secs(5),
            &target,
        )
        .await
        .unwrap();
        assert!(
            matches!(maknae_proto::decode_response(&frame).unwrap().result,
            RespResult::Err(ref e) if e.code == ProtoErrCode::Unauthorized)
        );
        let records = emit.records();
        let rec = request_record(&records);
        assert!(
            rec.outcome
                .reason
                .contains("Read(~/denied-development-sentinel.txt)"),
            "{role}: {}",
            rec.outcome.reason
        );
        assert!(!frame.windows(sentinel.len()).any(|w| w == sentinel));

        // A universally allowed path still needs subject OS authority.
        let emit = RecEmit::new();
        let frame = drive(
            &fx.principal,
            composed(&fx, "UNCLASSIFIED"),
            emit.clone(),
            me.as_raw(),
            maknae_proto::Verb::Read {
                path: fx.dir.join("allowed.txt").to_str().unwrap().into(),
            },
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        assert!(
            matches!(maknae_proto::decode_response(&frame).unwrap().result,
            RespResult::Err(ref e) if e.code == ProtoErrCode::Unauthorized)
        );
        let records = emit.records();
        assert!(
            request_record(&records)
                .outcome
                .reason
                .contains("os accessibility unknown"),
            "{role}"
        );
    }
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
    let frame = drive_read(
        &fx.principal,
        fx.authorizer(),
        emit.clone(),
        me,
        maknae_proto::Verb::Read {
            path: target.clone(),
        },
        Duration::from_secs(5),
        std::path::Path::new(&target),
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
    assert_eq!(
        req.object_requested, None,
        "asked and decided agree, so the divergence field stays absent — its presence \
         is the anomaly signal and must not be diluted by the ordinary case"
    );
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
    let frame = drive_read(
        &fx.principal,
        fx.authorizer(),
        emit.clone(),
        me,
        maknae_proto::Verb::Read {
            path: target.clone(),
        },
        Duration::from_secs(5),
        std::path::Path::new(&target),
    )
    .await
    .expect("refusal frame");
    match maknae_proto::decode_response(&frame).unwrap().result {
        RespResult::Err(e) => {
            assert_eq!(e.code, ProtoErrCode::Unauthorized);
            assert_eq!(e.message, "not authorized", "no note may reach the wire");
        }
        other => panic!("symlink alias must refuse: {other:?}"),
    }
    let needle = b"SECRET";
    assert!(!frame.windows(needle.len()).any(|w| w == needle));
    let req = request_record(&emit.records()).clone();
    assert_eq!(req.outcome.result, "deny");
    // CHANGED BY ADR-0009 decision 6, and this is the improvement: the refusal is no
    // longer a blanket structural "symlink refused" that never consulted policy. The
    // subject's descriptor resolves to the real object, the kernel reports THAT path,
    // and the shipped deny list matches it by name. The alias is defeated by the rule
    // it was trying to dodge — which also means a LEGITIMATE in-home symlink now
    // works, the deliberate loosening ADR-0009 D6 records.
    assert!(
        req.outcome.reason.contains(".ssh"),
        "the deny list must match the RESOLVED path, not the alias: {}",
        req.outcome.reason
    );

    // The trail must be reconstructable: a reviewer has to see BOTH what the client
    // asked for and what was actually decided, because ADR-0009 D6 makes them able to
    // differ by design. `object` is the DECIDED path; `object_requested` appears only
    // when it diverges -- so its PRESENCE is itself the signal that a client named one
    // object and a different one was evaluated.
    let resolved = fx.dir.join(".ssh/id_rsa").to_string_lossy().into_owned();
    assert_eq!(
        req.object.as_deref(),
        Some(resolved.as_str()),
        "object is the path the decision was made on"
    );
    assert_eq!(
        req.object_requested.as_deref(),
        Some(target.as_str()),
        "object_requested is what the client asked for, recorded because it differs"
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
        // Other-readable. Historically this kept the PEP's mode check out of the way
        // so ONLY nlink could refuse; under ADR-0009 `delegated_plan` sets the
        // target's `owner`/`mode_mask` to `None`, so mode is never evaluated here
        // and the line is now belt-and-braces (noted 2026-09-04, #216).
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    std::fs::hard_link(fx.dir.join(".ssh/id_rsa"), fx.dir.join("innocent")).unwrap();
    let target = fx.dir.join("innocent").to_string_lossy().into_owned();
    // The subject CAN open the alias, so a descriptor IS delegated below and the
    // `os dac` refusal that follows is not "no descriptor arrived". That rules
    // out ONE of the two ways this pass goes vacuous; the other -- a confinement
    // refusal upstream of the nlink check (#216) -- is held only by
    // `Fixture::new`'s canonicalize, and this assertion cannot see it.
    assert_eq!(
        std::fs::read(&target).expect("the subject can open the hard-link alias"),
        b"SECRET"
    );

    let emit = RecEmit::new();
    let me = nix::unistd::geteuid().as_raw();
    let frame = drive_read(
        &fx.principal,
        fx.authorizer(),
        emit.clone(),
        me,
        maknae_proto::Verb::Read {
            path: target.clone(),
        },
        Duration::from_secs(5),
        std::path::Path::new(&target),
    )
    .await
    .expect("refusal frame");
    match maknae_proto::decode_response(&frame).unwrap().result {
        RespResult::Err(e) => {
            assert_eq!(e.code, ProtoErrCode::Unauthorized);
            assert_eq!(e.message, "not authorized", "no note may reach the wire");
        }
        other => panic!("hardlink alias must refuse (nlink_exactly_one): {other:?}"),
    }
    let req = request_record(&emit.records()).clone();
    // CHANGED BY ADR-0009: `nlink_exactly_one` is now checked while VERIFYING the
    // delegated descriptor, before the decision — so a multiply-linked object never
    // establishes OS access at all and the verdict is a composed Deny rather than a
    // PEP refusal. The outcome is right and strictly earlier.
    //
    // OWED (#84 / #181 / ADR-0008 D5, "land it once"): this reason cannot yet
    // distinguish "a descriptor arrived and failed verification" from "no descriptor
    // arrived". Both deny, so nothing is unsafe — but an operator cannot tell a
    // hard-link alias from a client that sent nothing.
    assert!(
        req.outcome.reason.contains("os dac"),
        "the refusal is OS-DAC-attributed: {}",
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
    let frame = drive_read(
        &fx.principal,
        fx.authorizer(),
        emit.clone(),
        me,
        maknae_proto::Verb::Read {
            path: target.clone(),
        },
        Duration::from_secs(5),
        std::path::Path::new(&target),
    )
    .await
    .expect("unavailable frame");
    // Restore so Drop can clean up.
    std::fs::set_permissions(&fx.dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    // CHANGED BY ADR-0009 decision 7 — and this is the removed-behavior obligation
    // (ADR-0021) DISCHARGED, not waived. The anchor OPEN is gone from the read path,
    // but the anchor REQUIREMENT survives: `root_required` is checked by `stat` on the
    // home, which needs only search on its parent and no permission on the home
    // itself. A home any non-principal can write is still refused.
    //
    // What changed is the SHAPE of the refusal, for the better: it is now a composed
    // Deny at the PDP rather than a PEP unavailability. ADR-0009's "it produces a
    // verdict instead of a failure" — the trail records a decision, not an outage.
    match maknae_proto::decode_response(&frame).unwrap().result {
        RespResult::Err(e) => {
            assert_eq!(e.code, ProtoErrCode::Unauthorized);
            assert_eq!(e.message, "not authorized", "no note may reach the wire");
        }
        other => panic!("group-writable home must still be refused: {other:?}"),
    }
    let req = request_record(&emit.records()).clone();
    assert_eq!(req.outcome.result, "deny");
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
    let frame = drive_read(
        &fx.principal,
        fx.authorizer(),
        emit.clone(),
        me,
        maknae_proto::Verb::Read {
            path: target.clone(),
        },
        Duration::from_secs(5),
        std::path::Path::new(&target),
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
        RespResult::Err(e) => {
            assert_eq!(e.code, ProtoErrCode::Unauthorized);
            assert_eq!(e.message, "not authorized", "no note may reach the wire");
        }
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
    // An operator-added absolute grant for a tree OUTSIDE the enrolled home. The
    // object is CREATED rather than borrowed from `/etc`: the old fixture granted
    // `Read(/etc/**)` and delegated `/etc/hostname`, neither of which exists on
    // macOS — caught by the darwin-native CI job in `maknae-io`'s PARALLEL fixture
    // (`delegated.rs`, the `a_file` helper) and fixed here by inspection. Corrected
    // 2026-09-04 (#216): this suite is outside `DARWIN_CRATES` and has never run on
    // that job; the sentence as first written attributed the sibling's catch to it.
    let outside_dir =
        std::env::temp_dir().join(format!("enforce_offhome_obj_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&outside_dir);
    std::fs::create_dir_all(&outside_dir).unwrap();
    // Canonical for fixture hygiene, matching `Fixture::new` (#216); it does not
    // change this test's outcome. The grant below is never consulted: the object
    // is outside `principal.home`, so `verify_delegated` fails confinement, no OS
    // answer is stamped, and the `fs.read` arm's os-dac gate denies BEFORE
    // `decide_fs` (the only caller of the glob matcher) ever runs. The reason
    // assertion below is what pins that ordering: were the gate bypassed, the
    // ASKED path is what gets stamped (no verified object), the glob written
    // from the same variable matches it, and either matcher answer -- permit or
    // `no capability entry` -- changes the reason. The mutant dies in both
    // path forms.
    let outside_dir = outside_dir
        .canonicalize()
        .expect("canonicalize the outside dir");
    let outside = outside_dir.join("obj");
    std::fs::write(&outside, b"outside the enrolled home").unwrap();
    fx.write_policy(&format!(
        "schema_version: 1\npermissions:\n  allow:\n    - \"Read({}/**)\"\n  deny: []\n",
        outside_dir.display()
    ));
    // The subject CAN open the object, so a descriptor IS delegated and the
    // refusal below is confinement's, not "no descriptor arrived".
    assert_eq!(
        std::fs::read(&outside).expect("the subject can open the outside object"),
        b"outside the enrolled home"
    );
    let emit = RecEmit::new();
    let me = nix::unistd::geteuid().as_raw();
    let frame = drive_read(
        &fx.principal,
        fx.authorizer(),
        emit.clone(),
        me,
        maknae_proto::Verb::Read {
            path: outside.to_string_lossy().into_owned(),
        },
        Duration::from_secs(5),
        &outside,
    )
    .await
    .expect("outside-root frame");
    // CHANGED BY ADR-0009. Previously the PDP PERMITTED an operator-granted absolute
    // path and the PEP refused it afterwards, so the trail recorded "permit, then
    // refused-outside-root". Confinement is now one of the two proofs the decision
    // itself requires (decision 3), so an object outside the enrolled home never
    // establishes OS access and the verdict is a real Deny.
    //
    // The property this test exists for is unchanged and better served: a grant the
    // operator wrote for a path outside the home does NOT yield the bytes, and the
    // trail says so as a decision rather than as a delivery failure.
    match maknae_proto::decode_response(&frame).unwrap().result {
        RespResult::Err(e) => {
            assert_eq!(e.code, ProtoErrCode::Unauthorized);
            assert_eq!(e.message, "not authorized", "no note may reach the wire");
        }
        other => panic!("a grant outside the enrolled home must not deliver: {other:?}"),
    }
    let req = request_record(&emit.records()).clone();
    assert_eq!(req.outcome.result, "deny");
    // "Distinctly": a composed Deny at the PDP, not a delivery refusal. A
    // `ReadRefusal::Refused` renders the same wire triple and the same
    // `deny` result but can never carry this reason -- and the reason also
    // proves the os-dac gate short-circuited before the absolute grant was
    // evaluated: neither a matcher permit nor a `no capability entry` abstain
    // renders it, so a gate-bypass mutant dies here (a confinement-deletion
    // mutant delivers bytes and dies at the frame match above). What this
    // reason cannot do is separate "outside the
    // anchored root" from "root soundness failed" -- both render it (see the
    // note on `Fixture::new`); "no descriptor arrived" is ruled out by the
    // `std::fs::read` above.
    assert_eq!(
        req.outcome.reason, "os dac: os accessibility unknown",
        "an object outside the enrolled home never establishes OS access"
    );
    let leak = b"outside the enrolled home";
    assert!(
        !frame.windows(leak.len()).any(|w| w == leak),
        "no content from outside the home may ride the frame"
    );
    let _ = std::fs::remove_dir_all(&outside_dir);
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
        RespResult::Err(e) => {
            assert_eq!(e.code, ProtoErrCode::Unauthorized);
            assert_eq!(e.message, "not authorized", "no note may reach the wire");
        }
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
    fx.write_policy(BINDINGS_ROOT_USER); // root -> user: no management grant
    for verb in [
        maknae_proto::Verb::AdminStatus,
        maknae_proto::Verb::SessionNew,
        maknae_proto::Verb::FsWrite {
            path: "/home/test/x".into(),
            content: maknae_proto::Bytes::new(maknae_io::Zeroizing::new(Vec::new())),
            mode: maknae_proto::WriteMode::Existing,
        },
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
            RespResult::Err(e) => {
                assert_eq!(
                    e.code,
                    ProtoErrCode::Unauthorized,
                    "{verb:?} must deny without leaking implementation state"
                );
                assert_eq!(e.message, "not authorized", "no note may reach the wire");
            }
            other => panic!("expected Unauthorized for {verb:?}, got {other:?}"),
        }
    }
}

/// The transport a status test drives with, DELIBERATELY NON-DEFAULT.
///
/// Asserting `listener` against `transport_from_section(None)` -- the default
/// -- could not separate "reads `cfg.socket_path`" from a hardcoded literal:
/// expected and actual were the same string. Replacing both `listener` and
/// `authz_backend` with literals left the entire kernel suite GREEN, and
/// `run.rs` is in `exclude_globs`, so cargo-mutants never generated the
/// mutant either. A distinguishing input is the only thing that closes it.
fn nondefault_transport() -> maknae_config::TransportConfig {
    let mut t = maknae_config::transport_from_section(None).unwrap();
    t.socket_path = "/tmp/maknae-status-probe.sock".into();
    t
}

/// `admin.status` end to end: a real grant, a real verdict, real posture.
///
/// Every field is asserted, not just the variant. `authz_backend` is the one
/// worth naming: it is asked of the PDP rather than hardcoded, so with the
/// classification library present it reports that backend instead — an
/// operator debugging a verdict needs to know WHICH decider produced it.
#[tokio::test]
async fn a_granted_status_reports_real_posture_from_the_real_pdp() {
    let fx = Fixture::new("status-grant");
    fx.write_policy(
        "schema_version: 1\npermissions:\n  allow: []\n  deny: []\nbindings:\n  admin: [\"root\"]\nroles:\n  admin:\n    allow: [\"admin.status\"]\n",
    );
    // The classification system is DERIVED from a real `boot()` of a config that
    // declares the NON-default one (ADR-0022): `policy: aus` with a PSPF ceiling.
    // A literal `"US"` here matched the production default and could not tell
    // "read from boot" apart from "hardcoded" (critical-review round 1, C1) --
    // the same distinguishing-input rule `nondefault_transport()` follows.
    let cfg = fx.dir.join("maknae.yaml");
    std::fs::write(
        &cfg,
        "core:\n  handling:\n    ceiling:\n      classification: protected\n      sci: false\n      releasable_to: []\n      cui_permitted: false\n      cui_categories_permitted: []\n      dissemination_permitted: [\"Distribution Statement A\"]\n    accreditation_ref: null\n    policy: aus\n",
    )
    .unwrap();
    std::fs::set_permissions(&cfg, std::fs::Permissions::from_mode(0o640)).unwrap();
    let booted = maknae_kernel::boot(&fx.dir).expect("the AUS fixture boots");
    assert_eq!(booted.ceiling().classification.name, "PROTECTED");
    let emit = RecEmit::new();
    let frame = drive_with(
        &fx.principal,
        fx.authorizer(),
        emit.clone(),
        0,
        maknae_proto::Verb::AdminStatus,
        Duration::from_secs(5),
        maknae_io::DelegatedFds::new(0),
        Arc::new(Default::default()),
        nondefault_transport(),
        Arc::new(booted.classification_policy_name().to_string()),
    )
    .await
    .expect("a frame");
    match maknae_proto::decode_response(&frame).unwrap().result {
        RespResult::Ok(maknae_proto::Payload::Status(s)) => {
            assert_eq!(s.protocol_version, maknae_proto::PROTOCOL_VERSION);
            assert_eq!(s.authz_backend, "maknae-authz-basic");
            assert_eq!(
                s.classification_policy, "AUS",
                "the system NAME boot selected from `core.handling.policy` -- the \
                 registry's canonical spelling, not the operator's `aus`"
            );
            // EXACT, like its siblings. This was the one field where any
            // non-empty string passed; the test crate is `maknae-kernel`, the
            // same package whose CARGO_PKG_VERSION `run.rs` expands, so the
            // distinguishing assertion is free.
            assert_eq!(s.version, env!("CARGO_PKG_VERSION"));
            // The VALUE, not merely non-empty: wiring `listener` to any other
            // non-empty config string -- the audit path, the plane socket --
            // passed the emptiness check.
            assert_eq!(
                s.listener,
                nondefault_transport().socket_path.display().to_string(),
                "listener must be READ from the running config -- a default-valued \
                 expectation could not tell that apart from a hardcoded literal"
            );
        }
        other => panic!("expected a Status payload, got {other:?}"),
    }
    let req = request_record(&emit.records()).clone();
    assert_eq!(req.action, "admin.status");
    assert_eq!(req.outcome.result, "permit");
    assert_eq!(req.outcome.posture, "authorized");
}

/// `authz_backend` is ASKED OF THE PDP. A backend that does not name itself
/// reports `unknown`, and this is the input that proves the field is not the
/// `-basic` literal: `AlwaysPermit` implements only `decide`, so it takes the
/// seam default. Two tests, two backends, two different expected strings --
/// which is what "asked, not hardcoded" actually requires.
#[tokio::test]
async fn status_reports_the_backend_that_actually_decided() {
    let fx = Fixture::new("status-unknown-backend");
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
        RespResult::Ok(maknae_proto::Payload::Status(s)) => assert_eq!(
            s.authz_backend, "unknown",
            "a backend taking the seam default must report `unknown`, not the \
             name of some other backend"
        ),
        other => panic!("expected a Status payload, got {other:?}"),
    }
}

/// A backend that PANICS in `backend_name()` is contained, on the production
/// path. The kernel calls it INLINE on the async worker -- unlike `subjects`,
/// which `spawn_blocking` would backstop -- so without the guard the panic
/// unwinds through `handle()` AFTER the audit record already said
/// permit/authorized, and the caller gets a dropped connection instead of a
/// response. `run.rs` is mutation-excluded, so nothing else would catch a
/// revert to the raw call.
#[tokio::test]
async fn a_panicking_backend_name_is_contained_on_the_production_path() {
    let fx = Fixture::new("status-panicking-name");
    let emit = RecEmit::new();
    let frame = drive(
        &fx.principal,
        Arc::new(PanickingName),
        emit.clone(),
        0,
        maknae_proto::Verb::AdminStatus,
        Duration::from_secs(5),
    )
    .await
    .expect("a frame, not a dropped connection");
    match maknae_proto::decode_response(&frame).unwrap().result {
        RespResult::Ok(maknae_proto::Payload::Status(s)) => assert_eq!(
            s.authz_backend, "unknown",
            "a panicking name must fail closed to `unknown`, not escape"
        ),
        other => panic!("expected a Status payload, got {other:?}"),
    }
}

/// `admin.subject.list` reports what the POLICY FILE binds, end to end.
///
/// This does NOT prove liveness, and an earlier version of this doc claimed it
/// did. The fixture policy is on disk before `HermeticAuthorizer::new`, so an
/// implementation that snapshotted bindings at construction passes it
/// unchanged. The liveness property is owned by
/// `wrapper_subjects_delegate_and_read_live` in `maknae-authz-basic`, which
/// rewrites the policy between two calls and asserts the answer changes.
#[tokio::test]
async fn a_granted_subject_list_reports_the_policy_file_bindings() {
    let fx = Fixture::new("subjlist-grant");
    fx.write_policy(
        "schema_version: 1\npermissions:\n  allow: []\n  deny: []\nbindings:\n  admin: [\"root\"]\nroles:\n  admin:\n    allow: [\"admin.subject.list\"]\n",
    );
    let emit = RecEmit::new();
    let frame = drive(
        &fx.principal,
        fx.authorizer(),
        emit.clone(),
        0,
        maknae_proto::Verb::AdminSubjectList,
        Duration::from_secs(5),
    )
    .await
    .expect("a frame");
    match maknae_proto::decode_response(&frame).unwrap().result {
        RespResult::Ok(maknae_proto::Payload::SubjectList(b)) => {
            let admin = b
                .iter()
                .find(|r| r.role == "admin")
                .expect("the admin binding the fixture wrote");
            assert_eq!(
                admin.members,
                vec!["uid:0".to_string()],
                "root resolves to uid 0, and members are reported by uid"
            );
        }
        other => panic!("expected a SubjectList payload, got {other:?}"),
    }
    assert_eq!(request_record(&emit.records()).outcome.result, "permit");
}

/// A backend that CANNOT enumerate yields an explicit refusal, never an empty
/// list. This is the enforcement site of the claim the whole binding fix was
/// written to protect, and until now nothing tested it.
///
/// `AlwaysPermit` implements only `decide`, so its `subjects()` takes the seam
/// default of `None` -- exactly what a backend that cannot enumerate returns,
/// and what the shipped `authz.yaml` (no `bindings:` key) produces through
/// `-basic`. Replacing the kernel's `None` arm with
/// `Payload::SubjectList(vec![])` left every other test on this branch green,
/// and would tell an operator "nobody is bound" while the default-role
/// fallback was live.
#[tokio::test]
async fn a_backend_that_cannot_enumerate_refuses_rather_than_claiming_empty() {
    let fx = Fixture::new("subjlist-unavailable");
    let emit = RecEmit::new();
    let frame = drive(
        &fx.principal,
        Arc::new(AlwaysPermit),
        emit.clone(),
        0,
        maknae_proto::Verb::AdminSubjectList,
        Duration::from_secs(5),
    )
    .await
    .expect("a frame");
    match maknae_proto::decode_response(&frame).unwrap().result {
        RespResult::Err(e) => assert_eq!(e.code, ProtoErrCode::Internal),
        RespResult::Ok(maknae_proto::Payload::SubjectList(b)) => panic!(
            "an inability to enumerate must NOT render as a binding list -- \
             an empty list is the claim `nobody is bound`, got {b:?}"
        ),
        other => panic!("expected an explicit refusal, got {other:?}"),
    }
    // And the TRAIL must not claim the disclosure happened. The pre-dispatch
    // record says permit/authorized; a second record corrects the posture,
    // exactly as the read PEP does for these same four conditions.
    let last = emit.records().last().cloned().expect("a record");
    assert_eq!(last.outcome.result, "deny");
    assert_eq!(
        last.outcome.posture, "unavailable",
        "a Permit-then-not-performed must never read as a completed action"
    );
    // And the SPECIFIC condition, not just the category. Five paths reach the
    // refusal and only this one is benign -- an auditor must be able to tell
    // "this backend does not enumerate" (the shipped default's permanent
    // state) from "the policy filesystem is wedged" (an incident).
    assert!(
        last.outcome.reason.contains("does not enumerate"),
        "the reason must name WHICH refusal: {:?}",
        last.outcome.reason
    );
}

/// Neither new term discloses without a grant. The authorization decision is
/// the gate, not the dispatch.
#[tokio::test]
async fn the_new_terms_disclose_nothing_without_a_grant() {
    for (tag, verb) in [
        ("status-nogrant", maknae_proto::Verb::AdminStatus),
        ("subjlist-nogrant", maknae_proto::Verb::AdminSubjectList),
    ] {
        let fx = Fixture::new(tag);
        fx.write_policy(BINDINGS_ROOT_ADMIN); // admin binding, no `roles:` key
        let emit = RecEmit::new();
        let frame = drive(
            &fx.principal,
            fx.authorizer(),
            emit.clone(),
            0,
            verb.clone(),
            Duration::from_secs(5),
        )
        .await
        .expect("a frame");
        match maknae_proto::decode_response(&frame).unwrap().result {
            RespResult::Err(e) => {
                assert_eq!(e.code, ProtoErrCode::Unauthorized, "{verb:?}");
                assert_eq!(e.message, "not authorized", "no note may reach the wire");
            }
            other => panic!("{verb:?} disclosed without a grant: {other:?}"),
        }
        assert_eq!(request_record(&emit.records()).outcome.result, "deny");
    }
}

/// An oversized `ConfigView` is refused EXPLICITLY, not written oversized.
///
/// `ConfigView` is the only payload on that arm whose size scales with input --
/// one entry per config leaf. Without a bound the daemon writes a frame the
/// client's own `read_frame(frame_max_bytes)` then refuses as a framing
/// `Oversize`: an authorized request failing with an undiagnosable transport
/// error, after its audit record already said "permit / authorized". The read
/// PEP's stance applies unchanged -- a PERMIT whose delivery is refused is
/// refused explicitly.
///
/// Raised independently by an external reviewer after three internal rounds had
/// flagged it and it was deferred each time.
#[tokio::test]
async fn an_oversized_config_view_is_refused_explicitly_not_written_oversized() {
    let fx = Fixture::new("cfgshow-toolarge");
    fx.write_policy(
        "schema_version: 1\npermissions:\n  allow: []\n  deny: []\nbindings:\n  admin: [\"root\"]\nroles:\n  admin:\n    allow: [\"admin.config.show\"]\n",
    );
    // Enough leaves to exceed the default frame cap. Values are already
    // redacted; it is the KEY COUNT that grows the frame.
    let mut section = std::collections::BTreeMap::new();
    for i in 0..20_000 {
        section.insert(format!("key_{i:06}"), maknae_config::MASK.to_string());
    }
    let mut view = maknae_kernel::ConfigView::new();
    view.insert("vault".to_string(), section);

    let emit = RecEmit::new();
    let frame = drive_with(
        &fx.principal,
        fx.authorizer(),
        emit.clone(),
        0,
        maknae_proto::Verb::AdminConfigShow,
        Duration::from_secs(5),
        maknae_io::DelegatedFds::new(0),
        Arc::new(view),
        maknae_config::transport_from_section(None).unwrap(),
        Arc::new("US".to_string()),
    )
    .await
    .expect("a frame");

    let cfg = maknae_config::transport_from_section(None).unwrap();
    assert!(
        frame.len() <= cfg.frame_max_bytes + 64,
        "the daemon must not emit a frame its own client cannot read: {} bytes",
        frame.len()
    );
    match maknae_proto::decode_response(&frame).unwrap().result {
        RespResult::Err(e) => assert_eq!(e.code, ProtoErrCode::TooLarge),
        other => panic!("expected an explicit TooLarge refusal, got {other:?}"),
    }
    // And the TRAIL must not claim the disclosure happened. The pre-dispatch
    // record says permit/authorized; a corrective record carries the real
    // posture. `permit` is retained -- the DECISION was a permit; only the
    // delivery was refused.
    let last = emit.records().last().cloned().expect("a record");
    assert_eq!(last.outcome.result, "permit");
    assert_eq!(
        last.outcome.posture, "refused-oversize",
        "a Permit-then-not-delivered must never read as a completed action"
    );
}

/// `admin.config.show` end to end: a real `roles:` grant, a real PDP verdict,
/// and a real redacted disclosure on the wire (#162 Phase 2).
///
/// The secret is planted in the view the daemon holds and asserted ABSENT from
/// the response bytes, not merely from the decoded payload -- a redaction that
/// holds after decoding but leaks in the frame is not a redaction.
#[tokio::test]
async fn a_granted_config_show_discloses_the_redacted_view_and_nothing_else() {
    let fx = Fixture::new("cfgshow-grant");
    fx.write_policy(
        "schema_version: 1\npermissions:\n  allow: []\n  deny: []\nbindings:\n  admin: [\"root\"]\nroles:\n  admin:\n    allow: [\"admin.config.show\"]\n",
    );
    // The view is produced by the REAL redaction over a REAL Document holding a
    // REAL secret -- not hand-written to look redacted.
    //
    // The earlier version of this test built the masked view itself and then
    // asserted the secret was absent from the frame. The secret was never in
    // the input, so no mutation of the redaction rule, the boot wiring, or the
    // wire could make that assertion fail. It proved the author could type
    // maknae_config::MASK. Now `disclosable_view` runs, and widening DISCLOSABLE or
    // inverting render's allowlist check turns this red.
    let doc = maknae_config::Document::from_sections_for_test(vec![(
        "vault".to_string(),
        maknae_config::Value::Map(vec![
            (
                "addr".to_string(),
                maknae_config::Value::Str("https://vault.example:8200".into()),
            ),
            (
                "root_token".to_string(),
                maknae_config::Value::Str("hvs.THE-SECRET".into()),
            ),
        ]),
    )]);
    let view = doc.disclosable_view();
    assert_eq!(
        view["vault"]["root_token"],
        maknae_config::MASK,
        "precondition: the redaction masked it before the wire ever saw it"
    );

    let emit = RecEmit::new();
    let frame = drive_with(
        &fx.principal,
        fx.authorizer(),
        emit.clone(),
        0,
        maknae_proto::Verb::AdminConfigShow,
        Duration::from_secs(5),
        maknae_io::DelegatedFds::new(0),
        Arc::new(view),
        maknae_config::transport_from_section(None).unwrap(),
        Arc::new("US".to_string()),
    )
    .await
    .expect("a frame");

    assert!(
        !String::from_utf8_lossy(&frame).contains("hvs."),
        "no secret material may appear in the response FRAME -- the secret is \
         genuinely present in the source Document, so this can fail"
    );
    match maknae_proto::decode_response(&frame).unwrap().result {
        RespResult::Ok(maknae_proto::Payload::ConfigView(v)) => {
            assert_eq!(v["vault"]["root_token"], maknae_config::MASK);
            assert!(v["vault"].contains_key("addr"), "shape is disclosed: {v:?}");
        }
        other => panic!("expected a ConfigView payload, got {other:?}"),
    }
    let req = request_record(&emit.records()).clone();
    assert_eq!(req.action, "admin.config.show");
    assert_eq!(req.outcome.result, "permit");
    assert_eq!(
        req.outcome.posture, "authorized",
        "the term has behaviour now; assert the posture it MUST have, not merely \
         one it must not -- `assert_ne` passes for any other string"
    );
}

/// Without the grant, nothing is disclosed. This is what makes the test above
/// mean something: the authorization decision, not the dispatch, is the gate.
#[tokio::test]
async fn config_show_without_a_grant_discloses_nothing() {
    let fx = Fixture::new("cfgshow-nogrant");
    fx.write_policy(BINDINGS_ROOT_ADMIN); // admin binding, no `roles:` key
    let mut vault = std::collections::BTreeMap::new();
    vault.insert("addr".to_string(), maknae_config::MASK.to_string());
    let mut view = maknae_kernel::ConfigView::new();
    view.insert("vault".to_string(), vault);

    let emit = RecEmit::new();
    let frame = drive_with(
        &fx.principal,
        fx.authorizer(),
        emit.clone(),
        0,
        maknae_proto::Verb::AdminConfigShow,
        Duration::from_secs(5),
        maknae_io::DelegatedFds::new(0),
        Arc::new(view),
        maknae_config::transport_from_section(None).unwrap(),
        Arc::new("US".to_string()),
    )
    .await
    .expect("a frame");
    match maknae_proto::decode_response(&frame).unwrap().result {
        RespResult::Err(e) => {
            assert_eq!(e.code, ProtoErrCode::Unauthorized);
            assert_eq!(e.message, "not authorized", "no note may reach the wire");
        }
        other => panic!("an ungranted config.show must disclose NOTHING, got {other:?}"),
    }
    // NOTE: no "the section names are absent from the frame" assertion here.
    // One was written, and it could not fail: the deny path returns before the
    // `config_view` binding is ever reached, so no mutation of the redaction
    // rule, the allowlist or the view could turn it red. It read like a control
    // and was decoration. The two assertions that remain -- Unauthorized on the
    // wire, `deny` in the audit record -- are the real ones.
    assert_eq!(request_record(&emit.records()).outcome.result, "deny");
}

// RETIRED (#162 Phase 3): `a_roles_granted_term_permits_through_the_real_pdp_
// and_still_discloses_nothing` lived here. It drove a granted `admin.status`
// and asserted `NotImplemented` -- that the grant produced a real PDP verdict
// and disclosed nothing. Its second half is now deliberately false: the term
// is built and discloses posture.
//
// Deleted rather than rewritten, because its unique claim -- that a `roles:`
// grant crosses the seam to a real verdict -- is now made by three tests that
// assert the actual disclosure
// (`a_granted_status_reports_real_posture_from_the_real_pdp`,
// `a_granted_config_show_discloses_the_redacted_view_and_nothing_else`,
// `a_granted_subject_list_reports_the_policy_file_bindings`). Keeping it retargeted at an
// ungrantable term would have tested the NOOP path, which
// `a_permitted_unbuilt_term_is_audited_then_refused` already pins.

/// The same file WITHOUT the grant refuses. This is what makes the test above
/// mean something: without it, a permit that came from anywhere else in the
/// policy would read identically.
#[tokio::test]
async fn the_same_policy_without_the_grant_does_not_permit() {
    let fx = Fixture::new("roles-nogrant");
    fx.write_policy(BINDINGS_ROOT_ADMIN); // admin binding, no `roles:` key
    let emit = RecEmit::new();
    let frame = drive(
        &fx.principal,
        fx.authorizer(),
        emit.clone(),
        0,
        maknae_proto::Verb::AdminStatus,
        Duration::from_secs(5),
    )
    .await
    .expect("a frame");
    match maknae_proto::decode_response(&frame).unwrap().result {
        // The code that was OBSERVED, not merely "not NotImplemented" -- which
        // would also pass for Internal, Timeout, or any code added later.
        RespResult::Err(e) => {
            assert_eq!(
                e.code,
                ProtoErrCode::Unauthorized,
                "without a grant this must be refused by authz, never reach dispatch"
            );
            assert_eq!(e.message, "not authorized", "no note may reach the wire");
        }
        other => panic!("expected an error, got {other:?}"),
    }
    let req = request_record(&emit.records()).clone();
    assert_eq!(req.outcome.result, "deny");
}

/// An explicit `deny:` refuses -- and the reason NAMES the term in the audit
/// trail while the WIRE receives only the static "not authorized". The new
/// deny reason must not leak to a caller: the same hazard `decide.rs` warns
/// about for the path operand, where the reason carries a filesystem path.
#[tokio::test]
async fn a_roles_denied_term_names_the_term_in_audit_but_not_on_the_wire() {
    let fx = Fixture::new("roles-deny");
    fx.write_policy(
        "schema_version: 1\npermissions:\n  allow: []\n  deny: []\nbindings:\n  admin: [\"root\"]\nroles:\n  admin:\n    allow: [\"admin.status\"]\n    deny: [\"admin.status\"]\n",
    );
    let emit = RecEmit::new();
    let frame = drive(
        &fx.principal,
        fx.authorizer(),
        emit.clone(),
        0,
        maknae_proto::Verb::AdminStatus,
        Duration::from_secs(5),
    )
    .await
    .expect("a frame");
    let err = match maknae_proto::decode_response(&frame).unwrap().result {
        RespResult::Err(e) => e,
        other => panic!("expected an error, got {other:?}"),
    };
    assert!(
        !err.message.contains("admin.status") && !err.message.contains("role grant"),
        "the deny reason must not reach the wire: {:?}",
        err.message
    );
    let req = request_record(&emit.records()).clone();
    assert_eq!(req.outcome.result, "deny");
    assert!(
        req.outcome.reason.contains("admin.status"),
        "the audit trail MUST name the term that denied: {:?}",
        req.outcome.reason
    );
}

/// A PERMITTED but unbuilt term is decided, audited as decided-and-NOT-performed,
/// and only then refused — with the SAME wire answer as every refusal.
/// (Operator ruling 2026-09-02, superseding the #67 NOOP contract's wire half:
/// "unauthorized is all that is published to the wire" — implementation state
/// is never a wire disclosure, on the permitted path either; an extension that
/// wants to expose not-implemented does so through its own channel. The audit
/// half stands unchanged: permit / posture not-implemented is the trail's
/// truth.) Driven with a permissive authorizer because the real PDP grants no
/// unbuilt term — this exercises the PEP's ordering, not a decision.
#[tokio::test]
async fn a_permitted_unbuilt_term_is_audited_then_refused() {
    let fx = Fixture::new("noop-permit");
    let emit = RecEmit::new();
    let frame = drive(
        &fx.principal,
        Arc::new(AlwaysPermit),
        emit.clone(),
        0,
        maknae_proto::Verb::AdminContain,
        Duration::from_secs(5),
    )
    .await
    .expect("a frame");
    match maknae_proto::decode_response(&frame).unwrap().result {
        RespResult::Err(e) => {
            assert_eq!(e.code, ProtoErrCode::Unauthorized);
            assert_eq!(
                e.message, "not authorized",
                "build state is not a wire disclosure"
            );
        }
        other => panic!("expected Unauthorized, got {other:?}"),
    }
    let req = request_record(&emit.records()).clone();
    assert_eq!(req.action, "admin.contain");
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
        maknae_proto::Verb::AdminContain,
        Duration::from_secs(5),
    )
    .await;
    assert!(
        out.is_none(),
        "no frame may be released when its record could not append"
    );
    assert!(
        emit.records().iter().any(|r| r.action == "admin.contain"),
        "the record must have been OFFERED before the frame was withheld"
    );
}

/// The CORRECTIVE record is gated on ITS OWN append, not the admission
/// record's. n=3 leaves the admission record (1) and the pre-dispatch
/// `permit / authorized` record (2) durable and fails the third — the posture
/// correction — so the only surviving statement about this request is
/// "authorized and served", for a disclosure that never happened.
///
/// The three corrective sites discarded that result (`let _ =`) and wrote the
/// frame regardless, on the argument that a guard would be a constant `if
/// true`. That argument is about the ADMISSION record's `appended`; the value
/// discarded here is a second, freshly meaningful bool. Meanwhile
/// `emit_request_outcome` printed "withholding the frame" on a path that
/// responded.
#[tokio::test]
async fn a_corrective_record_that_cannot_append_withholds_its_frame() {
    let fx = Fixture::new("subjlist-corrective-withhold");
    let emit = FailNthEmit::new(3);
    let out = drive(
        &fx.principal,
        Arc::new(AlwaysPermit),
        emit.clone(),
        0,
        maknae_proto::Verb::AdminSubjectList,
        Duration::from_secs(5),
    )
    .await;
    assert!(
        out.is_none(),
        "no frame may be released when the record CORRECTING its posture could not append"
    );
    // The correction must have been OFFERED -- withholding because the record
    // was never attempted would pass this test for the wrong reason.
    let recs = emit.records();
    assert!(
        recs.iter()
            .any(|r| r.outcome.posture == "unavailable" && r.outcome.result == "deny"),
        "the corrective record must have been offered before the frame was withheld, got {:?}",
        recs.iter()
            .map(|r| (r.outcome.result.clone(), r.outcome.posture.clone()))
            .collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------------
// #181 — the trail distinguishes WHY an absence denied; the wire never does.
// Written RED against the un-annotated decide (S2 of the plan), turned green
// by S3's annotations. Every wire assertion is the SAME generic Unauthorized:
// the roadmap and the policy shape are audit-only disclosures.
// ---------------------------------------------------------------------------

/// Case 3: an enumerated-but-unbuilt term, asked by the role that would own
/// it. The trail states the roadmap fact; the wire stays indistinguishable
/// from unauthorized (ruling R1 -- fingerprinting denied).
#[tokio::test]
async fn an_unbuilt_term_tells_the_admin_trail_the_roadmap_fact() {
    let fx = Fixture::new("note-unbuilt-admin");
    fx.write_policy(BINDINGS_ROOT_ADMIN);
    let emit = RecEmit::new();
    let frame = drive(
        &fx.principal,
        fx.authorizer(),
        emit.clone(),
        0,
        maknae_proto::Verb::AdminContain,
        Duration::from_secs(5),
    )
    .await
    .expect("a deny frame");
    match maknae_proto::decode_response(&frame).unwrap().result {
        RespResult::Err(e) => {
            assert_eq!(e.code, ProtoErrCode::Unauthorized);
            assert_eq!(e.message, "not authorized", "no note may reach the wire");
        }
        other => panic!("expected Unauthorized, got {other:?}"),
    }
    let req = request_record(&emit.records()).clone();
    assert_eq!(req.outcome.result, "deny");
    assert_eq!(
        req.outcome.reason, "term enumerated, not implemented: admin.contain",
        "the ADMIN trail carries the roadmap fact"
    );
}

/// Case 2 for a non-admin: role-reach outranks build-state. A user asking the
/// same unbuilt term reads their OWN operational fact -- their reach -- not
/// the roadmap, which is admin-visible only.
#[tokio::test]
async fn an_unbuilt_term_tells_a_user_trail_their_reach() {
    let fx = Fixture::new("note-unbuilt-user");
    fx.write_policy(BINDINGS_ROOT_USER);
    let emit = RecEmit::new();
    let frame = drive(
        &fx.principal,
        fx.authorizer(),
        emit.clone(),
        0,
        maknae_proto::Verb::AdminContain,
        Duration::from_secs(5),
    )
    .await
    .expect("a deny frame");
    match maknae_proto::decode_response(&frame).unwrap().result {
        RespResult::Err(e) => {
            assert_eq!(e.code, ProtoErrCode::Unauthorized);
            assert_eq!(e.message, "not authorized", "no note may reach the wire");
        }
        other => panic!("expected Unauthorized, got {other:?}"),
    }
    let req = request_record(&emit.records()).clone();
    assert_eq!(
        req.outcome.reason, "role user: no rule for admin.contain",
        "a non-admin trail reads role-reach, never build-state"
    );
}

/// Case 2 at the grant surface: a grantable term with NO grant written. The
/// absence is a policy question ("a grant could exist; none does") and the
/// trail says so by term.
#[tokio::test]
async fn a_grantable_term_with_no_grant_names_the_absent_rule() {
    let fx = Fixture::new("note-nogrant");
    fx.write_policy(BINDINGS_ROOT_ADMIN); // bindings, but NO `roles:` key
    let emit = RecEmit::new();
    let frame = drive(
        &fx.principal,
        fx.authorizer(),
        emit.clone(),
        0,
        maknae_proto::Verb::AdminStatus,
        Duration::from_secs(5),
    )
    .await
    .expect("a deny frame");
    match maknae_proto::decode_response(&frame).unwrap().result {
        RespResult::Err(e) => {
            assert_eq!(e.code, ProtoErrCode::Unauthorized);
            assert_eq!(e.message, "not authorized", "no note may reach the wire");
        }
        other => panic!("expected Unauthorized, got {other:?}"),
    }
    let req = request_record(&emit.records()).clone();
    assert_eq!(
        req.outcome.reason, "role admin: no rule for admin.status",
        "a written deny would say 'denied by role grant'; an ABSENCE says this"
    );
}

/// Case 5: a delegated, OS-readable object that no capability entry matches.
/// Preconditions per the plan: a REAL delegated fd (without one, the os-dac
/// gate denies first with `os dac:`); the file inside the fixture home
/// (confinement); and a NARROW allow list -- under the shipped `Read(~/**)`
/// every in-home path AllowMatches and this test would Permit instead.
#[tokio::test]
async fn an_unmatched_read_names_the_missing_capability_entry() {
    let fx = Fixture::new("note-nocap");
    fx.write_policy(
        "schema_version: 1\npermissions:\n  allow:\n    - \"Read(~/allowed/**)\"\n  deny: []\nbindings:\n  admin: [\"root\"]\n",
    );
    std::fs::write(fx.dir.join("outside.txt"), b"not under any entry").unwrap();
    let target = fx.dir.join("outside.txt").to_string_lossy().into_owned();
    let emit = RecEmit::new();
    let frame = drive_read(
        &fx.principal,
        fx.authorizer(),
        emit.clone(),
        0,
        maknae_proto::Verb::Read {
            path: target.clone(),
        },
        Duration::from_secs(5),
        std::path::Path::new(&target),
    )
    .await
    .expect("a deny frame");
    match maknae_proto::decode_response(&frame).unwrap().result {
        RespResult::Err(e) => {
            assert_eq!(e.code, ProtoErrCode::Unauthorized);
            assert_eq!(e.message, "not authorized", "no note may reach the wire");
        }
        other => panic!("expected Unauthorized, got {other:?}"),
    }
    let req = request_record(&emit.records()).clone();
    assert_eq!(
        req.outcome.reason, "role admin: no capability entry for fs.read",
        "role and term only -- no rule for fs.read EXISTS; no entry MATCHED, \
         and the path stays out of the reason"
    );
}

// ---------------------------------------------------------------------------
// #148 / #154. THE COMPOSITION: baseline ∧ ceiling, deny-overrides, per request.
// ---------------------------------------------------------------------------

/// The production PDP shape -- `Composition<Baseline>` -- built the way
/// `run_inner` builds it, over the hermetic door.
fn composed(fx: &Fixture, level: &str) -> Arc<maknae_kernel::Composition<HermeticAuthorizer>> {
    use maknae_config::ClassificationPolicy;
    const US: &maknae_config::BasicPolicy = &maknae_config::BasicPolicy;
    let mut ceiling = maknae_config::Ceiling::baseline_for(US);
    ceiling.classification = US.level_of(level).expect("a US level");
    let basic =
        HermeticAuthorizer::new(fx.dir.join("authz.yaml"), fx.principal.clone(), seam_req())
            .expect("fixture policy constructs");
    Arc::new(maknae_kernel::Composition::new(
        basic,
        maknae_kernel::CeilingAuthorizer::new(ceiling, US),
    ))
}

/// `admin.status` under an ABOVE-BASELINE ceiling still answers -- the control
/// plane carries no content, so the ceiling abstains -- and it names BOTH
/// operands. This is the diagnosability property: an operator whose reads are
/// being refused can still ask the daemon which deciders it composes.
#[tokio::test]
async fn under_a_secret_ceiling_status_still_answers_and_names_both_operands() {
    let fx = Fixture::new("composed-status");
    fx.write_policy(
        "schema_version: 1\npermissions:\n  allow: []\n  deny: []\nbindings:\n  admin: [\"root\"]\nroles:\n  admin:\n    allow: [\"admin.status\"]\n",
    );
    let emit = RecEmit::new();
    let frame = drive_with(
        &fx.principal,
        composed(&fx, "SECRET"),
        emit.clone(),
        0,
        maknae_proto::Verb::AdminStatus,
        Duration::from_secs(5),
        maknae_io::DelegatedFds::new(0),
        Arc::new(Default::default()),
        nondefault_transport(),
        Arc::new("US".to_string()),
    )
    .await
    .expect("a frame");
    match maknae_proto::decode_response(&frame).unwrap().result {
        RespResult::Ok(maknae_proto::Payload::Status(s)) => {
            assert_eq!(s.authz_backend, "maknae-authz-basic+maknae-ceiling");
        }
        other => panic!("expected a Status payload, got {other:?}"),
    }
    assert_eq!(request_record(&emit.records()).outcome.result, "permit");
}

/// The #148 ruling, end to end: under a SECRET ceiling, a read the shipped
/// policy permits of UNMARKED content returns the bytes -- unmarked is
/// UNCLASSIFIED, at or below every ceiling. No deployment tier needs a labeler
/// to function. HONESTY NOTE: this test is invariant to the ceiling operand's
/// presence (it passes with the ceiling swapped out of the fold); it is a
/// regression guard against re-introducing the equality/deny-unlabeled
/// semantics, not a proof the operand is consulted. That proof is the status
/// test above (the composed name) and the composition unit tests with a
/// stamped label -- nothing in the request path stamps one yet.
#[tokio::test]
async fn under_a_secret_ceiling_unmarked_content_is_served_as_unclassified() {
    let fx = Fixture::new("composed-read-secret");
    fx.write_policy(SHIPPED_POLICY);
    let content: &[u8] = b"unmarked-content-is-UNCLASSIFIED";
    std::fs::write(fx.dir.join("notes.bin"), content).unwrap();
    std::fs::set_permissions(
        fx.dir.join("notes.bin"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let target = fx.dir.join("notes.bin").to_string_lossy().into_owned();

    let emit = RecEmit::new();
    let me = nix::unistd::geteuid().as_raw();
    let frame = drive_read(
        &fx.principal,
        composed(&fx, "SECRET"),
        emit.clone(),
        me,
        maknae_proto::Verb::Read {
            path: target.clone(),
        },
        Duration::from_secs(5),
        std::path::Path::new(&target),
    )
    .await
    .expect("a frame");
    match maknae_proto::decode_response(&frame).unwrap().result {
        RespResult::Ok(Payload::ReadContent(b)) => assert_eq!(&*b.0, content),
        other => panic!("a SECRET ceiling must SERVE unmarked content: {other:?}"),
    }
    let rec = request_record(&emit.records()).clone();
    assert_eq!(rec.action, "fs.read");
    assert_eq!(rec.outcome.result, "permit");
}

/// The identity half: at BASELINE the composition decides exactly what the
/// baseline alone decides -- the same permitted read returns the same bytes.
/// Without this, a ceiling that denied everything would pass the test above.
#[tokio::test]
async fn at_baseline_the_composition_permits_what_the_baseline_permits() {
    let fx = Fixture::new("composed-read-baseline");
    fx.write_policy(SHIPPED_POLICY);
    let content: &[u8] = b"baseline-bytes";
    std::fs::write(fx.dir.join("notes.bin"), content).unwrap();
    std::fs::set_permissions(
        fx.dir.join("notes.bin"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let target = fx.dir.join("notes.bin").to_string_lossy().into_owned();
    let emit = RecEmit::new();
    let me = nix::unistd::geteuid().as_raw();
    let frame = drive_read(
        &fx.principal,
        composed(&fx, "UNCLASSIFIED"),
        emit.clone(),
        me,
        maknae_proto::Verb::Read {
            path: target.clone(),
        },
        Duration::from_secs(5),
        std::path::Path::new(&target),
    )
    .await
    .expect("permitted read answers");
    match maknae_proto::decode_response(&frame).unwrap().result {
        RespResult::Ok(Payload::ReadContent(b)) => assert_eq!(&*b.0, content),
        other => panic!("expected content, got {other:?}"),
    }
    assert_eq!(request_record(&emit.records()).outcome.result, "permit");
}
